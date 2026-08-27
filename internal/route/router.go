// Package route implements the routing logic for the Tidebreak gateway.
// It decides where content goes: cloud API (scrubbed), local Ollama (full data),
// or blocked entirely. It coordinates the classifier, redactor, and Ollama client.
package route

import (
	"encoding/json"

	"github.com/earl-sid/tidebreak/internal/audit"
	"github.com/earl-sid/tidebreak/internal/classify"
	"github.com/earl-sid/tidebreak/internal/ollama"
	"github.com/earl-sid/tidebreak/internal/redact"
	"github.com/earl-sid/tidebreak/internal/rules"
)

// RequestContext holds per-request state (primarily the redactor mapping)
// that must be shared between ProcessRequest and the corresponding
// ProcessResponse/ProcessStreamChunk. This prevents concurrent requests
// from cross-contaminating each other's token mappings.
type RequestContext struct {
	Redactor *redact.Redactor
}

// Router coordinates the classification, redaction, and routing of content.
type Router struct {
	Classifier *classify.Classifier
	Ollama      *ollama.Client
	AuditLog    *audit.Log
}

// New creates a Router with all dependencies wired.
func New(rs *rules.RuleSet, ollamaClient *ollama.Client, auditLog *audit.Log) *Router {
	return &Router{
		Classifier: classify.New(rs),
		Ollama:     ollamaClient,
		AuditLog:   auditLog,
	}
}

// ProcessRequest takes an incoming LLM API request body, classifies each
// content block, and returns the modified request body ready to forward
// to the cloud API. For local-only blocks, the content is sent to Ollama
// and replaced with a de-identified summary.
//
// Returns:
//   - ctx: per-request RequestContext holding the redactor mapping for response restoration
//   - modifiedBody: the request body with redactions/summaries applied
//   - blocked: true if any block was blocked (caller should return error)
//   - error: for unexpected failures
func (r *Router) ProcessRequest(body []byte, agent string, provider string) (ctx *RequestContext, modifiedBody []byte, blocked bool, err error) {
	// Parse the request into content blocks
	blocks := classify.ParseRequest(body)
	if len(blocks) == 0 {
		// Can't parse — let it through as-is (better than blocking)
		return &RequestContext{Redactor: redact.New()}, body, false, nil
	}

	// Parse as generic JSON for modification
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		return &RequestContext{Redactor: redact.New()}, body, false, nil // unparseable — pass through
	}

	messages, ok := request["messages"].([]interface{})
	if !ok {
		return &RequestContext{Redactor: redact.New()}, body, false, nil
	}

	// Per-request Redactor — prevents concurrent cross-contamination
	reqRedactor := redact.New()
	ctx = &RequestContext{Redactor: reqRedactor}

	var redactionSummary redact.Summary = make(redact.Summary)
	anyBlocked := false

	blockIdx := 0
	for _, msg := range messages {
		m, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}

		if blockIdx >= len(blocks) {
			break
		}

		block := blocks[blockIdx]
		blockIdx++
		result := r.Classifier.ClassifyBlock(block)

		switch result.Tier {
		case rules.TierBlocked:
			anyBlocked = true
			if r.AuditLog != nil {
				r.AuditLog.Record(audit.Entry{
					Agent:    agent,
					Provider: provider,
					Action:   "read",
					Target:   block.FilePath,
					Tier:     "blocked",
					Notes:    "blocked by rule: " + result.Source,
				})
			}
			// Replace content with block message
			setMessageContent(m, "[Tidebreak: access denied — content blocked]")

		case rules.TierLocalOnly:
			// Send to Ollama for summarization
			if r.Ollama != nil && r.Ollama.Available() {
				summary, err := r.Ollama.Summarize(block.Content)
				if err != nil {
					// Ollama failed — block the content
					setMessageContent(m, "[Tidebreak: local-only content could not be processed]")
					if r.AuditLog != nil {
						r.AuditLog.Record(audit.Entry{
							Agent:    agent,
							Provider: provider,
							Action:   "read",
							Target:   block.FilePath,
							Tier:     "local-only",
							Notes:    "ollama failed: " + err.Error(),
						})
					}
				} else {
					setMessageContent(m, "[Ollama summary: "+summary+"]")
					if r.AuditLog != nil {
						r.AuditLog.Record(audit.Entry{
							Agent:    agent,
							Provider: provider,
							Action:   "read",
							Target:   block.FilePath,
							Tier:     "local-only",
							Notes:    "summarized by Ollama",
						})
					}
				}
			} else {
				// No Ollama — block
				setMessageContent(m, "[Tidebreak: local-only content blocked — Ollama not available]")
				if r.AuditLog != nil {
					r.AuditLog.Record(audit.Entry{
						Agent:    agent,
						Provider: provider,
						Action:   "read",
						Target:   block.FilePath,
						Tier:     "blocked",
						Notes:    "ollama unavailable",
					})
				}
			}

		case rules.TierRedacted:
			// Apply pattern redaction to content
			content := getBlockContent(m)
			redacted, summary := reqRedactor.Redact(content)
			setMessageContent(m, redacted)
			for k, v := range summary {
				redactionSummary[k] += v
			}
			if r.AuditLog != nil {
				redactionsJSON, _ := json.Marshal(summary)
				r.AuditLog.Record(audit.Entry{
					Agent:      agent,
					Provider:    provider,
					Action:     "read",
					Target:     block.FilePath,
					Tier:       "redacted",
					Redactions: string(redactionsJSON),
				})
			}

		case rules.TierPublic:
			// Pass through as-is
			if r.AuditLog != nil {
				r.AuditLog.Record(audit.Entry{
					Agent:    agent,
					Provider: provider,
					Action:   "read",
					Target:   block.FilePath,
					Tier:     "public",
				})
			}
		}
	}

	// Serialize the modified request
	modified, err := json.Marshal(request)
	if err != nil {
		return ctx, body, anyBlocked, nil
	}

	return ctx, modified, anyBlocked, nil
}

// ProcessResponse reverse-maps redaction tokens in the cloud model's response.
// This lets the agent see real values in the response instead of [TB:IP:1] tokens.
// ctx carries the per-request redactor mapping from ProcessRequest.
func (r *Router) ProcessResponse(ctx *RequestContext, body []byte) []byte {
	if ctx == nil || ctx.Redactor == nil {
		return body
	}
	tm := redact.NewTokenMatcher(ctx.Redactor)
	if !tm.HasMappings() {
		return body
	}

	// Try to parse as JSON and reverse-map string values
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		// Not JSON — try plain text
		return []byte(tm.Restore(string(body)))
	}

	restoreInPlace(response, tm)

	modified, err := json.Marshal(response)
	if err != nil {
		return body
	}
	return modified
}

// ProcessStreamChunk processes a single SSE streaming chunk from the cloud API.
// It reverse-maps any tokens that appear in the chunk, handling split tokens
// with a boundary buffer. The StreamRedactor is per-response — the caller
// should create one and reuse it across all chunks for a given response.
func (r *Router) ProcessStreamChunk(ctx *RequestContext, sr *redact.StreamRedactor, chunk []byte) []byte {
	if ctx == nil || ctx.Redactor == nil || sr == nil {
		return chunk
	}
	return sr.ProcessChunk(chunk)
}

// NewStreamRedactor creates a StreamRedactor for a streaming response,
// using the per-request redactor mapping. Call once per response and reuse
// across all chunks.
func (r *Router) NewStreamRedactor(ctx *RequestContext) *redact.StreamRedactor {
	if ctx == nil || ctx.Redactor == nil {
		return nil
	}
	tm := redact.NewTokenMatcher(ctx.Redactor)
	if !tm.HasMappings() {
		return nil
	}
	return redact.NewStreamRedactor(tm)
}

// setMessageContent sets the content of a message in a JSON message object.
func setMessageContent(m map[string]interface{}, content string) {
	m["content"] = content
}

// getBlockContent extracts the string content from a message.
func getBlockContent(m map[string]interface{}) string {
	if content, ok := m["content"].(string); ok {
		return content
	}
	// Array content (Anthropic)
	if content, ok := m["content"].([]interface{}); ok {
		var result string
		for _, part := range content {
			if p, ok := part.(map[string]interface{}); ok {
				if text, ok := p["text"].(string); ok {
					result += text + "\n"
				}
			}
		}
		return result
	}
	return ""
}

// restoreInPlace recursively walks a JSON structure and restores tokens in strings.
func restoreInPlace(v interface{}, tm *redact.TokenMatcher) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if s, ok := v.(string); ok {
				val[k] = tm.Restore(s)
			} else {
				restoreInPlace(v, tm)
			}
		}
	case []interface{}:
		for i, v := range val {
			if s, ok := v.(string); ok {
				val[i] = tm.Restore(s)
			} else {
				restoreInPlace(v, tm)
			}
		}
	}
}