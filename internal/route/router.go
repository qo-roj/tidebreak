// Package route implements the routing logic for the Tidebreak gateway.
// It decides where content goes: cloud API (scrubbed), local Ollama (full data),
// or blocked entirely. It coordinates the classifier, redactor, and Ollama client.
package route

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/earl-sid/tidebreak/internal/audit"
	"github.com/earl-sid/tidebreak/internal/classify"
	"github.com/earl-sid/tidebreak/internal/ollama"
	"github.com/earl-sid/tidebreak/internal/redact"
	"github.com/earl-sid/tidebreak/internal/rules"
)

// Router coordinates the classification, redaction, and routing of content.
type Router struct {
	Classifier  *classify.Classifier
	Redactor    *redact.Redactor
	Ollama      *ollama.Client
	AuditLog    *audit.Log
}

// New creates a Router with all dependencies wired.
func New(rs *rules.RuleSet, ollamaClient *ollama.Client, auditLog *audit.Log) *Router {
	return &Router{
		Classifier: classify.New(rs),
		Redactor:   redact.New(),
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
//   - modifiedBody: the request body with redactions/summaries applied
//   - blocked: true if any block was blocked (caller should return error)
//   - error: for unexpected failures
func (r *Router) ProcessRequest(body []byte, agent string, provider string) (modifiedBody []byte, blocked bool, err error) {
	// Parse the request into content blocks
	blocks := classify.ParseRequest(body)
	if len(blocks) == 0 {
		// Can't parse — let it through as-is (better than blocking)
		return body, false, nil
	}

	// Parse as generic JSON for modification
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		return body, false, nil // unparseable — pass through
	}

	messages, ok := request["messages"].([]interface{})
	if !ok {
		return body, false, nil
	}

	r.Redactor.Clear()
	var redactionSummary redact.Summary = make(redact.Summary)
	anyBlocked := false

	for i, msg := range messages {
		m, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}

		if i >= len(blocks) {
			break
		}

		block := blocks[i]
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
			redacted, summary := r.Redactor.Redact(content)
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
		return body, anyBlocked, nil
	}

	return modified, anyBlocked, nil
}

// ProcessResponse reverse-maps redaction tokens in the cloud model's response.
// This lets the agent see real values in the response instead of [TB:IP:1] tokens.
func (r *Router) ProcessResponse(body []byte) []byte {
	tm := redact.NewTokenMatcher(r.Redactor)
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
// with a boundary buffer.
func (r *Router) ProcessStreamChunk(chunk []byte) []byte {
	tm := redact.NewTokenMatcher(r.Redactor)
	if !tm.HasMappings() {
		return chunk
	}
	sr := redact.NewStreamRedactor(tm)
	return sr.ProcessChunk(chunk)
}

// ProxyToUpstream forwards the (already redacted) request body to the
// upstream cloud API and returns the response.
func (r *Router) ProxyToUpstream(req *http.Request, upstreamURL string) (*http.Response, error) {
	req.URL.Scheme = "https"
	req.URL.Host = upstreamURL
	req.RequestURI = ""

	// Remove the X-Tidebreak-Agent header before forwarding
	req.Header.Del("X-Tidebreak-Agent")

	client := &http.Client{}
	return client.Do(req)
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

// CopyRequestBody reads the request body safely.
func CopyRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	return body, err
}

// fmtError wraps an error with context.
func fmtError(ctx string, err error) error {
	return fmt.Errorf("%s: %w", ctx, err)
}