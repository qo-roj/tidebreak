// Package ollama provides a client for local Ollama model integration.
// It handles the two-stage redaction pipeline: Ollama summarizes local-only
// content to de-identify it, then the regex redactor scrubs any remaining
// structured PII from the summary before forwarding to the cloud.
package ollama

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/earl-sid/tidebreak/internal/redact"
)

// DefaultSummarizationPrompt is the prompt used for local-only content.
const DefaultSummarizationPrompt = `You are a privacy filter. Summarize the following content for an AI coding agent. Remove ALL personally identifiable information:
- IP addresses (replace with [REDACTED_IP])
- Email addresses (replace with [REDACTED_EMAIL])
- Phone numbers (replace with [REDACTED_PHONE])
- API keys, tokens, passwords (replace with [REDACTED_SECRET])
- Usernames and real names (replace with [REDACTED_USER])
- Hostnames (replace with [REDACTED_HOST])

KEEP all technical information that is not PII:
- Error messages and stack traces
- Config keys and structure (but not values)
- Service names and package versions
- Code logic and patterns
- File paths (if they don't reveal user identity)

Output only the summary, no preamble.`

// Client connects to a local Ollama instance.
type Client struct {
	URL   string
	Model string
	HTTP  *http.Client
}

// New creates an Ollama client. url is typically http://localhost:11434.
// If the URL is not localhost and uses plain HTTP, a warning is printed
// since local-only content will be sent unencrypted over the network.
func New(url, model string) *Client {
	if !strings.HasPrefix(url, "https://") && !isLocalhost(url) {
		fmt.Fprintf(os.Stderr, "WARNING: Ollama URL %s is not localhost and uses plain HTTP — local-only content will be sent unencrypted\n", url)
	}
	return &Client{
		URL:   url,
		Model: model,
		HTTP:  &http.Client{Timeout: 60 * time.Second},
	}
}

// isLocalhost checks if a URL points to localhost.
func isLocalhost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == ""
}

// SummarizeRequest is the Ollama API request body.
type SummarizeRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// SummarizeResponse is the Ollama API response body.
type SummarizeResponse struct {
	Response string `json:"response"`
}

// Summarize sends content to Ollama for de-identification, then runs
// the result through the pattern redactor (stage 2). Returns the
// two-stage scrubbed summary.
//
// If Ollama is unavailable, returns an error. The caller should
// block local-only content in this case (never send it to cloud).
func (c *Client) Summarize(content string) (string, error) {
	// Stage 1: Ollama summarization
	summary, err := c.callOllama(content)
	if err != nil {
		return "", fmt.Errorf("ollama summarization: %w", err)
	}

	// Stage 2: Pattern redaction on the summary
	// Per-call Redactor prevents concurrent cross-contamination
	redactor := redact.New()
	defer redactor.Clear()
	scrubbed, _ := redactor.Redact(summary)

	return scrubbed, nil
}

// callOllama sends the actual HTTP request to the Ollama API.
func (c *Client) callOllama(content string) (string, error) {
	reqBody := SummarizeRequest{
		Model:  c.Model,
		Prompt: DefaultSummarizationPrompt + "\n\n---\n\n" + content,
		Stream: false,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.HTTP.Post(c.URL+"/api/generate", "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("calling ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(body))
	}

	var result SummarizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding ollama response: %w", err)
	}

	return result.Response, nil
}

// Available checks if Ollama is running and the model is available.
func (c *Client) Available() bool {
	resp, err := c.HTTP.Get(c.URL + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Close is a no-op (kept for API compatibility).
func (c *Client) Close() {
}