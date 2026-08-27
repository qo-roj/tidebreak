// Package redact provides pattern-based content redaction for the Tidebreak
// gateway. It scans content for sensitive data (IPs, emails, API keys, etc.)
// and replaces matches with opaque tokens, maintaining an in-memory mapping
// for reverse restoration in responses.
package redact

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
)

// Pattern defines a single redaction pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Replacement string // template, e.g. "[IP_REDACTED_%d]"
	Enabled     bool
}

// Redactor holds active patterns and the token mapping for the current request.
// The mapping is never persisted, never logged, and is cleared after each
// request completes.
type Redactor struct {
	patterns []*Pattern
	mapping  map[string]string // token → original value
	mu       sync.Mutex
	counter  int64 // per-pattern counter for unique tokens
}

// New creates a Redactor with default patterns. Use WithPatterns to customize.
func New() *Redactor {
	return &Redactor{
		mapping:  make(map[string]string),
		patterns: DefaultPatterns(),
	}
}

// WithPatterns replaces the pattern set. Returns the redactor for chaining.
func (r *Redactor) WithPatterns(patterns []*Pattern) *Redactor {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.patterns = patterns
	return r
}

// EnablePattern enables a named pattern. Returns false if not found.
func (r *Redactor) EnablePattern(name string) bool {
	return r.setPatternEnabled(name, true)
}

// DisablePattern disables a named pattern. Returns false if not found.
func (r *Redactor) DisablePattern(name string) bool {
	return r.setPatternEnabled(name, false)
}

func (r *Redactor) setPatternEnabled(name string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.patterns {
		if p.Name == name {
			p.Enabled = enabled
			return true
		}
	}
	return false
}

// Redact scans content and replaces all sensitive matches with tokens.
// Returns the redacted content and a summary of what was redacted.
func (r *Redactor) Redact(content string) (string, Summary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := Summary{}
	result := content

	for _, p := range r.patterns {
		if !p.Enabled {
			continue
		}
		matches := p.Regex.FindAllString(result, -1)
		if len(matches) == 0 {
			continue
		}

		summary[p.Name] = len(matches)

		for _, match := range matches {
			token := r.allocateToken(p, match)
			result = p.Regex.ReplaceAllString(result, token)
		}
	}

	return result, summary
}

// Restore reverse-maps tokens in a response back to their original values.
// This lets the agent work with real data in the cloud model's response.
func (r *Redactor) Restore(content string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := content
	for token, original := range r.mapping {
		result = replaceAll(result, token, original)
	}
	return result
}

// Clear wipes the mapping table. Call after a request completes.
func (r *Redactor) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mapping = make(map[string]string)
	r.counter = 0
}

// MappingCount returns how many redactions are stored (for audit logging).
func (r *Redactor) MappingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.mapping)
}

// allocateToken creates a unique token for a matched value and stores the mapping.
func (r *Redactor) allocateToken(p *Pattern, original string) string {
	// Check if we already mapped this exact value
	for token, val := range r.mapping {
		if val == original {
			return token
		}
	}

	n := atomic.AddInt64(&r.counter, 1)
	prefix := tokenPrefix(p.Replacement)
	token := fmt.Sprintf("%s%d]", prefix, n)
	r.mapping[token] = original
	return token
}

// tokenPrefix extracts the prefix from a replacement template like "[IP_REDACTED_%d]" → "[IP_REDACTED_".
func tokenPrefix(template string) string {
	// Templates are like "[IP_REDACTED_%d]" — strip the "%d]" suffix
	for i := len(template) - 1; i >= 0; i-- {
		if template[i] == '%' {
			return template[:i]
		}
	}
	return template
}

// Summary maps pattern name → count of redactions.
type Summary map[string]int

// Total returns the total number of redactions across all patterns.
func (s Summary) Total() int {
	total := 0
	for _, count := range s {
		total += count
	}
	return total
}

// replaceAll is a simple string replacer (avoiding regexp for literal strings).
func replaceAll(s, old, new string) string {
	if old == "" {
		return s
	}
	result := ""
	for {
		idx := indexOf(s, old)
		if idx < 0 {
			return result + s
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}