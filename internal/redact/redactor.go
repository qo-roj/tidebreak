// Package redact provides pattern-based content redaction for the Tidebreak
// gateway. It scans content for sensitive data (IPs, emails, API keys, etc.)
// and replaces matches with opaque tokens, maintaining an in-memory mapping
// for reverse restoration in responses.
//
// Token format: [TB:CATEGORY:N] (e.g. [TB:IP:1], [TB:EMAIL:3])
// The TB: prefix makes collisions with natural text extremely unlikely.
package redact

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Pattern defines a single redaction pattern.
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Category string // token category, e.g. "IP", "EMAIL", "KEY"
	Enabled  bool
}

// Redactor holds active patterns and the token mapping for the current request.
// The mapping is never persisted, never logged, and is cleared after each
// request completes.
type Redactor struct {
	patterns    []*Pattern
	mapping     map[string]string // token → original value
	mu          sync.Mutex
	counters    map[string]int64 // per-category counter for unique tokens
}

// New creates a Redactor with default patterns. Use WithPatterns to customize.
func New() *Redactor {
	return &Redactor{
		mapping:  make(map[string]string),
		counters: make(map[string]int64),
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

		// Use ReplaceAllStringFunc so each distinct match value gets its own
		// token. ReplaceAllString would replace ALL matches with a single token,
		// collapsing distinct values (e.g. two different IPs → same token).
		matchCount := 0
		result = p.Regex.ReplaceAllStringFunc(result, func(match string) string {
			matchCount++
			return r.allocateToken(p, match)
		})
		if matchCount > 0 {
			summary[p.Name] = matchCount
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
	r.counters = make(map[string]int64)
}

// MappingCount returns how many redactions are stored (for audit logging).
func (r *Redactor) MappingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.mapping)
}

// allocateToken creates a unique token for a matched value and stores the mapping.
// Token format: [TB:CATEGORY:N] — e.g. [TB:IP:1], [TB:EMAIL:2]
func (r *Redactor) allocateToken(p *Pattern, original string) string {
	// Check if we already mapped this exact value
	for token, val := range r.mapping {
		if val == original {
			return token
		}
	}

	category := p.Category
	if category == "" {
		category = "REDACTED"
	}
	n := r.counters[category] + 1
	r.counters[category] = n
	token := fmt.Sprintf("[TB:%s:%d]", category, n)
	r.mapping[token] = original
	return token
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

// replaceAll replaces all occurrences of old with new in s.
func replaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}