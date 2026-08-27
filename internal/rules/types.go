// Package rules implements Tidebreak's layered rule system for content
// classification. Rules determine what tier (public, redacted, local-only,
// blocked) applies to a given file path or content reference.
//
// Resolution order (later overrides earlier):
//  1. Built-in defaults (embedded in binary)
//  2. Preset rules (desktop, server, paranoid)
//  3. User config (~/.config/tidebreak/tidebreak.conf)
//  4. Project-local config (./.tidebreak.conf)
//  5. CLI flags (highest priority)
package rules

// Tier represents the classification level for content.
type Tier int

const (
	// TierPublic: send to cloud as-is, no redaction.
	TierPublic Tier = iota
	// TierRedacted: scrub sensitive patterns, then send to cloud.
	TierRedacted
	// TierLocalOnly: route to local Ollama only, never to cloud.
	TierLocalOnly
	// TierBlocked: refuse access entirely, return error to agent.
	TierBlocked
)

func (t Tier) String() string {
	switch t {
	case TierPublic:
		return "public"
	case TierRedacted:
		return "redacted"
	case TierLocalOnly:
		return "local-only"
	case TierBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// PathRule maps a glob pattern to a tier.
type PathRule struct {
	Pattern string // glob pattern (doublestar-compatible)
	Tier    Tier
	Source  string // which config layer defined this rule (for debugging)
}

// RuleSet holds all resolved rules and enabled redaction patterns.
type RuleSet struct {
	PathRules       []PathRule
	RedactionFlags  map[string]bool // pattern name → enabled
	Preset         string
	AgentOverrides  map[string]*RuleSet // per-agent rule overrides (by agent name)
}

// Config represents a parsed configuration file (one layer of the stack).
type Config struct {
	Blocks      []string   // paths to block
	LocalOnly   []string   // paths for local-only
	Redact      []string   // paths to redact
	Patterns    map[string]bool // redaction pattern toggles
	AgentRules  map[string]*Config // per-agent sections
	Preset      string
}