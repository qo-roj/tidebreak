package rules

import (
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
)

// ClassifyPath determines the tier for a given file path by matching against
// all path rules. Rules are evaluated in order; the last matching rule wins
// (later config layers override earlier ones).
func (rs *RuleSet) ClassifyPath(path string) (Tier, string) {
	expandedPath := expandPath(path)
	bestTier := TierPublic
	bestSource := "default"

	for _, rule := range rs.PathRules {
		matched, err := matchPath(rule.Pattern, expandedPath)
		if err != nil {
			continue
		}
		if matched {
			bestTier = rule.Tier
			bestSource = rule.Source
		}
	}

	return bestTier, bestSource
}

// ClassifyPathForAgent classifies a path using agent-specific overrides if they exist,
// falling back to the global rule set.
func (rs *RuleSet) ClassifyPathForAgent(path string, agent string) (Tier, string) {
	if agentRules, ok := rs.AgentOverrides[agent]; ok {
		tier, source := agentRules.ClassifyPath(path)
		if tier != TierPublic || source != "default" {
			return tier, source + " (agent:" + agent + ")"
		}
	}
	return rs.ClassifyPath(path)
}

// matchPath uses doublestar glob matching against a pattern.
// Handles ** for recursive matching.
func matchPath(pattern, path string) (bool, error) {
	// doublestar.Match with ** support
	return doublestar.Match(pattern, path)
}

// BuildRuleSet creates a RuleSet from a merged Config, converting path lists
// to PathRule slices in the correct order.
func BuildRuleSet(cfg *Config, source string) *RuleSet {
	rs := &RuleSet{
		RedactionFlags: make(map[string]bool),
		AgentOverrides: make(map[string]*RuleSet),
		Preset:        cfg.Preset,
	}

	// Add path rules in order: block, local-only, redact.
	// Expand paths so ~ is resolved for glob matching.
	for _, p := range cfg.Blocks {
		rs.PathRules = append(rs.PathRules, PathRule{
			Pattern: expandPath(p),
			Tier:    TierBlocked,
			Source:  source,
		})
	}
	for _, p := range cfg.LocalOnly {
		rs.PathRules = append(rs.PathRules, PathRule{
			Pattern: expandPath(p),
			Tier:    TierLocalOnly,
			Source:  source,
		})
	}
	for _, p := range cfg.Redact {
		rs.PathRules = append(rs.PathRules, PathRule{
			Pattern: expandPath(p),
			Tier:    TierRedacted,
			Source:  source,
		})
	}

	// Copy pattern flags
	for k, v := range cfg.Patterns {
		rs.RedactionFlags[k] = v
	}

	// Build agent overrides
	for agent, ac := range cfg.AgentRules {
		rs.AgentOverrides[agent] = BuildRuleSet(ac, source+":agent:"+agent)
	}

	return rs
}

// IsRedactionEnabled checks if a named redaction pattern is enabled.
// Defaults to true if not explicitly set (conservative: redact by default).
func (rs *RuleSet) IsRedactionEnabled(name string) bool {
	enabled, ok := rs.RedactionFlags[name]
	if !ok {
		return true // default: enabled
	}
	return enabled
}

// _ suppresses unused import warning for filepath (used via expandPath in types.go)
var _ = filepath.Join