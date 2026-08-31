package rules

import (
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// ClassifyPath determines the tier for a given file path by matching against
// all path rules.
//
// Resolution semantics:
//  1. Within the same config layer, the last matching rule wins — later rules
//     in the same file whitelist earlier ones (e.g. block ~/.ssh/** then
//     redact ~/.ssh/config).
//  2. Across layers, a higher layer overrides a lower one — except that a
//     "blocked" verdict from a lower layer can only be overridden by a rule
//     from a human-authored layer (user config or project config). A preset
//     may never downgrade a block: blocked content stays blocked unless a
//     human explicitly re-permits it.
func (rs *RuleSet) ClassifyPath(path string) (Tier, string) {
	expandedPath := expandPath(path)
	return rs.classifyPathExpanded(expandedPath, rs.PathRules)
}

// classifyPathExpanded resolves a tier from a path-rule list with the sticky-
// block semantics documented on ClassifyPath.
func (rs *RuleSet) classifyPathExpanded(path string, rules []PathRule) (Tier, string) {
	bestTier := TierPublic
	bestSource := "default"
	bestLayer := 0

	for _, rule := range rules {
		matched, err := matchPath(rule.Pattern, path)
		if err != nil || !matched {
			continue
		}

		switch {
		case rule.Layer == bestLayer:
			// Same layer: last match wins (in-file whitelisting).
			bestTier = rule.Tier
			bestSource = rule.Source
		case rule.Layer > bestLayer:
			// Higher layer overrides the lower one, unless the lower layer
			// blocked the path and the higher layer is not human-authored.
			if bestTier == TierBlocked && rule.Layer < LayerUser {
				continue // presets may not downgrade blocks
			}
			bestTier = rule.Tier
			bestSource = rule.Source
			bestLayer = rule.Layer
		}
		// Lower layer than the current best — ignored.
	}

	return bestTier, bestSource
}

// ClassifyPathForAgent classifies a path using agent-specific overrides if
// they exist, falling back to the global rule set.
func (rs *RuleSet) ClassifyPathForAgent(path string, agent string) (Tier, string) {
	if agentRules, ok := rs.AgentOverrides[agent]; ok {
		tier, source := agentRules.ClassifyPath(path)
		if tier != TierPublic || source != "default" {
			return tier, source + " (agent:" + agent + ")"
		}
	}
	return rs.ClassifyPath(path)
}

// ClassifyCommand matches a command string against [cmd] rules. Returns
// (TierPublic, "default") when no rule matches or when no command rules were
// configured.
func (rs *RuleSet) ClassifyCommand(cmd string) (Tier, string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || len(rs.CmdRules) == 0 {
		return TierPublic, "default"
	}
	expandedCmd := expandPath(cmd)
	// Last matching rule wins. [cmd] rules carry layer stamps, so cross-layer
	// sticky-block semantics apply here too.
	tier, source := rs.classifyPathExpanded(expandedCmd, rs.CmdRules)
	if tier == TierPublic && source == "default" {
		return TierPublic, "default"
	}
	return tier, source
}

// matchPath uses doublestar glob matching against a pattern.
// Handles ** for recursive matching.
func matchPath(pattern, path string) (bool, error) {
	return doublestar.Match(pattern, path)
}

// BuildRuleSet creates a RuleSet from a single Config. Use
// BuildRuleSetLayered when combining multiple config layers — it implements
// cross-layer block protection. Kept for single-layer callers and tests.
func BuildRuleSet(cfg *Config, source string) *RuleSet {
	return BuildRuleSetLayered([]LayeredConfig{{Cfg: cfg, Layer: LayerUser, Source: source}})
}

// BuildRuleSetLayered builds a RuleSet from an ordered list of config layers
// (lowest first). Rules keep their layer stamp so ClassifyPath can apply
// sticky-block semantics across layers. Agent rules are resolved per layer
// and the resulting agent RuleSets are combined with the same semantics.
func BuildRuleSetLayered(layers []LayeredConfig) *RuleSet {
	rs := &RuleSet{
		RedactionFlags: make(map[string]bool),
		AgentOverrides: make(map[string]*RuleSet),
	}

	// Collect pattern toggles and preset: later layers override earlier ones.
	for _, lc := range layers {
		if lc.Cfg == nil {
			continue
		}
		for k, v := range lc.Cfg.Patterns {
			rs.RedactionFlags[k] = v
		}
		if lc.Cfg.Preset != "" {
			rs.Preset = lc.Cfg.Preset
		}
	}

	// Merge agent configs across layers (each agent's layers combine with
	// the same layered semantics as the global rules).
	agentLayers := make(map[string][]LayeredConfig)
	for _, lc := range layers {
		if lc.Cfg == nil {
			continue
		}
		for agent, ac := range lc.Cfg.AgentRules {
			agentLayers[agent] = append(agentLayers[agent], LayeredConfig{
				Cfg:    ac,
				Layer:  lc.Layer,
				Source: lc.Source + ":agent:" + agent,
			})
		}
	}
	for agent, aLayers := range agentLayers {
		rs.AgentOverrides[agent] = BuildRuleSetLayered(aLayers)
	}

	// Path rules and command rules, in layer order.
	for _, lc := range layers {
		if lc.Cfg == nil {
			continue
		}
		for _, p := range lc.Cfg.Blocks {
			rs.PathRules = append(rs.PathRules, PathRule{Pattern: expandPath(p), Tier: TierBlocked, Source: lc.Source, Layer: lc.Layer})
		}
		for _, p := range lc.Cfg.LocalOnly {
			rs.PathRules = append(rs.PathRules, PathRule{Pattern: expandPath(p), Tier: TierLocalOnly, Source: lc.Source, Layer: lc.Layer})
		}
		for _, p := range lc.Cfg.Redact {
			rs.PathRules = append(rs.PathRules, PathRule{Pattern: expandPath(p), Tier: TierRedacted, Source: lc.Source, Layer: lc.Layer})
		}
		for _, cr := range lc.Cfg.Cmds {
			if tier, ok := cmdTier(cr.Tier); ok {
				rs.CmdRules = append(rs.CmdRules, PathRule{Pattern: cr.Pattern, Tier: tier, Source: lc.Source + ":cmd", Layer: lc.Layer})
			}
		}
	}

	return rs
}

// cmdTier converts a [cmd] rule's tier string to a Tier.
func cmdTier(s string) (Tier, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block", "blocked":
		return TierBlocked, true
	case "local-only", "localonly", "local":
		return TierLocalOnly, true
	case "redact", "redacted":
		return TierRedacted, true
	case "public", "pass", "allow":
		return TierPublic, true
	}
	return TierPublic, false
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

// _ suppresses unused import warning for filepath (used via expandPath in parser.go)
var _ = filepath.Join
