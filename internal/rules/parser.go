package rules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseConfig reads and parses a Tidebreak config file.
// The format is INI-style with sections [block], [local-only], [redact],
// [redaction.patterns], and [agent:<name>].
func ParseConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	return ParseConfigBytes(data, path)
}

// ParseConfigBytes parses config data from a byte slice.
// The path parameter is used for error messages only.
func ParseConfigBytes(data []byte, path string) (*Config, error) {
	cfg := &Config{
		Patterns:   make(map[string]bool),
		AgentRules: make(map[string]*Config),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // accept large configs

	var currentSection string
	var currentAgent string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.TrimSpace(line[1 : len(line)-1])

			switch {
			case section == "block":
				currentSection = "block"
				// Don't reset currentAgent if we're inside an agent block
			case section == "local-only":
				currentSection = "local-only"
			case section == "redact":
				currentSection = "redact"
			case section == "redaction.patterns":
				currentSection = "patterns"
			case strings.HasPrefix(section, "agent:"):
				currentAgent = strings.TrimSpace(section[len("agent:"):])
				currentSection = "block" // default section for agent rules
				if _, ok := cfg.AgentRules[currentAgent]; !ok {
					cfg.AgentRules[currentAgent] = &Config{
						Patterns:   make(map[string]bool),
						AgentRules: make(map[string]*Config),
					}
				}
			case section == "preset":
				currentSection = "preset"
				currentAgent = ""
			default:
				// Unknown section — could be other config like [gateway], [cloud], [local]
				currentSection = "skip"
				currentAgent = ""
			}
			continue
		}

		// Skip sections we don't process here
		if currentSection == "skip" {
			continue
		}

		// Preset value line (bare word under [preset])
		if currentSection == "preset" {
			val := strings.TrimSpace(line)
			if val == "desktop" || val == "server" || val == "paranoid" || strings.Contains(val, ",") {
				cfg.Preset = val
			}
			continue
		}

		// Pattern toggle: name = true/false
		if currentSection == "patterns" {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				cfg.Patterns[name] = val == "true" || val == "1" || val == "yes"
			}
			continue
		}

		// Path rules
		if currentSection == "block" || currentSection == "local-only" || currentSection == "redact" {
			// Skip key=value lines that aren't paths
			if strings.Contains(line, "=") && !looksLikePath(line) {
				continue
			}

			expanded := expandPath(line)

			if currentAgent != "" {
				agentCfg := cfg.AgentRules[currentAgent]
				switch currentSection {
				case "block":
					agentCfg.Blocks = append(agentCfg.Blocks, expanded)
				case "local-only":
					agentCfg.LocalOnly = append(agentCfg.LocalOnly, expanded)
				case "redact":
					agentCfg.Redact = append(agentCfg.Redact, expanded)
				}
			} else {
				switch currentSection {
				case "block":
					cfg.Blocks = append(cfg.Blocks, expanded)
				case "local-only":
					cfg.LocalOnly = append(cfg.LocalOnly, expanded)
				case "redact":
					cfg.Redact = append(cfg.Redact, expanded)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	return cfg, nil
}

// looksLikePath returns true if the line appears to be a path rather than a key=value setting.
func looksLikePath(s string) bool {
	// Paths start with /, ~, or **, or contain path separators
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "~") ||
		strings.HasPrefix(s, "**") ||
		strings.HasPrefix(s, "./") ||
		strings.Contains(s, "/") && !strings.Contains(s, "=")
}

// expandPath expands ~ and ~USER prefixes to absolute paths.
func expandPath(p string) string {
	if p == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	if strings.HasPrefix(p, "~") {
		// ~USER/path — expand for named user
		rest := p[1:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx == -1 {
			return p // can't expand, leave as-is
		}
		username := rest[:slashIdx]
		restPath := rest[slashIdx+1:]
		if username == "" {
			home, _ := os.UserHomeDir()
			return filepath.Join(home, restPath)
		}
		// Look up user home
		home := filepath.Join("/home", username)
		return filepath.Join(home, restPath)
	}
	return p
}

// MergeConfig merges a child config into a parent. Child values override parent.
// For path rules, child rules are appended (and take precedence during matching
// since they're evaluated later). For patterns, child values override parent.
// If parent is nil, it's treated as an empty config.
func MergeConfig(parent, child *Config) *Config {
	if parent == nil {
		parent = &Config{
			Patterns:   make(map[string]bool),
			AgentRules: make(map[string]*Config),
		}
	}
	merged := &Config{
		Patterns:   make(map[string]bool),
		AgentRules: make(map[string]*Config),
	}

	// Copy parent patterns
	for k, v := range parent.Patterns {
		merged.Patterns[k] = v
	}
	// Override with child patterns
	for k, v := range child.Patterns {
		merged.Patterns[k] = v
	}

	// Append path rules (child rules come after parent, so they win on conflicts)
	merged.Blocks = append(append(merged.Blocks, parent.Blocks...), child.Blocks...)
	merged.LocalOnly = append(append(merged.LocalOnly, parent.LocalOnly...), child.LocalOnly...)
	merged.Redact = append(append(merged.Redact, parent.Redact...), child.Redact...)

	// Merge agent rules
	for agent, ac := range parent.AgentRules {
		merged.AgentRules[agent] = ac
	}
	for agent, ac := range child.AgentRules {
		if existing, ok := merged.AgentRules[agent]; ok {
			merged.AgentRules[agent] = MergeConfig(existing, ac)
		} else {
			merged.AgentRules[agent] = ac
		}
	}

	// Child preset overrides parent
	merged.Preset = parent.Preset
	if child.Preset != "" {
		merged.Preset = child.Preset
	}

	return merged
}
