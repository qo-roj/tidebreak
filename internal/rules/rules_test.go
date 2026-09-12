package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tidegate.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseConfigBasic(t *testing.T) {
	content := `
# Basic config
[block]
~/.ssh/id_*
/etc/shadow

[local-only]
~/.config/himalaya/*
/var/log/**

[redact]
~/.zsh_history

[redaction.patterns]
ipv4 = true
email = false
`
	path := writeTestConfig(t, content)
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Blocks) != 2 {
		t.Errorf("expected 2 block rules, got %d", len(cfg.Blocks))
	}
	if len(cfg.LocalOnly) != 2 {
		t.Errorf("expected 2 local-only rules, got %d", len(cfg.LocalOnly))
	}
	if len(cfg.Redact) != 1 {
		t.Errorf("expected 1 redact rule, got %d", len(cfg.Redact))
	}

	if cfg.Patterns["ipv4"] != true {
		t.Error("ipv4 should be enabled")
	}
	if cfg.Patterns["email"] != false {
		t.Error("email should be disabled")
	}
}

func TestParseConfigAgentRules(t *testing.T) {
	content := `
[block]
~/.ssh/**

[agent:claude]
[redact]
~/projects/**

[agent:codex]
[block]
~/projects/company-internal/**
`
	path := writeTestConfig(t, content)
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.AgentRules) != 2 {
		t.Fatalf("expected 2 agent rule sets, got %d", len(cfg.AgentRules))
	}

	claudeRules, ok := cfg.AgentRules["claude"]
	if !ok {
		t.Fatal("missing claude agent rules")
	}
	if len(claudeRules.Redact) != 1 {
		t.Errorf("claude should have 1 redact rule, got %d", len(claudeRules.Redact))
	}

	codexRules, ok := cfg.AgentRules["codex"]
	if !ok {
		t.Fatal("missing codex agent rules")
	}
	if len(codexRules.Blocks) != 1 {
		t.Errorf("codex should have 1 block rule, got %d", len(codexRules.Blocks))
	}
}

func TestParseConfigPreset(t *testing.T) {
	content := `
[preset]
desktop
`
	path := writeTestConfig(t, content)
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Preset != "desktop" {
		t.Errorf("expected preset 'desktop', got '%s'", cfg.Preset)
	}
}

func TestPathExpansion(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~/.ssh/id_rsa", filepath.Join(home, ".ssh", "id_rsa")},
		{"/etc/shadow", "/etc/shadow"},
		{"~root/.bashrc", "/home/root/.bashrc"},
		{"**/.env", "**/.env"},
		{"~/Documents/**", filepath.Join(home, "Documents", "**")},
	}

	for _, tc := range tests {
		got := expandPath(tc.input)
		if got != tc.expected {
			t.Errorf("expandPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestMergeConfig(t *testing.T) {
	parent := &Config{
		Blocks:   []string{"~/.ssh/id_*"},
		Redact:   []string{"~/.zsh_history"},
		Patterns: map[string]bool{"ipv4": true, "email": true},
	}

	child := &Config{
		Blocks:   []string{"/etc/shadow"},
		Patterns: map[string]bool{"email": false},
	}

	merged := MergeConfig(parent, child)

	if len(merged.Blocks) != 2 {
		t.Errorf("expected 2 block rules after merge, got %d", len(merged.Blocks))
	}
	// Child should override parent for patterns
	if merged.Patterns["email"] != false {
		t.Error("child should override email to false")
	}
	if merged.Patterns["ipv4"] != true {
		t.Error("parent ipv4 should be preserved")
	}
}

func TestClassifyPath(t *testing.T) {
	cfg := &Config{
		Blocks:    []string{"~/.ssh/id_*"},
		LocalOnly: []string{"**/.env"},
		Redact:    []string{"/var/log/**"},
	}
	rs := BuildRuleSet(cfg, "test")

	tests := []struct {
		path     string
		wantTier Tier
	}{
		{filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"), TierBlocked},
		{"/var/log/syslog", TierRedacted},
		{"/var/log/nginx/access.log", TierRedacted},
		{"/etc/nginx/nginx.conf", TierPublic},
		{"project/.env", TierLocalOnly},
		{"/home/user/code/main.go", TierPublic},
	}

	for _, tc := range tests {
		tier, _ := rs.ClassifyPath(tc.path)
		if tier != tc.wantTier {
			t.Errorf("ClassifyPath(%q) = %s, want %s", tc.path, tier, tc.wantTier)
		}
	}
}

func TestClassifyPathLastMatchWins(t *testing.T) {
	// When two rules match, the later (more specific) one wins
	cfg := &Config{
		Blocks: []string{
			"~/.ssh/**", // block everything in .ssh
		},
		Redact: []string{
			"~/.ssh/config", // but redact (allow) the config file
		},
	}
	rs := BuildRuleSet(cfg, "test")

	// Private key should be blocked
	sshDir, _ := os.UserHomeDir()
	keyPath := filepath.Join(sshDir, ".ssh", "id_rsa")
	tier, _ := rs.ClassifyPath(keyPath)
	if tier != TierBlocked {
		t.Errorf("private key should be blocked, got %s", tier)
	}

	// Config should be redacted (last match wins)
	cfgPath := filepath.Join(sshDir, ".ssh", "config")
	tier, _ = rs.ClassifyPath(cfgPath)
	if tier != TierRedacted {
		t.Errorf("ssh config should be redacted (override), got %s", tier)
	}
}

func TestClassifyPathForAgent(t *testing.T) {
	globalCfg := &Config{
		Redact: []string{"~/projects/**"},
	}
	agentCfg := &Config{
		Blocks: []string{"~/projects/company-internal/**"},
	}
	globalCfg.AgentRules = map[string]*Config{
		"codex": agentCfg,
	}

	rs := BuildRuleSet(globalCfg, "test")

	// For claude: uses global rules (redact)
	tier, _ := rs.ClassifyPathForAgent(filepath.Join(os.Getenv("HOME"), "projects", "myapp", "main.go"), "claude")
	if tier != TierRedacted {
		t.Errorf("claude should get redacted for projects, got %s", tier)
	}

	// For codex: uses agent override (block for internal)
	tier, _ = rs.ClassifyPathForAgent(filepath.Join(os.Getenv("HOME"), "projects", "company-internal", "secret.go"), "codex")
	if tier != TierBlocked {
		t.Errorf("codex should get blocked for internal projects, got %s", tier)
	}
}

func TestIsRedactionEnabled(t *testing.T) {
	cfg := &Config{
		Patterns: map[string]bool{
			"ipv4":  true,
			"email": false,
			"jwt":   true,
		},
	}
	rs := BuildRuleSet(cfg, "test")

	if !rs.IsRedactionEnabled("ipv4") {
		t.Error("ipv4 should be enabled")
	}
	if rs.IsRedactionEnabled("email") {
		t.Error("email should be disabled")
	}
	// Not in map → defaults to true (conservative)
	if !rs.IsRedactionEnabled("phone") {
		t.Error("phone should default to enabled")
	}
}

func TestGlobDoublestar(t *testing.T) {
	cfg := &Config{
		LocalOnly: []string{
			"/var/log/**",
			"**/.env",
			"**/credentials*",
		},
	}
	rs := BuildRuleSet(cfg, "test")

	tests := []struct {
		path     string
		wantTier Tier
	}{
		{"/var/log/nginx/access.log", TierLocalOnly},
		{"/var/log/syslog", TierLocalOnly},
		{"/var/log/sub/dir/deep.log", TierLocalOnly},
		{"project/.env", TierLocalOnly},
		{"~/projects/myapp/.env", TierLocalOnly},
		{"/home/user/credentials.json", TierLocalOnly},
		{"/home/user/app/credentials.yaml", TierLocalOnly},
		{"/etc/passwd", TierPublic},
	}

	for _, tc := range tests {
		tier, _ := rs.ClassifyPath(tc.path)
		if tier != tc.wantTier {
			t.Errorf("ClassifyPath(%q) = %s, want %s", tc.path, tier, tc.wantTier)
		}
	}
}
