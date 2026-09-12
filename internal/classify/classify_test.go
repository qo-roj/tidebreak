package classify

import (
	"encoding/json"
	"testing"

	"github.com/qo-roj/tidegate/internal/rules"
)

func makeRuleSet() *rules.RuleSet {
	cfg := &rules.Config{
		Blocks:    []string{"/etc/shadow", "~/.ssh/id_*"},
		LocalOnly: []string{"**/.env", "/etc/letsencrypt/"},
		Redact:    []string{"/var/log/**", "~/.zsh_history"},
	}
	return rules.BuildRuleSet(cfg, "test")
}

func TestClassifyBlockPublic(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content: "You are a helpful coding agent.",
		Role:    "system",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierPublic {
		t.Errorf("expected public, got %s", result.Tier)
	}
}

func TestClassifyBlockBlockedByPath(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content:  "root:$6$xyz...:19000:0:99999:7:::",
		FilePath: "/etc/shadow",
		Role:     "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierBlocked {
		t.Errorf("expected blocked, got %s", result.Tier)
	}
}

func TestClassifyBlockRedactedByPath(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content:  "server is starting up...",
		FilePath: "/var/log/syslog",
		Role:     "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierRedacted {
		t.Errorf("expected redacted, got %s", result.Tier)
	}
}

func TestClassifyBlockLocalOnlyByPath(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content:  "DATABASE_URL=postgres://user:pass@host/db",
		FilePath: "project/.env",
		Role:     "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierLocalOnly {
		t.Errorf("expected local-only, got %s", result.Tier)
	}
}

func TestClassifyBlockContentContainsPath(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content: "I read /etc/shadow and found the root hash",
		Role:    "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierBlocked {
		t.Errorf("expected blocked due to /etc/shadow in content, got %s", result.Tier)
	}
}

func TestClassifyBlockContentContainsLogPath(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content: "Check /var/log/nginx/access.log for errors",
		Role:    "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierRedacted {
		t.Errorf("expected redacted due to /var/log/ path in content, got %s", result.Tier)
	}
}

func TestParseRequestOpenAI(t *testing.T) {
	body := json.RawMessage(`{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are a coding agent."},
			{"role": "user", "content": "Read /etc/nginx/nginx.conf and show me the config"}
		]
	}`)

	blocks := ParseRequest(body)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(blocks))
	}

	if blocks[0].Role != "system" {
		t.Error("first block should be system")
	}
	if blocks[1].Role != "user" {
		t.Error("second block should be user")
	}
	if !blocks[0].IsSystemBlock {
		t.Error("system block should have IsSystemBlock=true")
	}
}

func TestParseRequestAnthropic(t *testing.T) {
	body := json.RawMessage(`{
		"model": "claude-opus-4-20250514",
		"messages": [
			{
				"role": "user",
				"content": [
					{"type": "text", "text": "Here's my config:"},
					{"type": "text", "text": "/etc/nginx/nginx.conf"}
				]
			}
		]
	}`)

	blocks := ParseRequest(body)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	if blocks[0].Role != "user" {
		t.Error("expected user role")
	}
	if blocks[0].Content == "" {
		t.Error("expected non-empty content")
	}
}

func TestParseRequestWithToolResult(t *testing.T) {
	body := json.RawMessage(`{
		"messages": [
			{"role": "user", "content": "read /etc/shadow"},
			{"role": "assistant", "tool_calls": [{"id": "1", "function": {"name": "read_file"}}]},
			{"role": "tool", "tool_call_id": "1", "content": "root:$6$..."}
		]
	}`)

	blocks := ParseRequest(body)
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if !blocks[1].IsToolResult {
		t.Error("assistant block with tool_calls should be tool result")
	}
	if !blocks[2].IsToolResult {
		t.Error("tool block should be tool result")
	}
}

func TestEscalateTier(t *testing.T) {
	tests := []struct {
		a, b, want rules.Tier
	}{
		{rules.TierPublic, rules.TierRedacted, rules.TierRedacted},
		{rules.TierRedacted, rules.TierLocalOnly, rules.TierLocalOnly},
		{rules.TierLocalOnly, rules.TierBlocked, rules.TierBlocked},
		{rules.TierPublic, rules.TierPublic, rules.TierPublic},
	}

	for _, tc := range tests {
		got := EscalateTier(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("EscalateTier(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestExtractPaths(t *testing.T) {
	content := "I read /etc/shadow and ~/.zsh_history then checked /var/log/syslog"
	paths := extractPaths(content)

	if len(paths) < 2 {
		t.Errorf("expected at least 2 paths, got %d: %v", len(paths), paths)
	}

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}
	if !found["/etc/shadow"] {
		t.Error("expected /etc/shadow in paths")
	}
	if !found["/var/log/syslog"] {
		t.Error("expected /var/log/syslog in paths")
	}
}

func TestClassifyBlockSSSKey(t *testing.T) {
	c := New(makeRuleSet())

	block := ContentBlock{
		Content:  "My private key is at ~/.ssh/id_ed25519",
		FilePath: "~/.ssh/id_ed25519",
		Role:     "user",
	}

	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierBlocked {
		t.Errorf("expected blocked for SSH key, got %s", result.Tier)
	}
}

// TestClassifyBlockAgentOverride verifies that per-agent overrides actually
// take effect — the regression test for the v0.2.0 bug where AgentOverrides
// were built but never consulted (ClassifyBlock ignored the agent parameter).
func TestClassifyBlockAgentOverride(t *testing.T) {
	// Global rules: /tmp/project/ is public (no rule matches).
	// Agent override for "claude": /tmp/project/secret.go is blocked.
	cfg := &rules.Config{
		AgentRules: map[string]*rules.Config{
			"claude": {
				Blocks: []string{"/tmp/project/secret.go"},
			},
		},
	}
	rs := rules.BuildRuleSet(cfg, "test")
	c := New(rs)

	block := ContentBlock{
		Content:  "package main",
		FilePath: "/tmp/project/secret.go",
		Role:     "user",
	}

	// Without agent — global rules apply, should be public.
	result := c.ClassifyBlock(block, "")
	if result.Tier != rules.TierPublic {
		t.Errorf("without agent: expected public, got %s", result.Tier)
	}

	// With agent — override applies, should be blocked.
	result = c.ClassifyBlock(block, "claude")
	if result.Tier != rules.TierBlocked {
		t.Errorf("with agent=claude: expected blocked, got %s", result.Tier)
	}
}
