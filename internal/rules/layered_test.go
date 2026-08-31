package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// homePath returns a path under the current user's home directory. Tests
// must use this instead of hardcoded /home/<name> paths — configs use ~
// globs, which expand to the test runner's own HOME.
func homePath(t *testing.T, rel string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, rel)
}

// ─────────────────────────────────────────────────────────────────────
// Cross-layer tier resolution (security-critical semantics)
// ─────────────────────────────────────────────────────────────────────

func TestLayeredPresetCannotDowngradeBlock(t *testing.T) {
	// Defaults block SSH keys; paranoid preset's ~/** local-only rule must
	// NOT downgrade them. This was the pre-fix behavior (fail-open).
	defaultsCfg, _ := ParseConfigBytes([]byte(`
[block]
~/.ssh/id_*
~/.ssh/known_hosts
`), "defaults")
	paranoidCfg, _ := ParseConfigBytes([]byte(`
[block]
**/*secret*

[local-only]
~/**
`), "paranoid")

	rs := BuildRuleSetLayered([]LayeredConfig{
		{Cfg: defaultsCfg, Layer: LayerDefaults, Source: "defaults"},
		{Cfg: paranoidCfg, Layer: LayerPreset, Source: "paranoid"},
	})

	for _, p := range []string{homePath(t, ".ssh/id_ed25519"), homePath(t, ".ssh/known_hosts")} {
		tier, _ := rs.ClassifyPath(p)
		if tier != TierBlocked {
			t.Errorf("preset downgraded blocked path %s to %s — blocks must survive preset layers", p, tier)
		}
	}
}

func TestLayeredUserConfigCanHarden(t *testing.T) {
	// A user config must be able to escalate (redact → block) — that's
	// the whole point of user overrides.
	defaultsCfg, _ := ParseConfigBytes([]byte(`
[redact]
~/.zsh_history
`), "defaults")
	userCfg, _ := ParseConfigBytes([]byte(`
[block]
~/.zsh_history
`), "user")

	rs := BuildRuleSetLayered([]LayeredConfig{
		{Cfg: defaultsCfg, Layer: LayerDefaults, Source: "defaults"},
		{Cfg: userCfg, Layer: LayerUser, Source: "user"},
	})

	tier, _ := rs.ClassifyPath(homePath(t, ".zsh_history"))
	if tier != TierBlocked {
		t.Errorf("user [block] should override defaults [redact], got %s", tier)
	}
}

func TestLayeredUserConfigMayExplicitlyDowngradeBlock(t *testing.T) {
	// A human-authored layer can re-permit a blocked path (explicit trust).
	defaultsCfg, _ := ParseConfigBytes([]byte(`
[block]
~/.ssh/id_*
`), "defaults")
	userCfg, _ := ParseConfigBytes([]byte(`
[redact]
~/.ssh/id_ed25519
`), "user")

	rs := BuildRuleSetLayered([]LayeredConfig{
		{Cfg: defaultsCfg, Layer: LayerDefaults, Source: "defaults"},
		{Cfg: userCfg, Layer: LayerUser, Source: "user"},
	})

	tier, _ := rs.ClassifyPath(homePath(t, ".ssh/id_ed25519"))
	if tier != TierRedacted {
		t.Errorf("user layer should be able to explicitly downgrade a block, got %s", tier)
	}
}

func TestSameLayerLastMatchWinsStillWorks(t *testing.T) {
	// Whitelisting within one file: block .ssh/**, then redact .ssh/config.
	cfg := &Config{
		Blocks: []string{"~/.ssh/**"},
		Redact: []string{"~/.ssh/config"},
	}
	rs := BuildRuleSetLayered([]LayeredConfig{{Cfg: cfg, Layer: LayerUser, Source: "test"}})

	tier, _ := rs.ClassifyPath(homePath(t, ".ssh/id_rsa"))
	if tier != TierBlocked {
		t.Errorf("ssh key should be blocked, got %s", tier)
	}
	tier, _ = rs.ClassifyPath(homePath(t, ".ssh/config"))
	if tier != TierRedacted {
		t.Errorf("ssh config should be whitelisted to redact, got %s", tier)
	}
}

func TestHigherLayerOverridesLowerNonBlock(t *testing.T) {
	// Ordinary cross-layer override (redact → local-only) still works.
	defaultsCfg, _ := ParseConfigBytes([]byte(`
[redact]
/var/log/**
`), "defaults")
	userCfg, _ := ParseConfigBytes([]byte(`
[local-only]
/var/log/**
`), "user")

	rs := BuildRuleSetLayered([]LayeredConfig{
		{Cfg: defaultsCfg, Layer: LayerDefaults, Source: "defaults"},
		{Cfg: userCfg, Layer: LayerUser, Source: "user"},
	})

	tier, _ := rs.ClassifyPath("/var/log/syslog")
	if tier != TierLocalOnly {
		t.Errorf("user local-only should override defaults redact, got %s", tier)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Parser: inline comments, [cmd] sections, agent scope
// ─────────────────────────────────────────────────────────────────────

func TestParseInlineComments(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
[redact]
~/.config/Code/*           # VS Code settings may contain tokens
~/.config/obsidian/*       # Obsidian vault may contain personal notes
~/.config/discord/*

[redaction.patterns]
ipv4 = true
api_key_github = true     # ghp_*, gho_*, ghs_*, ghu_*
email = false             # disabled for this test
`), "probe")
	if err != nil {
		t.Fatal(err)
	}

	for i, p := range cfg.Redact {
		if strings.Contains(p, "#") {
			t.Errorf("redact[%d] = %q — inline comment not stripped", i, p)
		}
	}

	// Patterns: toggles with trailing comments must parse correctly.
	if !cfg.Patterns["api_key_github"] {
		t.Error("'api_key_github = true  # comment' should parse as enabled")
	}
	if !cfg.Patterns["ipv4"] {
		t.Error("ipv4 should be enabled")
	}
	if cfg.Patterns["email"] {
		t.Error("email should be disabled")
	}
}

func TestParseCmdSection(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
[cmd]
journalctl -u *           = redact
ps aux                    = redact
mysql *                   = local-only
cat /etc/shadow           = block
`), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Cmds) != 4 {
		t.Fatalf("expected 4 cmd rules, got %d — [cmd] section dropped", len(cfg.Cmds))
	}

	rs := BuildRuleSetLayered([]LayeredConfig{{Cfg: cfg, Layer: LayerUser, Source: "user"}})
	cases := []struct {
		cmd  string
		want Tier
	}{
		{"journalctl -u nginx", TierRedacted},
		{"ps aux", TierRedacted},
		{"mysql -u root -p foo", TierLocalOnly},
		{"cat /etc/shadow", TierBlocked},
		{"ls -la", TierPublic},
	}
	for _, c := range cases {
		tier, _ := rs.ClassifyCommand(c.cmd)
		if tier != c.want {
			t.Errorf("ClassifyCommand(%q) = %s, want %s", c.cmd, tier, c.want)
		}
	}
}

func TestParseGlobalScopeEscape(t *testing.T) {
	// [global] returns to global scope after an agent section.
	cfg, err := ParseConfigBytes([]byte(`
[agent:claude-code]
[block]
~/.secret-project/**

[global]
[block]
/etc/shadow
`), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Blocks) != 1 || cfg.Blocks[0] != "/etc/shadow" {
		t.Fatalf("global [block] after [agent:x] leaked into agent scope: global=%v", cfg.Blocks)
	}
	agentCfg, ok := cfg.AgentRules["claude-code"]
	if !ok || len(agentCfg.Blocks) != 1 {
		t.Errorf("agent rules missing or wrong: %+v", cfg.AgentRules)
	}
}

func TestParsePresetAcceptsAnyName(t *testing.T) {
	// "training-data" was rejected by the old whitelist.
	cfg, err := ParseConfigBytes([]byte(`
[preset]
training-data
`), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Preset != "training-data" {
		t.Errorf("preset = %q, want training-data", cfg.Preset)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Defaults / shipped configs must classify as documented
// ─────────────────────────────────────────────────────────────────────

func TestShippedDefaultsClassifySecrets(t *testing.T) {
	defaultsData, err := os.ReadFile("../config/rules/defaults.conf")
	if err != nil {
		t.Skip("defaults.conf not readable from test dir")
	}
	defaultsCfg, err := ParseConfigBytes(defaultsData, "defaults")
	if err != nil {
		t.Fatal(err)
	}
	rs := BuildRuleSetLayered([]LayeredConfig{{Cfg: defaultsCfg, Layer: LayerDefaults, Source: "defaults"}})

	cases := []struct {
		path string
		want Tier
	}{
		{"/etc/letsencrypt/live/app.example.com/privkey.pem", TierLocalOnly},
		{homePath(t, ".gnupg/private-keys-v1.d/key.asc"), TierBlocked},
		{homePath(t, ".password-store/work/github.gpg"), TierBlocked},
		{homePath(t, ".ssh/id_ed25519"), TierBlocked},
		{homePath(t, ".zsh_history"), TierRedacted},
	}
	for _, c := range cases {
		tier, _ := rs.ClassifyPath(c.path)
		if tier != c.want {
			t.Errorf("defaults: ClassifyPath(%q) = %s, want %s", c.path, tier, c.want)
		}
	}
}
