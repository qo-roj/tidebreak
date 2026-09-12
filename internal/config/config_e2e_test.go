package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qo-roj/tidegate/internal/rules"
)

// End-to-end config.Load test: a preset selected in the user config file
// must actually change the active rules (pre-fix: it only re-labeled
// cfg.Gateway.Preset and desktop rules stayed active).
func TestConfigPresetFromFileAppliesRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	confDir := filepath.Join(home, ".config", "tidegate")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	// User picks paranoid; if it applies, /var/log/syslog goes local-only
	// (paranoid has /var/log/** in local-only) instead of defaults'
	// redacted tier.
	err := os.WriteFile(filepath.Join(confDir, "tidegate.conf"), []byte(`
[preset]
paranoid

[redaction.patterns]
email = false
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(0, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	if cfg.Gateway.Preset != "paranoid" {
		t.Fatalf("preset label = %q, want paranoid", cfg.Gateway.Preset)
	}

	tier, _ := cfg.RuleSet.ClassifyPath("/var/log/syslog")
	if tier != rules.TierLocalOnly {
		t.Errorf("paranoid from config file did not apply: /var/log/syslog tier = %s, want local-only", tier)
	}

	// Sticky block across layers: SSH keys blocked by defaults must survive
	// paranoid's ~/** local-only rule.
	tier, _ = cfg.RuleSet.ClassifyPath(filepath.Join(home, ".ssh", "id_ed25519"))
	if tier != rules.TierBlocked {
		t.Errorf("sticky block failed live: ~/.ssh/id_ed25519 tier = %s, want blocked", tier)
	}

	// Pattern toggle from config file must reach the resolved rule set.
	if cfg.RuleSet.IsRedactionEnabled("email") {
		t.Error("email = false in user config did not disable the email pattern")
	}
	if !cfg.RuleSet.IsRedactionEnabled("ipv4") {
		t.Error("ipv4 should remain enabled (unmentioned → default on)")
	}
	// ipv4_private is extended and opt-in at the flags level — but the
	// paranoid preset selected by this user explicitly enables it.
	if !cfg.RuleSet.IsRedactionEnabled("ipv4_private") {
		t.Error("paranoid preset should enable ipv4_private (it sets the toggle true)")
	}
}

// CLI preset selection must keep working (it did pre-fix).
func TestConfigPresetFromCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg, err := Load(0, "paranoid")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Gateway.Preset != "paranoid" {
		t.Fatalf("preset label = %q, want paranoid", cfg.Gateway.Preset)
	}
	tier, _ := cfg.RuleSet.ClassifyPath("/var/log/syslog")
	if tier != rules.TierLocalOnly {
		t.Errorf("CLI paranoid did not apply: /var/log/syslog tier = %s, want local-only", tier)
	}
}

// Bad preset name must fail loudly (both CLI and config file).
func TestConfigUnknownPresetFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := Load(0, "no-such-preset"); err == nil {
		t.Error("unknown CLI preset should fail config.Load")
	}

	confDir := filepath.Join(home, ".config", "tidegate")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "tidegate.conf"), []byte("[preset]\nno-such-preset\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(0, ""); err == nil {
		t.Error("unknown config-file preset should fail config.Load")
	}
}
