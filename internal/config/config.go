// Package config handles loading and merging Tidebreak configuration from
// multiple sources: embedded defaults, preset files, user config, and
// project-local .tidebreak.conf files.
package config

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/earl-sid/tidebreak/internal/rules"
)

//go:embed rules/defaults.conf
var defaultsConf embed.FS

//go:embed rules/presets/desktop.conf
var desktopConf embed.FS

//go:embed rules/presets/server.conf
var serverConf embed.FS

//go:embed rules/presets/paranoid.conf
var paranoidConf embed.FS

// Gateway holds the runtime configuration for the Tidebreak gateway.
type Gateway struct {
	Port     int
	LogLevel string
	Preset   string
}

// Cloud holds cloud provider configuration.
type Cloud struct {
	AnthropicKey string
	OpenAIKey    string
	XAIKey       string
}

// Local holds local model (Ollama) configuration.
type Local struct {
	OllamaURL   string
	OllamaModel string
}

// AppConfig is the fully resolved configuration.
type AppConfig struct {
	Gateway Gateway
	Cloud   Cloud
	Local   Local
	RuleSet *rules.RuleSet
}

// Load resolves configuration from all sources in order:
// 1. Built-in defaults (embedded in binary)
// 2. Preset (embedded in binary)
// 3. User config (~/.config/tidebreak/tidebreak.conf)
// 4. Project-local config (./.tidebreak.conf)
// 5. CLI flags (passed as params)
func Load(cliPort int, cliPreset string) (*AppConfig, error) {
	cfg := &AppConfig{
		Gateway: Gateway{
			Port:     8842,
			LogLevel: "info",
			Preset:   "desktop",
		},
		Local: Local{
			OllamaURL:   "http://localhost:11434",
			OllamaModel: "llama3:8b",
		},
	}

	// 1. Built-in defaults (embedded)
	defaultsData, err := defaultsConf.ReadFile("rules/defaults.conf")
	if err != nil {
		return nil, fmt.Errorf("reading embedded defaults: %w", err)
	}
	defaultsCfg, err := rules.ParseConfigBytes(defaultsData, "defaults")
	if err != nil {
		return nil, fmt.Errorf("parsing defaults: %w", err)
	}
	mergedRules := defaultsCfg

	// 2. Preset (embedded)
	if cliPreset != "" {
		cfg.Gateway.Preset = cliPreset
	}
	presetData, err := loadPreset(cfg.Gateway.Preset)
	if err != nil {
		return nil, fmt.Errorf("loading preset %s: %w", cfg.Gateway.Preset, err)
	}
	if presetData != nil {
		presetCfg, err := rules.ParseConfigBytes(presetData, "preset:"+cfg.Gateway.Preset)
		if err != nil {
			return nil, fmt.Errorf("parsing preset: %w", err)
		}
		mergedRules = rules.MergeConfig(mergedRules, presetCfg)
	}

	// 3. User config
	home, _ := os.UserHomeDir()
	userConfigPath := filepath.Join(home, ".config", "tidebreak", "tidebreak.conf")
	if fileExists(userConfigPath) {
		userCfg, err := rules.ParseConfig(userConfigPath)
		if err != nil {
			return nil, fmt.Errorf("user config: %w", err)
		}
		if userCfg.Preset != "" {
			cfg.Gateway.Preset = userCfg.Preset
		}
		mergedRules = rules.MergeConfig(mergedRules, userCfg)
	}

	// 4. Project-local config
	if fileExists(".tidebreak.conf") {
		projCfg, err := rules.ParseConfig(".tidebreak.conf")
		if err != nil {
			return nil, fmt.Errorf("project config: %w", err)
		}
		if projCfg.Preset != "" {
			cfg.Gateway.Preset = projCfg.Preset
		}
		mergedRules = rules.MergeConfig(mergedRules, projCfg)
	}

	// 5. CLI overrides
	if cliPort > 0 {
		cfg.Gateway.Port = cliPort
	}

	// Build the rule set
	if mergedRules == nil {
		mergedRules = &rules.Config{
			Patterns: make(map[string]bool),
		}
	}
	cfg.RuleSet = rules.BuildRuleSet(mergedRules, "user")

	// Load cloud keys from environment
	cfg.Cloud.AnthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	cfg.Cloud.OpenAIKey = os.Getenv("OPENAI_API_KEY")
	cfg.Cloud.XAIKey = os.Getenv("XAI_API_KEY")

	return cfg, nil
}

// loadPreset returns the embedded preset config data for the given preset name.
// Returns nil if the preset name is empty or unknown.
func loadPreset(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	switch name {
	case "":
		return nil, nil
	case "desktop":
		return desktopConf.ReadFile("rules/presets/desktop.conf")
	case "server":
		return serverConf.ReadFile("rules/presets/server.conf")
	case "paranoid":
		return paranoidConf.ReadFile("rules/presets/paranoid.conf")
	default:
		return nil, fmt.Errorf("unknown preset: %s", name)
	}
}

// fileExists returns true if the path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// SaveDefaultConfig writes a default config file to the given path.
func SaveDefaultConfig(path string) error {
	content := `# Tidebreak Configuration
# Docs: https://github.com/earl-sid/tidebreak/blob/main/docs/rules-guide.md

[gateway]
port = 8842
log_level = info

[cloud]
# Cloud providers — keys are read from env vars by default
# ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.

[local]
ollama_url = http://localhost:11434
ollama_model = llama3:8b

[redaction]
# All built-in patterns enabled by default

[preset]
desktop
`
	return os.WriteFile(path, []byte(content), 0644)
}

// ParsePort parses a port string and returns the integer, or the default if empty/invalid.
func ParsePort(s string, defaultPort int) int {
	if s == "" {
		return defaultPort
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return defaultPort
	}
	return port
}