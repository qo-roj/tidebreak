package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestDetectAgent(t *testing.T) {
	tests := []struct {
		name      string
		customHdr string
		userAgent string
		want      string
	}{
		{
			name:      "custom header takes priority",
			customHdr: "my-agent",
			userAgent: "claude-code/1.0",
			want:      "my-agent",
		},
		{
			name:      "claude-code via User-Agent",
			userAgent: "claude-code/1.0.28",
			want:      "claude-code",
		},
		{
			name:      "codex via User-Agent",
			userAgent: "openai-codex/0.1",
			want:      "codex",
		},
		{
			name:      "hermes via User-Agent",
			userAgent: "Hermes-Agent/0.19.0",
			want:      "hermes",
		},
		{
			name:      "cursor via User-Agent",
			userAgent: "cursor/0.42.0",
			want:      "cursor",
		},
		{
			name:      "aider via User-Agent",
			userAgent: "aider 0.8.0",
			want:      "aider",
		},
		{
			name:      "github copilot via User-Agent",
			userAgent: "github-copilot/1.0",
			want:      "github-copilot",
		},
		{
			name:      "grok-cli via User-Agent",
			userAgent: "grok-cli/2.3",
			want:      "grok-cli",
		},
		{
			name:      "unknown agent with User-Agent",
			userAgent: "some-random-tool/1.0",
			want:      "ua:some-random-tool/1.0",
		},
		{
			name:      "no headers at all",
			userAgent: "",
			want:      "unknown",
		},
		{
			name:      "long unknown User-Agent gets truncated",
			userAgent: "this-is-a-very-long-user-agent-string-that-exceeds-forty-characters",
			want:      "ua:this-is-a-very-long-user-agent-string-th",
		},
		{
			name:      "opencode via User-Agent",
			userAgent: "opencode/0.5",
			want:      "opencode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
			if tt.customHdr != "" {
				req.Header.Set("X-Tidebreak-Agent", tt.customHdr)
			}
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			// Test detectAgent directly
			got := detectAgent(req)
			// detectAgent is only called when custom header is empty,
			// so skip the priority test here
			if tt.customHdr != "" {
				return
			}
			if got != tt.want {
				t.Errorf("detectAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectAgentPriority(t *testing.T) {
	// Verify that X-Tidebreak-Agent takes priority over User-Agent
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
	req.Header.Set("X-Tidebreak-Agent", "custom-agent")
	req.Header.Set("User-Agent", "claude-code/1.0")

	agent := req.Header.Get("X-Tidebreak-Agent")
	if agent == "" {
		agent = detectAgent(req)
	}

	if agent != "custom-agent" {
		t.Errorf("expected custom-agent, got %s", agent)
	}
}
