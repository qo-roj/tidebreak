package redact

import (
	"strings"
	"testing"
)

// github_pat_ fine-grained tokens (GitHub's newer format, 2023+) were NOT
// covered by the api_key_github pattern, which only matched classic prefixes
// (ghp_/gho_/ghs_/ghu_/ghr_). Regression test from the tidebreak text E2E run.
func TestRedactGitHubFineGrainedToken(t *testing.T) {
	r := New()
	defer r.Clear()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "fine-grained classic-shape",
			content: "token github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234567890 leaked",
		},
		{
			name:    "fine-grained embedded in sentence",
			content: "config uses github_pat_11XyZ0abcdefghijklmnopqrstuvwxyz1234567890 as auth",
		},
		{
			name:    "fine-grained minimum length (22 body chars)",
			content: "token github_pat_11ABCDEFG0abcdefghijkl here",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redacted, summary := r.Redact(tc.content)

			if strings.Contains(redacted, "github_pat_") {
				t.Error("redacted content still contains github_pat_ prefix")
			}
			if !strings.Contains(redacted, "[TB:TOKEN:") {
				t.Error("redacted content missing [TB:TOKEN: token")
			}
			if summary["api_key_github"] != 1 {
				t.Errorf("expected 1 api_key_github redaction, got %d", summary["api_key_github"])
			}
		})
	}
}

// The github_pat_ regex must not swallow surrounding punctuation or trigger
// on the bare prefix without a token body.
func TestGitHubFineGrainedNoFalsePositives(t *testing.T) {
	r := New()
	defer r.Clear()

	tests := []struct {
		name    string
		content string
	}{
		{"bare prefix", "docs say github_pat_ is the format"},
		{"too short", "short github_pat_11ABCDEFG0abcdefgh"},
		{"21 body chars rejected", "short github_pat_11ABCDEFG0abcdefghi"},
		{"prefix word alone", "we use github_pat tokens now"},
		{"version string", "app version 1.22.2 on 10.1.1.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redacted, _ := r.Redact(tc.content)
			if strings.Contains(redacted, "[TB:TOKEN:") {
				t.Errorf("false positive: %q produced %q", tc.content, redacted)
			}
		})
	}
}
