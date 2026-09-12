package main

import (
	"strings"
	"testing"
)

// splitTextArgs receives the POSITIONAL arguments left after flag parsing
// (Go's parser stops at the first positional, so a flag typed after the text
// arrives here un-parsed). It must flag that case so the caller can fail
// loudly instead of silently redacting `--out clean.txt` into the output.
func TestSplitTextArgsDetectsTrailingFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantText    []string
		wantFlagArg string
	}{
		{
			name:        "flag after text is caught",
			args:        []string{"server 10.0.0.5 down", "--out", "clean.txt"},
			wantText:    []string{"server 10.0.0.5 down"},
			wantFlagArg: "--out",
		},
		{
			name:        "text only passes through",
			args:        []string{"server 10.0.0.5 down"},
			wantText:    []string{"server 10.0.0.5 down"},
			wantFlagArg: "",
		},
		{
			name:     "text containing a short flag word is not flagged",
			args:     []string{"diff -u output was weird"},
			wantText: []string{"diff -u output", "was", "weird"},
		},
		{
			name:     "bare double dash separator is not flagged",
			args:     []string{"before", "--", "after"},
			wantText: []string{"before", "--", "after"},
		},
		{
			name:     "multiple text words stay whole",
			args:     []string{"the", "server", "at", "10.0.0.5", "is", "down"},
			wantText: []string{"the", "server", "at", "10.0.0.5", "is", "down"},
		},
		{
			name:        "flag at start of positionals is caught",
			args:        []string{"--summary", "some text"},
			wantText:    []string{},
			wantFlagArg: "--summary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text, flagArg := splitTextArgs(tc.args)
			if strings.Join(text, " ") != strings.Join(tc.wantText, " ") {
				t.Errorf("text = %q, want %q", text, tc.wantText)
			}
			if flagArg != tc.wantFlagArg {
				t.Errorf("flagArg = %q, want %q", flagArg, tc.wantFlagArg)
			}
		})
	}
}
