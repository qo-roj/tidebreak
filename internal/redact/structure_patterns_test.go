package redact

import (
	"regexp"
	"strings"
	"testing"
)

// newTestRedactor builds a Redactor with only the named patterns enabled.
func newTestRedactor(names ...string) *Redactor {
	r := New().WithPatterns(AllPatterns())
	for _, p := range r.patterns {
		p.Enabled = false
	}
	for _, p := range r.patterns {
		for _, n := range names {
			if p.Name == n {
				p.Enabled = true
			}
		}
	}
	return r
}

func TestSyslogHostnameRedacts(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	in := "Sep  3 17:54:01 himbeerkuchen systemd[1]: Started Daily apt download.\n"
	out, s := r.Redact(in)
	if !strings.Contains(out, "[TB:HOST:1] systemd[1]") {
		t.Errorf("hostname not redacted: %q", out)
	}
	if !strings.Contains(out, "Sep  3 17:54:01") {
		t.Errorf("timestamp was altered: %q", out)
	}
	if s["syslog_hostname"] != 1 {
		t.Errorf("summary = %v, want syslog_hostname: 1", s)
	}
}

func TestSyslogHostnameISOTimestamp(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, _ := r.Redact("2026-09-03T17:54:03.123456+02:00 rotten-berry sshd[4242]: Failed password\n")
	if !strings.Contains(out, "[TB:HOST:1] sshd[4242]") {
		t.Errorf("ISO-format hostname not redacted: %q", out)
	}
}

func TestSyslogHostnameDedup(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, s := r.Redact("Sep  3 17:54:01 host-a kernel: x\nSep  3 17:54:02 host-a kernel: y\nSep  3 17:54:03 host-b kernel: z\n")
	if got := strings.Count(out, "[TB:HOST:1]"); got != 2 {
		t.Errorf("same hostname should reuse token, got %d HOST:1 in %q", got, out)
	}
	if !strings.Contains(out, "[TB:HOST:2]") || strings.Count(out, "[TB:HOST:2]") != 1 {
		t.Errorf("second hostname should get HOST:2, got %q", out)
	}
	if s["syslog_hostname"] != 3 {
		t.Errorf("summary = %v, want 3", s)
	}
}

func TestSyslogHostnameIgnoresMidLineTimestamps(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, s := r.Redact("The meeting notes say 17:54:01 himbeerkuchen and nothing else.")
	if out != "The meeting notes say 17:54:01 himbeerkuchen and nothing else." {
		t.Errorf("mid-line timestamp falsely matched: %q", out)
	}
	if len(s) != 0 {
		t.Errorf("unexpected redactions: %v", s)
	}
}

func TestPasswdUsernameRedacts(t *testing.T) {
	r := newTestRedactor("passwd_username")
	in := "root:x:0:0:root:/root:/bin/bash\nsid:x:1000:1000:Sid Crab:/home/sid:/usr/bin/fish\n"
	out, s := r.Redact(in)
	if !strings.HasPrefix(out, "[TB:USER:1]:x:0:0:") {
		t.Errorf("first username not redacted: %q", out)
	}
	if !strings.Contains(out, "[TB:USER:2]:x:1000:1000:Sid Crab:/home/sid") {
		t.Errorf("second username not redacted: %q", out)
	}
	if s["passwd_username"] != 2 {
		t.Errorf("summary = %v, want 2", s)
	}
}

func TestPasswdUsernameIgnoresColonPairs(t *testing.T) {
	r := newTestRedactor("passwd_username")
	cases := []string{
		"user:password is a common example phrase",
		"username: admin",
		"localhost: 127.0.0.1",
		`"json_key": {"nested": 1}`,
		"# comment: explaining something",
		"time: 12:30 and time: 09:15",
	}
	for _, c := range cases {
		out, s := r.Redact(c)
		if out != c {
			t.Errorf("false positive on %q → %q", c, out)
		}
		if len(s) != 0 {
			t.Errorf("false-positive summary on %q: %v", c, s)
		}
	}
}

// Group-span patterns must keep the anchoring context (timestamp) while the
// redacted value round-trips through Restore.
func TestGroupPatternRestoreRoundTrip(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	in := "Sep  3 17:54:01 himbeerkuchen systemd[1]: Started\n"
	red, _ := r.Redact(in)
	restored := r.Restore(red)
	if restored != in {
		t.Errorf("round-trip mismatch:\nred:  %q\nwant: %q", restored, in)
	}
}

// Group indices that don't exist in a match must leave content untouched.
func TestGroupSpanMissingGroup(t *testing.T) {
	r := New()
	r.WithPatterns([]*Pattern{{
		Name:     "bogus_group",
		Regex:    regexp.MustCompile(`^(\w+) world`),
		Category: "TEST",
		Group:    5, // no such group
	}})
	out, s := r.Redact("hello world")
	if out != "hello world" {
		t.Errorf("out-of-range group redacted anyway: %q", out)
	}
	if len(s) != 0 {
		t.Errorf("unexpected summary: %v", s)
	}
}
