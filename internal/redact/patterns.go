package redact

import "regexp"

// DefaultPatterns returns the built-in redaction patterns enabled by default.
// These cover the patterns described in rules/defaults.conf.
//
// Order matters: more specific patterns (API keys, private keys, JWTs) run
// before less specific ones (phone, credit card) to prevent greedy matches
// from consuming substrings of longer token formats.
func DefaultPatterns() []*Pattern {
	return []*Pattern{
		// Private keys (PEM blocks) — most specific, must run before credit card etc.
		{
			Name:     "private_key",
			Regex:    regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			Category: "KEY",
			Enabled:  true,
		},

		// JWT tokens — specific structure, run before generic patterns
		{
			Name:     "jwt",
			Regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
			Category: "JWT",
			Enabled:  true,
		},

		// API keys — specific prefixes, run before phone/credit card
		{
			Name:     "api_key_github",
			Regex:    regexp.MustCompile(`\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_openai",
			Regex:    regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_anthropic",
			Regex:    regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_aws",
			Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_aws_secret",
			Regex:    regexp.MustCompile(`\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_google",
			Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_stripe",
			Regex:    regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_slack",
			Regex:    regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_gitlab",
			Regex:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "bearer_token",
			Regex:    regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},

		// Email — specific structure with @
		{
			Name:     "email",
			Regex:    regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			Category: "EMAIL",
			Enabled:  true,
		},

		// Network — IPv4, IPv6, MAC
		{
			Name:     "ipv4",
			Regex:    regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`),
			Category: "IP",
			Enabled:  true,
		},
		{
			Name:     "ipv6",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			Category: "IP",
			Enabled:  true,
		},
		{
			Name:     "mac_address",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`),
			Category: "MAC",
			Enabled:  true,
		},

		// Database connection strings
		{
			Name:     "database_connection",
			Regex:    regexp.MustCompile(`\b(?:postgres|mysql|mongodb|redis)://[^\s]+`),
			Category: "DBURL",
			Enabled:  true,
		},

		// Credit card — 13-16 digits with optional separators
		{
			Name:     "credit_card",
			Regex:    regexp.MustCompile(`\b(?:\d[ \-]?){13,16}\b`),
			Category: "CC",
			Enabled:  true,
		},

		// US Social Security Numbers
		{
			Name:     "ssn_us",
			Regex:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Category: "SSN",
			Enabled:  true,
		},

		// Phone — requires + prefix or 10+ digits to reduce false positives
		{
			Name:     "phone",
			Regex:    regexp.MustCompile(`\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,5}[\s.\-]?\d{3,5}`),
			Category: "PHONE",
			Enabled:  true,
		},
	}
}

// ExtendedPatterns returns additional patterns used by server and paranoid presets.
// These are more aggressive patterns that may have higher false-positive rates.
func ExtendedPatterns() []*Pattern {
	extra := []*Pattern{
		// Private IPv4 ranges
		{
			Name:     "ipv4_private",
			Regex:    regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
			Category: "IP",
			Enabled:  false,
		},
		// Internal hostnames
		{
			Name:     "hostname_internal",
			Regex:    regexp.MustCompile(`\b[a-z0-9][a-z0-9\-]*\.(?:local|internal|lan)\b`),
			Category: "HOST",
			Enabled:  false,
		},
		// IBAN
		{
			Name:     "iban",
			Regex:    regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`),
			Category: "IBAN",
			Enabled:  false,
		},
		// Passport numbers (simplified)
		{
			Name:     "passport",
			Regex:    regexp.MustCompile(`\b[A-Z]\d{8}\b`),
			Category: "PASSPORT",
			Enabled:  false,
		},
		// Generic high-entropy secrets (36+ char alphanumeric, likely a token)
		{
			Name:     "high_entropy_secret",
			Regex:    regexp.MustCompile(`\b[A-Za-z0-9_\-]{36,}\b`),
			Category: "SECRET",
			Enabled:  false,
		},
	}
	return append(DefaultPatterns(), extra...)
}