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
			Name:        "private_key",
			Regex:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			Replacement: "[KEY_BLOCKED_%d]",
			Enabled:     true,
		},

		// JWT tokens — specific structure, run before generic patterns
		{
			Name:        "jwt",
			Regex:       regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
			Replacement: "[JWT_REDACTED_%d]",
			Enabled:     true,
		},

		// API keys — specific prefixes, run before phone/credit card
		{
			Name:        "api_key_github",
			Regex:       regexp.MustCompile(`\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "api_key_openai",
			Regex:       regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "api_key_anthropic",
			Regex:       regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "api_key_aws",
			Regex:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "api_key_google",
			Regex:       regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "api_key_stripe",
			Regex:       regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b`),
			Replacement: "[TOKEN_REDACTED_%d]",
			Enabled:     true,
		},

		// Email — specific structure with @
		{
			Name:        "email",
			Regex:       regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			Replacement: "[EMAIL_REDACTED_%d]",
			Enabled:     true,
		},

		// Network — IPv4, IPv6, MAC
		{
			Name:        "ipv4",
			Regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`),
			Replacement: "[IP_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "ipv6",
			Regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			Replacement: "[IP_REDACTED_%d]",
			Enabled:     true,
		},
		{
			Name:        "mac_address",
			Regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`),
			Replacement: "[MAC_REDACTED_%d]",
			Enabled:     true,
		},

		// Credit card — 16 digits in groups of 4
		{
			Name:        "credit_card",
			Regex:       regexp.MustCompile(`\b(?:\d{4}[\s-]?){3}\d{4}\b`),
			Replacement: "[CC_REDACTED_%d]",
			Enabled:     true,
		},

		// Phone — least specific, run last to avoid consuming other digit patterns.
		// Requires +prefix or at least 10 digits to reduce false positives.
		{
			Name:        "phone",
			Regex:       regexp.MustCompile(`\+?\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,5}[\s.\-]?\d{3,5}`),
			Replacement: "[PHONE_REDACTED_%d]",
			Enabled:     true,
		},
	}
}

// ExtendedPatterns returns additional patterns used by server and paranoid presets.
func ExtendedPatterns() []*Pattern {
	extra := []*Pattern{
		// Private IPv4 ranges
		{
			Name:        "ipv4_private",
			Regex:       regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
			Replacement: "[IP_REDACTED_%d]",
			Enabled:     false,
		},
		// Internal hostnames
		{
			Name:        "hostname_internal",
			Regex:       regexp.MustCompile(`\b[a-z0-9][a-z0-9\-]*\.(?:local|internal|lan)\b`),
			Replacement: "[HOST_REDACTED_%d]",
			Enabled:     false,
		},
		// Database connection strings
		{
			Name:        "database_connection",
			Regex:       regexp.MustCompile(`\b(?:postgres|mysql|mongodb|redis)://[^\s]+`),
			Replacement: "[DBURL_REDACTED_%d]",
			Enabled:     false,
		},
		// US Social Security Numbers
		{
			Name:        "ssn_us",
			Regex:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Replacement: "[SSN_REDACTED_%d]",
			Enabled:     false,
		},
		// IBAN
		{
			Name:        "iban",
			Regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`),
			Replacement: "[IBAN_REDACTED_%d]",
			Enabled:     false,
		},
		// Passport numbers (simplified)
		{
			Name:        "passport",
			Regex:       regexp.MustCompile(`\b[A-Z]\d{8}\b`),
			Replacement: "[PASSPORT_REDACTED_%d]",
			Enabled:     false,
		},
	}
	return append(DefaultPatterns(), extra...)
}