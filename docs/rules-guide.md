# Tidebreak — Rules Guide

## How Rules Work

Tidebreak uses a layered rule system to classify content before it reaches any LLM.

### Classification Tiers

Every piece of content in an agent request is assigned exactly one tier:

| Tier | Cloud sees it? | Ollama sees it? | Agent sees result? |
|---|---|---|---|
| **public** | ✅ as-is | — | ✅ |
| **redacted** | ✅ with patterns stripped | — | ✅ |
| **local-only** | ❌ never | ✅ raw data + produces scrubbed summary | ✅ sees summary |
| **blocked** | ❌ never | ❌ never | ❌ error returned to agent |

### Rule Resolution Order

Rules are evaluated in this order (later rules override earlier ones):

1. **Built-in defaults** (`rules/defaults.conf`)
2. **Preset rules** (e.g. `rules/presets/server.conf`)
3. **User config** (`~/.config/tidebreak/tidebreak.conf`)
4. **Project-local config** (`.tidebreak.conf` in project root)
5. **CLI flags** (highest priority, temporary)

When two rules match the same path, the more specific one wins. Within the same
specificity, the later rule wins.

## Rule Syntax

### Path Rules

Paths use glob patterns (doublestar — `**` matches recursively).

```ini
[block]
~/.ssh/id_*
/etc/shadow
**/.env

[local-only]
~/.config/himalaya/*
/var/log/**
**/credentials*

[redact]
~/.zsh_history
/var/log/nginx/access.log
```

### Command-Output Rules

Command rules classify the **output** of commands that agents run (via tool use).
These are separate from path rules because they match command strings, not file paths.

```ini
[cmd]
# Redact command output (strip IPs, emails, etc.)
journalctl -u *           = redact
docker logs *              = redact
ps aux                    = redact
ss -tlnp                  = redact

# Route command output to local Ollama only (never to cloud)
mysql *                   = local-only
psql *                    = local-only
redis-cli *               = local-only

# Block — agent should never run this
cat /etc/shadow           = block
```

How it works: when an agent runs a command (e.g. `journalctl -u nginx`), the
tool result contains the command and its output. Tidebreak matches the command
against `[cmd]` rules and classifies the output accordingly. Path rules do NOT
apply to command output — they only apply to file content.

**Special prefixes:**
- `~/` — expands to current user's home directory
- `~USER/` — expands to a specific user's home
- `/` — absolute path from filesystem root
- `**/` — matches any number of directories
- `*` — matches anything within a single path segment

### Pattern Rules

Redaction patterns are regex-based. Each pattern has:
- A name (for config and audit log)
- A regex that matches sensitive data
- A replacement template (usually `[NAME_REDACTED_N]`)

Built-in patterns:

| Name | Matches | Example | Replaced With |
|---|---|---|---|
| `ipv4` | IPv4 addresses | `203.0.113.42` | `[IP_REDACTED_1]` |
| `ipv6` | IPv6 addresses | `2001:db8::1` | `[IP_REDACTED_1]` |
| `email` | Email addresses | `user@example.com` | `[EMAIL_REDACTED_1]` |
| `phone` | Phone numbers | `+49 170 1234567` | `[PHONE_REDACTED_1]` |
| `api_key_github` | GitHub tokens | `ghp_xxxx...` | `[TOKEN_REDACTED_1]` |
| `api_key_openai` | OpenAI keys | `sk-proj-xxxx...` | `[TOKEN_REDACTED_1]` |
| `api_key_anthropic` | Anthropic keys | `sk-ant-xxxx...` | `[TOKEN_REDACTED_1]` |
| `api_key_aws` | AWS keys | `AKIAxxxx...` | `[TOKEN_REDACTED_1]` |
| `jwt` | JWT tokens | `eyJxxxx...` | `[JWT_REDACTED_1]` |
| `private_key` | PEM private keys | `-----BEGIN ... PRIVATE KEY-----` | `[KEY_BLOCKED]` |
| `mac_address` | MAC addresses | `00:1B:44:11:3A:B7` | `[MAC_REDACTED_1]` |
| `credit_card` | Credit card numbers | `4111 1111 1111 1111` | `[CC_REDACTED_1]` |

### Custom Patterns

```ini
[redaction.custom]
# Custom patterns use named regex groups
internal_host = '(?P<value>[a-z0-9-]+\.internal\.company\.com)'
internal_host_replacement = '[INTERNAL_HOST_REDACTED_N]'

# Or via CLI
# tidebreak config add-pattern internal_host '[a-z0-9-]+\.internal\.company\.com' '[INTERNAL_HOST_REDACTED_N]'
```

## Presets

Presets are named collections of rules for common scenarios:

```bash
# List available presets
tidebreak presets
# desktop    — Omarchy / personal workstation
# server     — Production server with user data
# paranoid   — Maximum redaction, minimal cloud exposure

# Use a preset
tidebreak config set preset server

# Combine presets (later ones extend earlier ones)
tidebreak config set preset desktop,server
```

## Common Patterns

### "My agent needs to read this file but it has secrets in it"

```ini
[redact]
/path/to/file.conf
```

The file goes to the cloud with secrets stripped. The agent can see the structure
but not the actual credentials.

### "My agent should never touch this file at all"

```ini
[block]
/path/to/sensitive/file
```

The agent receives an error. It can't read this file through any model.

### "This file has user data — I want Ollama to summarize it"

```ini
[local-only]
/path/to/user-data.json
```

Ollama reads the raw file, produces a de-identified summary ("JSON file with 847
users, fields: id, email, phone, created_at"), and the summary goes to the cloud.

### "This whole directory is sensitive"

```ini
[local-only]
/var/lib/myapp/data/**
```

Everything under `/var/lib/myapp/data/` is routed to Ollama only.

### "I want to whitelist a specific file from a blocked directory"

```ini
[block]
~/.ssh/**

[redact]
~/.ssh/config
```

The SSH config is redacted (hostnames, IPs stripped) but readable. Private keys
remain blocked.

### "Per-agent rules — different agents get different access"

```ini
[agent:claude]
[redact]
~/projects/**

[agent:codex]
[block]
~/projects/company-internal/**
```

Claude can read your projects (redacted). Codex can't access internal company
projects at all.

## Testing Your Rules

```bash
# Test how a file would be classified
tidebreak classify ~/.ssh/id_ed25519
# → tier: blocked
# → reason: matches block rule ~/.ssh/id_*

tidebreak classify /etc/nginx/nginx.conf
# → tier: redacted
# → reason: matches redact rule /etc/nginx/**
# → redactions: 2 IPs found, 0 emails, 1 token

tidebreak classify /var/log/nginx/access.log
# → tier: redacted
# → redactions: 847 IPs, 23 emails, 0 tokens

# Test what the cloud model would actually receive
tidebreak dry-run --file /etc/nginx/nginx.conf
# Shows the redacted output that would be sent to the cloud
```