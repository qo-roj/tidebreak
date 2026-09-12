# Tidegate — Agent Setup Guide

## How Tidegate Intercepts Agent Traffic

Tidegate works as a local HTTPS proxy. Instead of sending requests directly to
`api.anthropic.com` or `api.openai.com`, agents send them to `localhost:8842`,
which forwards to the real API after redaction.

Most agents support API base URL configuration via environment variables. For
agents that don't, Tidegate can use `HTTP_PROXY` / `HTTPS_PROXY` env vars.

## Agent Configuration

### Claude Code

```bash
# Environment variable approach
export ANTHROPIC_BASE_URL=http://localhost:8842/anthropic

# Or in your shell profile (~/.config/omarchy/shell/exports.sh)
export ANTHROPIC_BASE_URL=http://localhost:8842/anthropic
```

Verify:
```bash
claude --version
# Run any task — check tidegate audit to see intercepted traffic
```

### OpenAI Codex

```bash
export OPENAI_BASE_URL=http://localhost:8842/openai

# Codex uses the OpenAI API format
codex
```

### OpenCode

```bash
# In OpenCode's config, override the provider base URL
export OPENCODE_API_BASE=http://localhost:8842/openai

opencode
```

### Hermes Agent

```yaml
# In ~/.hermes/config.yaml
providers:
  anthropic:
    base_url: http://localhost:8842/anthropic
    api_key: sk-ant-xxx
  
  openai:
    base_url: http://localhost:8842/openai
    api_key: sk-xxx
  
  ollama:
    base_url: http://localhost:11434
    # Ollama goes direct, not through Tidegate — it IS the local model
```

### Grok CLI (xAI)

```bash
export XAI_BASE_URL=http://localhost:8842/xai
```

### GitHub Copilot CLI

```bash
# Copilot uses GitHub's API, not a direct LLM API
# Use proxy env vars instead
export HTTPS_PROXY=http://localhost:8842
export HTTP_PROXY=http://localhost:8842
```

### Any OpenAI-compatible agent

```bash
export OPENAI_API_BASE=http://localhost:8842/openai
export OPENAI_BASE_URL=http://localhost:8842/openai
```

## Auto-Configuration

Tidegate can auto-configure supported agents:

```bash
# Detect and configure all installed agents
tidegate install --all

# Configure a specific agent
tidegate install --agent claude-code
tidegate install --agent codex
tidegate install --agent hermes

# Show what would be changed (dry run)
tidegate install --agent claude-code --dry-run
```

This modifies shell profiles / config files. Always review changes:
```bash
tidegate install --agent claude-code --diff
```

## Per-Project Rules

Create a `.tidegate.conf` in your project root to add project-specific rules:

```ini
# .tidegate.conf in ~/projects/myapp

[local-only]
# This project's database seeds contain PII
**/seeds/*.sql
**/fixtures/*.json

[redact]
# Logs from this project may contain customer data
**/logs/*.log

[block]
# Don't let agents read the production credentials file
**/prod.env
```

Project rules are merged with user rules and defaults. Project rules take
precedence for overlapping paths.

## Verifying It Works

```bash
# Start Tidegate
tidegate start

# Run any agent task
claude "show me my nginx config"

# Check the audit log
tidegate audit

# You should see:
# - The request was intercepted
# - Sensitive content was redacted
# - The right model was used (cloud for public, Ollama for local-only)
```

## Troubleshooting

### Agent isn't routing through Tidegate

Some agents hardcode their API endpoint and ignore env vars. Check:
```bash
# See if the agent is hitting Tidegate
tidegate audit --live

# If no traffic appears, the agent may be bypassing the proxy
# Try the HTTP_PROXY approach:
export HTTPS_PROXY=http://localhost:8842
```

### Ollama not available

If Ollama is down, `local-only` content is blocked entirely. The agent will see:
```
Error: content classified as local-only but Ollama is not available.
Start Ollama or reclassify this content.
```

### Redaction is too aggressive

```bash
# Check what was redacted
tidegate audit --detail <id>

# Temporarily disable a pattern
tidegate config set redaction.email false

# Or use a less restrictive preset
tidegate config set preset desktop
```

### Redaction is not aggressive enough

```bash
# Add a custom pattern
tidegate config add-pattern my_pattern 'MY_SECRET_\w+' '[CUSTOM_REDACTED]'

# Or switch to the paranoid preset
tidegate config set preset paranoid
```