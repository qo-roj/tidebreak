#!/usr/bin/env bash
set -euo pipefail

# Tidebreak — Installer
# Usage: curl -fsSL https://tidebreak.dev/install.sh | bash

VERSION="${1:-latest}"
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/tidebreak"
DATA_DIR="${HOME}/.local/share/tidebreak"

echo "🦞 Tidebreak — Redaction Gateway for AI Agents"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)  PLATFORM="linux" ;;
    darwin) PLATFORM="darwin" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Detected: ${PLATFORM}/${ARCH}"
echo ""

# Create directories
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"

# Download binary
if [[ "$VERSION" == "latest" ]]; then
    DOWNLOAD_URL="https://github.com/earl-sid/tidebreak/releases/latest/download/tidebreak-${PLATFORM}-${ARCH}"
else
    DOWNLOAD_URL="https://github.com/earl-sid/tidebreak/releases/download/${VERSION}/tidebreak-${PLATFORM}-${ARCH}"
fi

echo "Downloading Tidebreak ${VERSION}..."
if curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/tidebreak"; then
    chmod +x "${INSTALL_DIR}/tidebreak"
    echo "✓ Binary installed to ${INSTALL_DIR}/tidebreak"
else
    echo "✗ Failed to download. Check your connection or version."
    echo "  URL: ${DOWNLOAD_URL}"
    exit 1
fi

# Check if binary is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo ""
    echo "⚠ ${INSTALL_DIR} is not in your PATH."
    echo "  Add this to your shell profile:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# Create default config if it doesn't exist
if [[ ! -f "${CONFIG_DIR}/tidebreak.conf" ]]; then
    cat > "${CONFIG_DIR}/tidebreak.conf" << 'CONF'
# Tidebreak Configuration
# Docs: https://github.com/earl-sid/tidebreak/blob/main/docs/rules-guide.md

[gateway]
port = 8842
log_level = info

[cloud]
# Cloud providers — keys are read from env vars by default
# ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.
# Or set explicitly:
# anthropic = sk-ant-xxx
# openai = sk-xxx

[local]
# Local model for sensitive data processing
ollama_url = http://localhost:11434
ollama_model = llama3:8b

[redaction]
# All built-in patterns enabled by default
# See rules/defaults.conf for the full list

[preset]
# Choose: desktop, server, or paranoid
# desktop   — Omarchy / personal workstation (default)
# server    — Production server with user data
# paranoid  — Maximum redaction
desktop
CONF
    echo "✓ Default config created at ${CONFIG_DIR}/tidebreak.conf"
fi

# Check for Ollama
echo ""
if command -v ollama &>/dev/null; then
    echo "✓ Ollama detected"
else
    echo "⚠ Ollama not found. Local-only content will be blocked (not summarized)."
    echo "  Install Ollama: https://ollama.com"
    echo "  Or run: tidebreak setup-ollama"
fi

# Done
echo ""
echo "─────────────────────────────────────"
echo "  Tidebreak installed successfully"
echo "─────────────────────────────────────"
echo ""
echo "Next steps:"
echo ""
echo "  1. Start the gateway:"
echo "     tidebreak start"
echo ""
echo "  2. Configure your agents:"
echo "     tidebreak install --agent claude-code"
echo "     tidebreak install --agent codex"
echo "     tidebreak install --agent hermes"
echo ""
echo "  3. Verify it's working:"
echo "     tidebreak audit --live"
echo ""
echo "  4. Review your rules:"
echo "     tidebreak config edit"
echo ""
echo "Docs: https://github.com/earl-sid/tidebreak"