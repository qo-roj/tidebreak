#!/usr/bin/env bash
set -euo pipefail

# Tidebreak — Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/qo-roj/tidebreak/main/scripts/install.sh | bash
#   TIDEBREAK_MIRROR=https://mirror.local bash install.sh       # Fleet mirror
#   bash install.sh --local /path/to/tidebreak-binary          # Local binary (dev)
#   bash install.sh --build                                     # Build from source (needs Go)

VERSION="${VERSION:-latest}"
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/tidebreak"
DATA_DIR="${HOME}/.local/share/tidebreak"
LOCAL_BINARY=""
DO_BUILD=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)    LOCAL_BINARY="$2"; shift 2 ;;
        --build)   DO_BUILD=true; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Mirror URL (can be overridden for fleet/private hosting)
DOWNLOAD_BASE="${TIDEBREAK_MIRROR:-https://github.com/qo-roj/tidebreak/releases}"

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

# Install method 1: local binary (development)
if [[ -n "$LOCAL_BINARY" ]]; then
    echo "Installing from local binary: $LOCAL_BINARY"
    cp "$LOCAL_BINARY" "${INSTALL_DIR}/tidebreak"
    chmod +x "${INSTALL_DIR}/tidebreak"
    echo "✓ Binary installed to ${INSTALL_DIR}/tidebreak"

# Install method 2: build from source
elif [[ "$DO_BUILD" == true ]]; then
    if ! command -v go &>/dev/null; then
        echo "✗ Go is not installed. Install Go or use --local / a release binary."
        exit 1
    fi
    echo "Building from source..."
    TMP_SRC="$(mktemp -d)"
    git clone https://github.com/qo-roj/tidebreak "$TMP_SRC" 2>/dev/null || {
        echo "✗ Could not clone repo. If the GitHub repo doesn't exist yet,"
        echo "  use --local /path/to/binary or build manually."
        exit 1
    }
    cd "$TMP_SRC" && go build -o "${INSTALL_DIR}/tidebreak" ./cmd/tidebreak
    chmod +x "${INSTALL_DIR}/tidebreak"
    rm -rf "$TMP_SRC"
    echo "✓ Built and installed to ${INSTALL_DIR}/tidebreak"

# Install method 3: download from mirror/GitHub releases
else
    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="${DOWNLOAD_BASE}/latest/download/tidebreak-${PLATFORM}-${ARCH}"
    else
        DOWNLOAD_URL="${DOWNLOAD_BASE}/download/${VERSION}/tidebreak-${PLATFORM}-${ARCH}"
    fi

    echo "Downloading Tidebreak ${VERSION}..."
    echo "  Source: ${DOWNLOAD_URL}"
    echo ""

    if curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/tidebreak" 2>/dev/null; then
        chmod +x "${INSTALL_DIR}/tidebreak"
        echo "✓ Binary installed to ${INSTALL_DIR}/tidebreak"
    else
        echo "✗ Failed to download from ${DOWNLOAD_URL}"
        echo ""
        echo "The GitHub repo may not exist yet. Alternative install methods:"
        echo ""
        echo "  1. Build from source (requires Go):"
        echo "     bash install.sh --build"
        echo ""
        echo "  2. Install a local binary (development):"
        echo "     bash install.sh --local /path/to/tidebreak"
        echo ""
        echo "  3. Use a fleet mirror:"
        echo "     TIDEBREAK_MIRROR=https://your-mirror bash install.sh"
        exit 1
    fi
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
# Docs: https://github.com/qo-roj/tidebreak/blob/main/docs/rules-guide.md

[gateway]
port = 8842
log_level = info
# tls = false  # set true for paranoid mode (local TLS)

[cloud]
# Cloud providers — keys read from env vars by default
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
# Choose: desktop, server, paranoid, or training-data
# desktop         — Omarchy / personal workstation (default)
# server          — Production server with user data
# paranoid        — Maximum redaction
# training-data   — Redact all PII for fine-tuning datasets
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
echo "Docs: https://github.com/qo-roj/tidebreak"