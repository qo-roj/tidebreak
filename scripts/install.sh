#!/usr/bin/env bash
set -euo pipefail

# Tidebreak — Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/qo-roj/tidebreak/main/scripts/install.sh | bash
#   TIDEBREAK_MIRROR=https://mirror.local bash install.sh       # Fleet mirror
#   bash install.sh --local /path/to/tidebreak-binary          # Local binary (dev)
#   bash install.sh --build                                     # Build from source (needs Go)
#   bash install.sh --system                                    # /usr/local/bin (needs sudo)
#   bash install.sh --user                                      # ~/.local/bin (default fallback)
#   bash install.sh --add-to-path                               # Also write PATH entry to ~/.profile
#
# Default scope is "auto": install to /usr/local/bin when it is writable
# (or passwordless sudo exists), otherwise ~/.local/bin.

VERSION="${VERSION:-latest}"
CONFIG_DIR="${HOME}/.config/tidebreak"
DATA_DIR="${HOME}/.local/share/tidebreak"
LOCAL_BINARY=""
DO_BUILD=false
INSTALL_SCOPE="auto"   # auto | user | system
ADD_TO_PATH=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)    LOCAL_BINARY="$2"; shift 2 ;;
        --build)   DO_BUILD=true; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        --user)    INSTALL_SCOPE="user"; shift ;;
        --system)  INSTALL_SCOPE="system"; shift ;;
        --add-to-path) ADD_TO_PATH=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Resolve install directory.
#
# System paths work out of the box on every distro; ~/.local/bin needs a PATH
# entry many users don't have (Linux Mint, stock Debian, etc.). Scope "auto"
# picks a system path when we can write to one without an interactive sudo
# prompt breaking `curl | bash`; otherwise falls back to ~/.local/bin.
SYSTEM_DIR="/usr/local/bin"
install_dir_user="${HOME}/.local/bin"

dir_writable() {
    [[ -d "$1" && -w "$1" ]]
}

can_sudo() {
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

if [[ "$INSTALL_SCOPE" == "system" ]]; then
    if dir_writable "$SYSTEM_DIR" || can_sudo; then
        INSTALL_DIR="$SYSTEM_DIR"
    else
        echo "✗ Cannot install system-wide: $SYSTEM_DIR is not writable and sudo needs a password."
        echo "  Run with --user, or rerun interactively so sudo can prompt."
        exit 1
    fi
elif [[ "$INSTALL_SCOPE" == "user" ]]; then
    INSTALL_DIR="$install_dir_user"
else
    if dir_writable "$SYSTEM_DIR"; then
        INSTALL_DIR="$SYSTEM_DIR"
    else
        INSTALL_DIR="$install_dir_user"
    fi
fi

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

# Place a staged binary into $INSTALL_DIR, using sudo when the dir is not
# directly writable (passwordless sudo only; a password prompt inside
# `curl | bash` breaks stdin).
install_binary() {
    local staged="$1"
    if dir_writable "$INSTALL_DIR"; then
        cp "$staged" "${INSTALL_DIR}/tidebreak"
        chmod +x "${INSTALL_DIR}/tidebreak"
    elif can_sudo; then
        sudo -n install -m 0755 "$staged" "${INSTALL_DIR}/tidebreak"
    else
        echo "✗ Cannot write to ${INSTALL_DIR} and no passwordless sudo available."
        exit 1
    fi
    echo "✓ Binary installed to ${INSTALL_DIR}/tidebreak"
}

# Create directories (user install dir; system dirs are expected to exist)
mkdir -p "$install_dir_user" "$CONFIG_DIR" "$DATA_DIR"

# Install method 1: local binary (development)
if [[ -n "$LOCAL_BINARY" ]]; then
    echo "Installing from local binary: $LOCAL_BINARY"
    install_binary "$LOCAL_BINARY"

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
    STAGED="$(mktemp)"
    (cd "$TMP_SRC" && go build -o "$STAGED" ./cmd/tidebreak)
    rm -rf "$TMP_SRC"
    install_binary "$STAGED"
    rm -f "$STAGED"
    echo "✓ Built and installed"

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

    STAGED="$(mktemp)"
    if curl -fsSL "$DOWNLOAD_URL" -o "$STAGED" 2>/dev/null; then
        install_binary "$STAGED"
        rm -f "$STAGED"
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
path_in_path() {
    [[ ":$PATH:" == *":${1}:"* ]]
}

if ! path_in_path "$INSTALL_DIR"; then
    if [[ "$ADD_TO_PATH" == true ]]; then
        PROFILE_FILE="${HOME}/.profile"
        touch "$PROFILE_FILE"
        if ! grep -qs "TIDEBREAK_PATH" "$PROFILE_FILE"; then
            {
                echo ""
                echo "# TIDEBREAK_PATH — added by tidebreak installer"
                echo "export PATH=\"${INSTALL_DIR}:\$PATH\""
            } >> "$PROFILE_FILE"
            echo "✓ Added ${INSTALL_DIR} to PATH via ${PROFILE_FILE}"
            echo "  Start a new shell (or: source ${PROFILE_FILE}) to pick it up."
        else
            echo "✓ ${PROFILE_FILE} already contains the PATH entry"
        fi
    else
        echo ""
        echo "⚠ ${INSTALL_DIR} is not in your PATH."
        echo "  Fix it permanently by re-running with --add-to-path, or add this to your shell profile:"
        echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
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