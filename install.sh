#!/bin/sh
# AgentShield Universal Installer
# Usage: curl -fsSL https://aiconnai.github.io/agentshield/install.sh | sh
#
# Environment variables:
#   VERSION      - Specify target version (e.g. "v1.0.0"). Defaults to latest.
#   INSTALL_DIR  - Target installation directory. Defaults to ~/.local/bin or /usr/local/bin.

set -e

REPO="aiconnai/agentshield"
DEFAULT_VERSION="v1.0.0"

# Text styling
if [ -t 1 ]; then
  BOLD="\033[1m"
  GREEN="\033[32m"
  BLUE="\033[34m"
  YELLOW="\033[33m"
  RED="\033[31m"
  RESET="\033[0m"
else
  BOLD=""
  GREEN=""
  BLUE=""
  YELLOW=""
  RED=""
  RESET=""
fi

log_info() {
  printf "${BLUE}[INFO]${RESET} %s\n" "$1"
}

log_success() {
  printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}[WARN]${RESET} %s\n" "$1"
}

log_error() {
  printf "${RED}[ERROR]${RESET} %s\n" "$1" >&2
}

# Detect OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64)
        TARGET="aarch64-apple-darwin"
        ;;
      x86_64)
        TARGET="x86_64-apple-darwin"
        ;;
      *)
        log_error "Unsupported macOS architecture: $ARCH"
        exit 1
        ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
      aarch64|arm64)
        TARGET="aarch64-unknown-linux-gnu"
        ;;
      *)
        log_error "Unsupported Linux architecture: $ARCH"
        exit 1
        ;;
    esac
    ;;
  *)
    log_error "Unsupported operating system: $OS (Windows users can download prebuilt zip from GitHub Releases)"
    exit 1
    ;;
esac

# Resolve Version
if [ -z "$VERSION" ]; then
  log_info "Fetching latest AgentShield release version..."
  if command -v curl >/dev/null 2>&1; then
    LATEST_JSON=$(curl -fsSL --connect-timeout 5 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)
    VERSION=$(printf "%s" "$LATEST_JSON" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  fi
  if [ -z "$VERSION" ]; then
    VERSION="$DEFAULT_VERSION"
    log_warn "Could not fetch latest release from GitHub API; falling back to $VERSION"
  fi
fi

# Ensure version has 'v' prefix
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac

# Determine installation directory
if [ -n "$INSTALL_DIR" ]; then
  DEST_DIR="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
  DEST_DIR="/usr/local/bin"
else
  DEST_DIR="$HOME/.local/bin"
fi

mkdir -p "$DEST_DIR"

ARCHIVE_NAME="agentshield-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

printf "\n${BOLD}🛡️  AgentShield Installer${RESET} (${VERSION})\n"
log_info "Detected platform: ${BOLD}${OS} ${ARCH}${RESET} (${TARGET})"
log_info "Destination:       ${BOLD}${DEST_DIR}/agentshield${RESET}"
log_info "Downloading from:  ${DOWNLOAD_URL}"

# Temporary working directory
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'agentshield-install')
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Download binary archive
if command -v curl >/dev/null 2>&1; then
  curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$TMP_DIR/$ARCHIVE_NAME"
elif command -v wget >/dev/null 2>&1; then
  wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP_DIR/$ARCHIVE_NAME"
else
  log_error "Neither curl nor wget found in PATH."
  exit 1
fi

# Extract and install
log_info "Extracting ${ARCHIVE_NAME}..."
tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/agentshield" ]; then
  log_error "Failed to locate extracted binary in archive."
  exit 1
fi

chmod +x "$TMP_DIR/agentshield"
mv "$TMP_DIR/agentshield" "$DEST_DIR/agentshield"

# Verify installation
if command -v "$DEST_DIR/agentshield" >/dev/null 2>&1; then
  INSTALLED_VER=$("$DEST_DIR/agentshield" --version 2>/dev/null || echo "$VERSION")
  log_success "Successfully installed ${BOLD}${INSTALLED_VER}${RESET} to ${DEST_DIR}/agentshield"
else
  log_success "Binary installed to ${DEST_DIR}/agentshield"
fi

# Check PATH
case ":$PATH:" in
  *":$DEST_DIR:"*) ;;
  *)
    log_warn "${DEST_DIR} is not in your current PATH."
    printf "Add it to your shell configuration:\n"
    printf "  ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n\n" "$DEST_DIR"
    ;;
esac

printf "\n${BOLD}🚀 Quick Start:${RESET}\n"
printf "  Scan your workspace:    ${GREEN}agentshield scan .${RESET}\n"
printf "  Interactive explorer:   ${GREEN}agentshield scan . --explain${RESET}\n"
printf "  1-Click security fix:   ${GREEN}agentshield fix --all${RESET}\n\n"
