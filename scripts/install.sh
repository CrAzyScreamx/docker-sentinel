#!/usr/bin/env bash
# Install docker-sentinel on Linux (amd64 only)
# Usage: curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.sh | bash

set -euo pipefail

REPO="CrAzyScreamx/docker-sentinel"
BINARY_NAME="docker-sentinel-linux-amd64"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="${INSTALL_DIR}/docker-sentinel"

# Architecture guard
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    echo "ERROR: Only x86_64 supported. Detected: $ARCH" >&2; exit 1
fi

echo "Fetching latest release..."
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

if command -v curl &>/dev/null; then
    RELEASE_JSON=$(curl -fsSL "$API_URL")
elif command -v wget &>/dev/null; then
    RELEASE_JSON=$(wget -qO- "$API_URL")
else
    echo "ERROR: curl or wget required" >&2; exit 1
fi

DOWNLOAD_URL=$(echo "$RELEASE_JSON" \
    | grep -o '"browser_download_url": *"[^"]*'"${BINARY_NAME}"'"' \
    | grep -o 'https://[^"]*')

[[ -z "$DOWNLOAD_URL" ]] && { echo "ERROR: Asset not found in release" >&2; exit 1; }

TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT

echo "Downloading: $DOWNLOAD_URL"
if command -v curl &>/dev/null; then
    curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"
else
    wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
fi
chmod +x "$TMP_FILE"

if [[ -w "$INSTALL_DIR" ]]; then
    mv "$TMP_FILE" "$INSTALL_PATH"
else
    echo "Requires sudo to write to $INSTALL_DIR..."
    sudo mv "$TMP_FILE" "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"
fi

echo "Installed: $INSTALL_PATH"
docker-sentinel --help
