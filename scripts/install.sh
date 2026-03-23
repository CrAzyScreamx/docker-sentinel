#!/usr/bin/env bash
# Install docker-sentinel on Linux (amd64 only)
# Usage: curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.sh | bash

set -euo pipefail

REPO="CrAzyScreamx/docker-sentinel"
ASSET_NAME="docker-sentinel-linux-amd64.tar.gz"
INSTALL_DIR="/usr/local/lib/docker-sentinel"
SYMLINK_PATH="/usr/local/bin/docker-sentinel"

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
    | grep -o '"browser_download_url": *"[^"]*'"${ASSET_NAME}"'"' \
    | grep -o 'https://[^"]*')

[[ -z "$DOWNLOAD_URL" ]] && { echo "ERROR: Asset not found in release" >&2; exit 1; }

TMP_FILE=$(mktemp)
TMP_DIR=$(mktemp -d)
trap 'rm -f "$TMP_FILE"; rm -rf "$TMP_DIR"' EXIT

echo "Downloading: $DOWNLOAD_URL"
if command -v curl &>/dev/null; then
    curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"
else
    wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
fi

echo "Extracting..."
tar -xzf "$TMP_FILE" -C "$TMP_DIR"

NEEDS_SUDO=false
if [[ ! -w "$(dirname "$INSTALL_DIR")" ]]; then
    NEEDS_SUDO=true
    echo "Requires sudo to install to $INSTALL_DIR..."
fi

run_cmd() {
    if $NEEDS_SUDO; then sudo "$@"; else "$@"; fi
}

# Remove previous installation if present
if [[ -d "$INSTALL_DIR" ]]; then
    run_cmd rm -rf "$INSTALL_DIR"
fi
if [[ -L "$SYMLINK_PATH" || -f "$SYMLINK_PATH" ]]; then
    run_cmd rm -f "$SYMLINK_PATH"
fi

# Move extracted directory into place
run_cmd mv "$TMP_DIR/docker-sentinel" "$INSTALL_DIR"
run_cmd chmod +x "$INSTALL_DIR/docker-sentinel"

# Symlink executable into PATH
run_cmd ln -s "$INSTALL_DIR/docker-sentinel" "$SYMLINK_PATH"

echo "Installed: $SYMLINK_PATH -> $INSTALL_DIR/docker-sentinel"
docker-sentinel --help

# ---------------------------------------------------------------------------
# Claude Code skills (optional)
# ---------------------------------------------------------------------------

find_claude_dir() {
    if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then echo "$CLAUDE_CONFIG_DIR"; return; fi
    echo "${HOME}/.claude"
}

printf '\nInstall Claude Code skills? [y/N] '
read -r _skills_answer
case "$_skills_answer" in
    [yY]|[yY][eE][sS])
        RELEASE_TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
        SKILLS_ZIP_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/docker-sentinel-skills.zip"
        MARKETPLACE_DIR="${HOME}/.docker-sentinel/marketplace"
        SKILLS_TMP=$(mktemp --suffix=.zip)

        echo "Downloading skills package..."
        if command -v curl &>/dev/null; then
            curl -fsSL -o "$SKILLS_TMP" "$SKILLS_ZIP_URL"
        else
            wget -qO "$SKILLS_TMP" "$SKILLS_ZIP_URL"
        fi

        mkdir -p "$MARKETPLACE_DIR"
        unzip -qo "$SKILLS_TMP" -d "$MARKETPLACE_DIR"
        rm -f "$SKILLS_TMP"

        echo "Registering marketplace..."
        claude plugin marketplace add "$MARKETPLACE_DIR"

        echo "Installing plugin..."
        claude plugin install docker-sentinel@docker-sentinel

        echo "Skills installed. Restart Claude Code to activate the docker-sentinel skill."
        ;;
    *)
        echo "Skipped Claude Code skills installation."
        ;;
esac
