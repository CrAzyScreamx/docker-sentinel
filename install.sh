#!/usr/bin/env bash
# install.sh — docker-sentinel installer for Linux and macOS
#
# Downloads the latest binary from GitHub Releases, optionally stores
# DOCKER_SENTINEL_AI_KEY, and installs Claude Code skills on request.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/install.sh | bash
#   # or clone and run:
#   bash install.sh

set -euo pipefail

REPO="CrAzyScreamx/docker-sentinel"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="docker-sentinel"
ENV_FILE="$HOME/.docker-sentinel.env"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

find_claude_dir() {
    # Respect an explicit override set by the user or CI environment.
    if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        echo "$CLAUDE_CONFIG_DIR"
        return
    fi
    # Standard location used by Claude Code on Linux and macOS.
    echo "${HOME}/.claude"
}

info()  { printf '\033[0;32m✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m!\033[0m %s\n' "$*"; }
error() { printf '\033[0;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 \
        || error "Required command not found: $1. Please install it and retry."
}

# ---------------------------------------------------------------------------
# Step 1 — Detect OS and architecture
# ---------------------------------------------------------------------------

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux)  os="linux"  ;;
        Darwin) os="darwin" ;;
        *)      error "Unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64 | amd64) arch="amd64" ;;
        arm64  | aarch64) arch="arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}-${arch}"
}

# ---------------------------------------------------------------------------
# Step 2 — Fetch latest release tag from GitHub API
# ---------------------------------------------------------------------------

fetch_latest_tag() {
    require_cmd curl

    local tag
    tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
          | grep '"tag_name"' \
          | head -1 \
          | sed 's/.*"tag_name": *"\(.*\)".*/\1/')

    [ -n "$tag" ] || error "Could not determine latest release tag."
    echo "$tag"
}

# ---------------------------------------------------------------------------
# Step 3 — Download and install the binary
# ---------------------------------------------------------------------------

install_binary() {
    local platform="$1"
    local tag="$2"
    local url="https://github.com/${REPO}/releases/download/${tag}/${BINARY_NAME}-${platform}"
    local tmp_bin

    info "Downloading ${BINARY_NAME} ${tag} for ${platform}..."
    tmp_bin=$(mktemp)
    curl -fsSL "$url" -o "$tmp_bin" \
        || error "Download failed. Check your internet connection and that the release exists."

    chmod +x "$tmp_bin"

    info "Installing to ${INSTALL_DIR}/${BINARY_NAME} (may require sudo)..."
    sudo mv "$tmp_bin" "${INSTALL_DIR}/${BINARY_NAME}"

    info "Binary installed: $(command -v ${BINARY_NAME})"
}

# ---------------------------------------------------------------------------
# Step 4 — Verify Docker daemon
# ---------------------------------------------------------------------------

check_docker() {
    if command -v docker >/dev/null 2>&1; then
        if ! docker info >/dev/null 2>&1; then
            warn "Docker daemon is not running. Start Docker before scanning images."
        else
            info "Docker daemon is reachable."
        fi
    else
        warn "Docker is not installed. Install Docker to use docker-sentinel."
    fi
}

# ---------------------------------------------------------------------------
# Step 5 — Prompt for API key (optional)
# ---------------------------------------------------------------------------

prompt_api_key() {
    printf '\nDOCKER_SENTINEL_AI_KEY (Enter to skip — not needed with Claude Code skills): '
    read -r api_key

    if [ -n "$api_key" ]; then
        printf 'DOCKER_SENTINEL_AI_KEY=%s\n' "$api_key" > "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        info "API key saved to ${ENV_FILE}"
    else
        info "Skipped — no API key stored."
    fi
}

# ---------------------------------------------------------------------------
# Step 6 — Prompt to install Claude Code skills
# ---------------------------------------------------------------------------

install_skills() {
    local tag="$1"
    local zip_url="https://github.com/${REPO}/releases/download/${tag}/docker-sentinel-skills.zip"
    local claude_dir skills_dir plugins_json tmp_zip now

    claude_dir="$(find_claude_dir)"
    skills_dir="${claude_dir}/plugins/cache/local/docker-sentinel/1.0.0"
    plugins_json="${claude_dir}/plugins/installed_plugins.json"

    printf '\nInstall Claude Code skills? [y/N] '
    read -r answer

    case "$answer" in
        [yY]|[yY][eE][sS])
            require_cmd unzip

            info "Downloading skills package..."
            tmp_zip=$(mktemp --suffix=.zip)
            curl -fsSL "$zip_url" -o "$tmp_zip" \
                || error "Skills download failed."

            mkdir -p "$skills_dir"
            unzip -qo "$tmp_zip" -d "$skills_dir"
            rm -f "$tmp_zip"

            info "Registering plugin in installed_plugins.json..."
            now=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
            python3 - <<PYEOF
import json, sys

path = "${plugins_json}"
try:
    with open(path) as f:
        data = json.load(f)
except FileNotFoundError:
    data = {"version": 2, "plugins": {}}

data.setdefault("plugins", {})["docker-sentinel@local"] = [{
    "scope": "user",
    "installPath": "${skills_dir}",
    "version": "1.0.0",
    "installedAt": "${now}",
    "lastUpdated": "${now}",
    "gitCommitSha": ""
}]

with open(path, "w") as f:
    json.dump(data, f, indent=2)
PYEOF

            info "Plugin registered as docker-sentinel@local"
            info "Skills installed to ${skills_dir}"
            info "Restart Claude Code to activate the docker-sentinel skill."
            ;;
        *)
            info "Skipped Claude Code skills installation."
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo "docker-sentinel installer"
    echo "========================="

    local platform tag
    platform=$(detect_platform)
    tag=$(fetch_latest_tag)

    info "Platform: ${platform}"
    info "Release:  ${tag}"

    install_binary "$platform" "$tag"
    check_docker
    prompt_api_key
    install_skills "$tag"

    echo ""
    info "Installation complete. Run: docker-sentinel --help"
    echo ""
}

main "$@"
