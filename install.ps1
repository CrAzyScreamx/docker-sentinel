# install.ps1 — docker-sentinel installer for Windows
#
# Downloads the latest binary from GitHub Releases, optionally stores
# DOCKER_SENTINEL_AI_KEY, and installs Claude Code skills on request.
#
# Usage (run from PowerShell as a regular user):
#   irm https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/install.ps1 | iex
#   # or download and run:
#   .\install.ps1

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo       = "CrAzyScreamx/docker-sentinel"
$BinaryName = "docker-sentinel.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "docker-sentinel"
$EnvFile    = Join-Path $env:USERPROFILE ".docker-sentinel.env"
# Skills dir is resolved at runtime via Get-ClaudeDir (see below).

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Info  { param($Msg) Write-Host "✓ $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "! $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "✗ $Msg" -ForegroundColor Red; exit 1 }

function Get-ClaudeDir {
    # Respect an explicit override set by the user or CI environment.
    if ($env:CLAUDE_CONFIG_DIR) { return $env:CLAUDE_CONFIG_DIR }
    # Standard location used by Claude Code on Windows.
    return Join-Path $env:USERPROFILE ".claude"
}

# ---------------------------------------------------------------------------
# Step 1 — Detect architecture
# ---------------------------------------------------------------------------

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Err "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

# ---------------------------------------------------------------------------
# Step 2 — Fetch latest release tag from GitHub API
# ---------------------------------------------------------------------------

function Get-LatestTag {
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $Response = Invoke-WebRequest -Uri $ApiUrl -UseBasicParsing -ErrorAction Stop
        $Json = $Response.Content | ConvertFrom-Json
        $Tag = $Json.tag_name
        if (-not $Tag) { Write-Err "Could not determine latest release tag." }
        return $Tag
    } catch {
        Write-Err "Failed to query GitHub API: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 3 — Download and install the binary
# ---------------------------------------------------------------------------

function Install-Binary {
    param([string]$Arch, [string]$Tag)

    $DownloadUrl = "https://github.com/$Repo/releases/download/$Tag/docker-sentinel-windows-$Arch.exe"
    $TmpPath     = Join-Path $env:TEMP "docker-sentinel-tmp.exe"

    Write-Info "Downloading docker-sentinel $Tag for windows-$Arch..."
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpPath -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Err "Download failed: $_"
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    $BinaryPath = Join-Path $InstallDir $BinaryName
    Move-Item -Path $TmpPath -Destination $BinaryPath -Force

    # Add install dir to user PATH if not already present
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($CurrentPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$CurrentPath;$InstallDir",
            "User"
        )
        Write-Info "Added $InstallDir to user PATH."
        Write-Warn "Restart your terminal for PATH changes to take effect."
    }

    Write-Info "Binary installed: $BinaryPath"
}

# ---------------------------------------------------------------------------
# Step 4 — Verify Docker daemon
# ---------------------------------------------------------------------------

function Test-Docker {
    if (Get-Command "docker" -ErrorAction SilentlyContinue) {
        $DockerInfo = docker info 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Docker daemon is not running. Start Docker Desktop before scanning images."
        } else {
            Write-Info "Docker daemon is reachable."
        }
    } else {
        Write-Warn "Docker is not installed. Install Docker Desktop to use docker-sentinel."
    }
}

# ---------------------------------------------------------------------------
# Step 5 — Prompt for API key (optional)
# ---------------------------------------------------------------------------

function Prompt-ApiKey {
    Write-Host ""
    $ApiKey = Read-Host "DOCKER_SENTINEL_AI_KEY (Enter to skip — not needed with Claude Code skills)"

    if ($ApiKey) {
        "DOCKER_SENTINEL_AI_KEY=$ApiKey" | Set-Content -Path $EnvFile -Encoding UTF8
        Write-Info "API key saved to $EnvFile"
    } else {
        Write-Info "Skipped — no API key stored."
    }
}

# ---------------------------------------------------------------------------
# Step 6 — Prompt to install Claude Code skills
# ---------------------------------------------------------------------------

function Install-Skills {
    param([string]$Tag)

    Write-Host ""
    $Answer = Read-Host "Install Claude Code skills? [y/N]"

    if ($Answer -match "^[yY]") {
        $ClaudeDir   = Get-ClaudeDir
        $SkillsDir   = Join-Path $ClaudeDir "plugins\cache\local\docker-sentinel\1.0.0"
        $PluginsJson = Join-Path $ClaudeDir "plugins\installed_plugins.json"
        $ZipUrl      = "https://github.com/$Repo/releases/download/$Tag/docker-sentinel-skills.zip"
        $TmpZip      = Join-Path $env:TEMP "docker-sentinel-skills.zip"

        Write-Info "Downloading skills package..."
        try {
            Invoke-WebRequest -Uri $ZipUrl -OutFile $TmpZip -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Err "Skills download failed: $_"
        }

        if (-not (Test-Path $SkillsDir)) {
            New-Item -ItemType Directory -Path $SkillsDir -Force | Out-Null
        }

        Expand-Archive -Path $TmpZip -DestinationPath $SkillsDir -Force
        Remove-Item $TmpZip -Force

        # Register the plugin in installed_plugins.json so Claude Code
        # discovers it the same way marketplace-installed plugins are found.
        Write-Info "Registering plugin in installed_plugins.json..."
        $Now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        if (Test-Path $PluginsJson) {
            $Data = Get-Content $PluginsJson -Raw | ConvertFrom-Json
        } else {
            $Data = [PSCustomObject]@{ version = 2; plugins = [PSCustomObject]@{} }
        }

        $Entry = @([PSCustomObject]@{
            scope        = "user"
            installPath  = $SkillsDir
            version      = "1.0.0"
            installedAt  = $Now
            lastUpdated  = $Now
            gitCommitSha = ""
        })

        # Add-Member handles both new and existing keys.
        if ($Data.plugins.PSObject.Properties["docker-sentinel@local"]) {
            $Data.plugins."docker-sentinel@local" = $Entry
        } else {
            $Data.plugins | Add-Member -NotePropertyName "docker-sentinel@local" -NotePropertyValue $Entry
        }

        $Data | ConvertTo-Json -Depth 10 | Set-Content $PluginsJson -Encoding UTF8

        Write-Info "Plugin registered as docker-sentinel@local"
        Write-Info "Skills installed to $SkillsDir"
        Write-Info "Restart Claude Code to activate the docker-sentinel skill."
    } else {
        Write-Info "Skipped Claude Code skills installation."
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "docker-sentinel installer" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

$Arch = Get-Arch
$Tag  = Get-LatestTag

Write-Info "Architecture: $Arch"
Write-Info "Release:      $Tag"

Install-Binary -Arch $Arch -Tag $Tag
Test-Docker
Prompt-ApiKey
Install-Skills -Tag $Tag

Write-Host ""
Write-Info "Installation complete. Run: docker-sentinel --help"
Write-Host ""
