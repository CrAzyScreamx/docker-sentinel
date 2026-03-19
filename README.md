# docker-sentinel

An AI-powered Docker image security inspector. docker-sentinel runs a 7-step pipeline that combines static analysis, dynamic runtime probing, and four LLM agents to score and rate the security posture of any Docker image. Results are written to a timestamped JSON report and displayed as a colour-coded Rich terminal summary.

---

## How it works

docker-sentinel executes a 7-step pipeline for every image:

| Step | What runs | Description |
|------|-----------|-------------|
| **1 - Image Profiler** | LLM agent | Collects Docker Hub metadata (official status, publisher, pull count) and daemon metadata (labels, env vars, ports, architecture, size), then structures it into a validated profile. |
| **2 - Static Analysis** | 9 direct Python tools | Runs all nine static analyzers (see below) with zero LLM overhead. |
| **3 - URL Validator** | LLM agent *(conditional)* | Classifies any flagged URLs as Safe or Not Safe. Skipped if no URLs were extracted. |
| **4 - Dynamic Analysis** | Direct Python | Starts an isolated container (no network, all capabilities dropped, read-only FS, 256 MB RAM) and runs 7 runtime probes: processes, SUID files, environment variables, crontab, listening services, sudoers, and active systemd units. |
| **5 - Filter** | Direct Python | Discards empty tool results so the Scorer only sees actionable findings. |
| **6 - Scorer** | LLM agent | Assigns a 1–10 risk score to every finding using per-source rules, with a –2 trust discount for official or verified-publisher images. |
| **7 - Rater** | LLM agent | Maps the highest score to a rating band and writes a one-sentence plain-English summary. |

### Static analysis tools

| Tool | What it detects |
|------|----------------|
| **TruffleHog** | Secrets and credentials embedded in image layers |
| **Layer Analyzer** | SUID/SGID bits, hidden files, known malicious binaries, executables in `/tmp` or `/dev/shm` |
| **Script Analyzer** | Reverse shells, pipe-to-shell patterns, obfuscation, cryptominers, persistence (cron, LD_PRELOAD, rc.local), history hiding |
| **URL Extractor** | Suspicious HTTP/HTTPS URLs and bare IP addresses across layers, env vars, and labels |
| **Env Analyzer** | Credential-like environment variables (passwords, tokens, API keys, JWTs, AWS keys, PEM headers) |
| **Manifest Analyzer** | Typosquatted packages, known-malicious dependencies, unpinned versions, vulnerable version ranges |
| **Persistence Analyzer** | Cron jobs, init scripts, systemd units, LD_PRELOAD hooks, SSH `authorized_keys`, shell profile backdoors |
| **History Analyzer** | Suspicious build commands in layer history (pipe-to-shell, base64 decode, chmod +x, remote adds) |
| **Capability Analyzer** | Root user, privileged ports, `DOCKER_SOCK` labels, `setcap` calls in scripts |

### Risk ratings

| Rating | Score threshold | Terminal colour |
|--------|----------------|----------------|
| CRITICAL | ≥ 9 | Bold red |
| HIGH | ≥ 7 | Red |
| MEDIUM | ≥ 5 | Yellow |
| LOW | ≥ 3 | Cyan |
| INFO | < 3 or no findings | Green |

---

## Prerequisites

- **Docker Engine** must be running locally — all image operations and the TruffleHog scanner use the Docker daemon.
- **Anthropic API key** — set `ANTHROPIC_API_KEY` in your environment or in a `.env` file next to the binary.

---

## Installation

### Windows (PowerShell)

Paste this into any PowerShell terminal — no admin rights required. The binary is installed to `%LOCALAPPDATA%\docker-sentinel` and added to your user PATH automatically.

```powershell
irm https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.ps1 | iex
```

Open a new terminal after installation and run:

```powershell
docker-sentinel --help
```

### Linux (amd64)

Paste this into any terminal. The binary is installed to `/usr/local/lib/docker-sentinel` and symlinked into `/usr/local/bin`. `sudo` is requested automatically if needed.

```bash
curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.sh | bash
```

Both scripts always install the **latest published release**. To install a specific version, download the asset directly from the [Releases page](https://github.com/CrAzyScreamx/docker-sentinel/releases) and extract it to a directory of your choice.

---

## Usage

```
docker-sentinel IMAGE_NAME [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output-dir DIR` | `.` | Directory where the JSON report is written |
| `-m, --model STRING` | `anthropic/claude-sonnet-4-6` | LiteLLM model string override (also `DOCKER_SENTINEL_MODEL` env var) |
| `--json-only` | off | Skip the Rich terminal output; write the JSON report only |
| `--detailed` | off | Show the score rationale for each finding in the terminal output |
| `-h, --help` | | Show help |

### Examples

```bash
# Scan the official nginx image
docker-sentinel nginx:latest

# Scan and write the report to a reports/ directory
docker-sentinel nginx:latest -o reports/

# Scan with detailed score rationale shown
docker-sentinel myorg/myapp:v2.3.1 --detailed

# Scan using a different model
docker-sentinel myorg/myapp:v2.3.1 --model anthropic/claude-opus-4-6

# CI mode — JSON report only, no terminal output
docker-sentinel myorg/myapp:v2.3.1 --json-only -o /tmp/reports/
```

---

## Configuration

All settings can be provided as environment variables or in a `.env` file placed next to the binary (frozen) or in the project root (source install).

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | *(required)* | Anthropic API key for the LLM agents |
| `DOCKER_SENTINEL_MODEL` | `anthropic/claude-sonnet-4-6` | LiteLLM model string used by all four agents |
---

## Output

Every scan produces a timestamped JSON report (`sentinel_<image>_<timestamp>.json`) and a Rich terminal summary. The JSON structure is:

```json
{
  "schema_version": "2.0.0",
  "generated_at": "2026-03-19T00:27:43Z",
  "image_name": "nginx:latest",
  "profile": { "is_official": true, "publisher": "Docker Official Images", ... },
  "url_verdicts": [],
  "scored_findings": [
    { "source": "layer", "description": "...", "score": 3, "rationale": "..." }
  ],
  "final_rating": "LOW",
  "summary": "One security concern was identified..."
}
```

---

## Development install

```bash
git clone https://github.com/CrAzyScreamx/docker-sentinel.git
cd docker-sentinel
pip install -e .[dev]
docker-sentinel nginx:latest
```

### Build a local binary (Windows)

```powershell
.\scripts\build-local.ps1
```

The binary is written to `dist\docker-sentinel\docker-sentinel.exe`.
