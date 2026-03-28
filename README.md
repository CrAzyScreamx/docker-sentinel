# docker-sentinel

An AI-powered Docker image security inspector. docker-sentinel scans any Docker image for secrets, malicious binaries, dangerous scripts, risky URLs, persistence mechanisms, and capability abuse — then produces a rated security report (INFO → CRITICAL).

It ships in two modes: a **full pipeline** that uses your own Anthropic key to score and rate findings, and a **raw-findings mode** that runs without any API key and is designed to be driven by Claude Code's built-in skills.

---

## Modes at a glance

| Mode | Command | Requires API key? | Output |
|------|---------|:-----------------:|--------|
| Full pipeline | `docker-sentinel nginx:latest` | Yes | Rich terminal report + `sentinel_*.json` |
| Raw findings | `docker-sentinel nginx:latest --raw-findings` | No | 4 TOON `.txt` files |
| Claude Code skill | `"scan nginx:latest"` in Claude Code | No | Inline markdown report in Claude |

---

## Full pipeline — how it works

The full pipeline runs 7 steps for every image:

| Step | What runs | Description |
|------|-----------|-------------|
| **1 — Pull** | Docker daemon | Pulls the image if not already cached, showing per-layer progress. |
| **2 — Image Profiler** | LLM agent | Collects Docker Hub metadata (official status, publisher, pull count) and daemon metadata (labels, env vars, ports, architecture, size), then structures it into a validated profile. |
| **3 — Static Analysis** | 9 Python tools (parallel) | Runs all nine static analyzers concurrently with zero LLM overhead. |
| **4 — URL Validator** | Deterministic pipeline *(conditional)* | Three-stage: (1) filters RFC 1918, loopback, APIPA, and known DNS servers; (2) resolves domains to IPv4 via Google DNS over HTTPS; (3) checks each public IP against Spamhaus ZEN using GNS authoritative nameservers. Skipped if no URLs were extracted. |
| **5 — Dynamic Analysis** | Direct Python | Starts an isolated container (no network, all capabilities dropped, read-only FS, 256 MB RAM) and runs 7 runtime probes: processes, SUID files, env vars, crontab, listening services, sudoers, active systemd units. |
| **6 — Scorer** | LLM agent | Assigns a 1–10 risk score to every finding using per-source rules, with a –2 trust discount for official or verified-publisher images. |
| **7 — Rater** | LLM agent | Maps the highest score to a rating band and writes a one-sentence plain-English summary. |

### Static analysis tools

| Tool | What it detects |
|------|----------------|
| **TruffleHog** | Secrets and credentials embedded in image layers |
| **Layer Analyzer** | SUID/SGID bits, hidden files, known malicious binaries, executables in `/tmp` or `/dev/shm` |
| **Script Analyzer** | Reverse shells, pipe-to-shell patterns, obfuscation, cryptominers, persistence hooks, history hiding |
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

## Raw-findings mode — how it works

`--raw-findings` runs the same pull, static analysis, URL validation, and dynamic analysis steps but skips all LLM agents. No API key is required. Results are written as four TOON-encoded `.txt` files, one per analysis category:

| File | Contents |
|------|----------|
| `metadata-<image>-<version>.txt` | Docker Hub status and image metadata |
| `static-<image>-<version>.txt` | All 9 static tool results |
| `url-verdicts-<image>-<version>.txt` | Per-URL Safe / Not Safe verdicts |
| `dynamic-<image>-<version>.txt` | All 7 dynamic probe results |

TOON (Token-Oriented Object Notation) is a compact, token-efficient text format designed for passing structured data to LLMs. It is significantly smaller than JSON for the same data.

This mode exists so that the **Claude Code skill** can consume the output files using Claude Code's own model access — no user API key needed.

---

## Claude Code skill

Install the skill once (see [Installation](#installation)) and docker-sentinel becomes a native Claude Code command. Just describe what you want:

```
scan nginx:latest
check redis:7 for vulnerabilities
is myorg/myapp:v2.3.1 safe to deploy?
audit ubuntu:22.04
```

### How the skill works

The skill orchestrates four specialised subagents across six steps:

```
Step 1  Extract image name from your message
Step 2  Create a temp directory
Step 3  Run docker-sentinel --raw-findings  →  4 TOON files
Step 4  Profiler + Scorer run in parallel
          Profiler (haiku)  reads metadata-*.txt  → profile sentences
          Scorer  (sonnet)  reads static/dynamic/url-verdicts*.txt  → scored JSON
Step 5  Rater (sonnet)  reads scorer output  → rating + one-sentence summary
Step 6  Shower (haiku)  reads scorer + rater → renders markdown report inline
```

### Subagents

| Agent | Model | Role |
|-------|-------|------|
| **docker-sentinel-profiler** | Claude Haiku | Reads `metadata-*.txt` and writes 3 plain-English sentences: identity, popularity, and runtime profile. |
| **docker-sentinel-scorer** | Claude Sonnet | Reads the three findings files, scores every finding 1–10 using explicit per-source rules, and applies a –2 trust discount for official/verified images. |
| **docker-sentinel-rater** | Claude Sonnet | Maps the highest score to a rating band (INFO → CRITICAL) and writes a one-sentence plain-English summary. |
| **docker-sentinel-shower** | Claude Haiku | Reads the scorer and rater outputs and renders the final report as a markdown table directly in the Claude Code conversation. |

### Report format (Claude Code)

```
## Security Report — nginx:latest
🔴 HIGH RISK  |  Max score: 8/10

> The image contains a curl pipe-to-shell pattern in the entrypoint script
> that executes arbitrary remote code at container startup.

| Source  | Score | Description                        | Rationale                  |
|---------|-------|------------------------------------|----------------------------|
| scripts | 8     | pipe-to-shell in entrypoint.sh:12  | Executes remote code...    |
| layer   | 5     | hidden file at /etc/.hidden        | Hidden file outside skel   |

> ℹ️ Scores reduced by 2 — image is a Docker Official Image.
```

---

## Prerequisites

- **Docker Engine** must be running locally — all image operations and the TruffleHog scanner use the Docker daemon.
- **Anthropic API key** — required for the full pipeline only. Not needed for `--raw-findings` or the Claude Code skill.

---

## Authentication

`DOCKER_SENTINEL_AI_KEY` accepts two token formats:

| Format | Source | Example prefix |
|--------|--------|---------------|
| API key | [console.anthropic.com](https://console.anthropic.com) | `sk-ant-api03-...` |
| OAuth token | `~/.claude/.credentials.json` → `claudeAiOauth.accessToken` | `sk-ant-oat01-...` |

LiteLLM ≥ 1.63 handles both formats automatically — no code changes required.

---

## Installation

### Windows (PowerShell)

No admin rights required. The binary is installed to `%LOCALAPPDATA%\docker-sentinel` and added to your user PATH automatically.

```powershell
irm https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.ps1 | iex
```

The installer will ask whether you want to install the Claude Code skills after the binary is set up.

**Skills only** (if you already have the binary):

```powershell
irm https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.ps1 | iex -args --skills-only
```

### Linux / macOS (amd64)

The binary is installed to `/usr/local/lib/docker-sentinel` and symlinked into `/usr/local/bin`. `sudo` is requested automatically if needed.

```bash
curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.sh | bash
```

The installer will ask whether you want to install the Claude Code skills after the binary is set up.

**Skills only** (if you already have the binary):

```bash
curl -fsSL https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.sh | bash -s -- --skills-only
```

Both scripts always install the **latest published release**. To install a specific version, download the asset directly from the [Releases page](https://github.com/CrAzyScreamx/docker-sentinel/releases).

---

## Usage

```
docker-sentinel IMAGE_NAME [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output-dir DIR` | `.` | Directory where output files are written |
| `-m, --model STRING` | `anthropic/claude-sonnet-4-6` | LiteLLM model string override (also `DOCKER_SENTINEL_MODEL` env var) |
| `--raw-findings` | off | Run static + dynamic analysis only; write 4 TOON `.txt` files; no API key required |
| `--json-only` | off | Skip the Rich terminal output; write the JSON report only (full pipeline) |
| `--detailed` | off | Show the score rationale for each finding in the terminal output (full pipeline) |
| `-h, --help` | | Show help |

### Examples

```bash
# Scan the official nginx image (full pipeline)
docker-sentinel nginx:latest

# Scan and write the report to a reports/ directory
docker-sentinel nginx:latest -o reports/

# Scan with detailed score rationale shown
docker-sentinel myorg/myapp:v2.3.1 --detailed

# Scan using a different model
docker-sentinel myorg/myapp:v2.3.1 --model anthropic/claude-opus-4-6

# CI mode — JSON report only, no terminal output
docker-sentinel myorg/myapp:v2.3.1 --json-only -o /tmp/reports/

# Raw-findings mode — no API key required, produces 4 TOON files
docker-sentinel nginx:latest --raw-findings -o /tmp/
```

---

## Configuration

All settings can be provided as environment variables or in a `.env` file placed next to the binary (frozen install) or in the project root (source install).

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_SENTINEL_AI_KEY` | *(required for full pipeline)* | Anthropic API key or Claude Pro/Max OAuth token. Both formats accepted. |
| `DOCKER_SENTINEL_MODEL` | `anthropic/claude-sonnet-4-6` | LiteLLM model string used by all LLM agents |

---

## Output

### Full pipeline

Every full-pipeline scan writes a timestamped JSON report (`sentinel_<timestamp>.json`) and displays a Rich terminal summary. The JSON structure is:

```json
{
  "schema_version": "2.0.0",
  "generated_at": "2026-03-25T12:00:00Z",
  "image_name": "nginx:latest",
  "profile": { "is_official": true, "publisher": "Docker Official Images", "pull_count": 1000000000, "..." },
  "url_verdicts": [],
  "scored_findings": [
    { "source": "layer", "description": "...", "score": 3, "rationale": "..." }
  ],
  "final_rating": "LOW",
  "summary": "One minor finding was detected in the image layers."
}
```

### Raw-findings mode

Four TOON `.txt` files are written to the output directory, named after the image:

```
metadata-nginx-latest.txt
static-nginx-latest.txt
url-verdicts-nginx-latest.txt
dynamic-nginx-latest.txt
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
