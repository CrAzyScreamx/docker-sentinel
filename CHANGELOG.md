# Changelog

All notable changes to docker-sentinel are documented here.

---

## [1.1.0] - 2026-03-22

### Changed

- **URL Validator replaced with deterministic pipeline** — the LLM-based URL classifier has been removed entirely and replaced with a three-stage deterministic pipeline:
  1. *Filter* — silently drops RFC 1918 (10/8, 172.16/12, 192.168/16), APIPA (169.254/16), loopback (127/8), shared space (100.64/10), and known public DNS servers (1.1.1.1, 8.8.8.8)
  2. *Resolve* — resolves domain names to IPv4 via Google DNS over HTTPS, independent of the system resolver
  3. *DNSBL* — checks each public IP against Spamhaus ZEN by querying Spamhaus GNS authoritative nameservers directly (bypasses Google/Cloudflare DNS which block DNSBL traffic by policy); operational return codes (127.255.255.252/254/255) are treated as inconclusive to avoid false positives on free-tier quota hits

- **Static analysis now runs in parallel** — all 9 static tools are dispatched concurrently via `asyncio.gather` + thread pool, reducing Step 2 wall-clock time from the sequential sum of all tools to approximately the slowest single tool

- **API key renamed** — `ANTHROPIC_API_KEY` is now `DOCKER_SENTINEL_AI_KEY`; a LiteLLM bridge in the runner forwards the value at runtime so no changes to LiteLLM internals are required

### Improved

- **Pipeline progress display** — each step now prints a structured progress line (`[N/7] ...`); Step 1 shows layer-by-layer pull output mirroring `docker pull` style; Step 2 prints each of the 9 tool names before dispatch; Step 5 prints each probe name immediately before it fires via an `on_probe` callback in the dynamic runner

---

## [1.0.0] - Initial release
