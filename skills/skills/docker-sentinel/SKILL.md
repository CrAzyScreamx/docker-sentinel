---
name: docker-sentinel
description: >
  Scan Docker images for security issues — secrets, malicious binaries,
  dangerous scripts, risky URLs, persistence mechanisms, capability abuse,
  and more. Use when the user asks to scan, inspect, audit, or check the
  security of a Docker image. Triggers on phrases like "scan nginx:latest",
  "check this image for vulnerabilities", "is redis:7 safe to use",
  "audit my Docker image".
metadata:
  priority: 50
  promptSignals:
    phrases:
      - "scan"
      - "inspect image"
      - "audit"
      - "docker image"
      - "vulnerabilities"
      - "is safe"
      - "check image"
      - "security scan"
---

# docker-sentinel Skill

You are orchestrating a Docker image security scan using the `docker-sentinel`
CLI tool. The CLI runs all analysis tools locally (no API key needed for
`--raw-findings`). You then act as the AI layer: profiling, scoring, and
rating the image using your own model access.

## Step 1 — Identify the image

Extract the Docker image name from the user's message (e.g. `nginx:latest`,
`redis:7`, `myrepo/myapp:1.2.3`). If no image name was provided, ask the user
before proceeding.

## Step 2 — Create a temp directory

Use the Bash tool to create a temporary output directory:

```bash
TMPDIR=$(mktemp -d)
echo $TMPDIR
```

## Step 3 — Run raw findings

Use the Bash tool to run the CLI in raw-findings mode:

```bash
docker-sentinel <IMAGE_NAME> --raw-findings -o "$TMPDIR"
```

If the command exits with a non-zero code, report the error message to the
user and stop. Do not attempt to continue with partial output.

## Step 4 — Read the output JSON

Use the Bash tool to find and read the output file:

```bash
cat "$TMPDIR"/sentinel_raw_*.json
```

Parse the JSON into memory. It has the structure:
```
{
  "schema_version": "...",
  "image_name": "...",
  "static": { "trufflehog": {...}, "layer": {...}, "scripts": {...},
              "urls": {...}, "env": {...}, "manifests": {...},
              "persistence": {...}, "history": {...}, "capabilities": {...} },
  "dynamic": { "container_id": "...", "checks": [...] }
}
```

## Step 5 — Profile the image (haiku)

Use the Agent tool with `model: "haiku"` and the instructions in
`agents/profiler.md`. Pass the full raw findings JSON as context.

Capture the returned JSON object as `image_profile`.

## Step 6 — Score the findings (sonnet)

Use the Agent tool with `model: "sonnet"` and the instructions in
`agents/scorer.md`. Pass:
- `image_profile` from Step 5
- The `static` and `dynamic` sections of the raw findings JSON

Capture the returned JSON as `scoring_report`:
```json
{
  "scored_findings": [
    {"source": "...", "description": "...", "score": 7, "rationale": "..."}
  ],
  "adjustment_note": null
}
```

## Step 7 — Rate the image (sonnet)

Use the Agent tool with `model: "sonnet"` and the instructions in
`agents/rater.md`. Pass `scoring_report` from Step 6.

Capture the returned JSON as `rater_report`:
```json
{"final_rating": "HIGH", "summary": "..."}
```

## Step 8 — Render the final report

Display the report in this order:

### Header
Print the image name and final rating. Use colour cues in your prose:
- CRITICAL / HIGH → describe as high-risk / dangerous
- MEDIUM → describe as moderate-risk
- LOW / INFO → describe as low-risk / clean

### Summary
Print the one-sentence `summary` from `rater_report`.

### Scored Findings Table
Render a markdown table with columns: **Source | Score | Description**

Sort rows by `score` descending. Include all findings from `scored_findings`.
If `scored_findings` is empty, print: *No significant findings.*

### URL Verdicts Table
Only render this section if the `static.urls.url_findings` list contains
entries — and only show entries that were classified "Not Safe" by the
Spamhaus DNSBL stage (check `static.urls.url_findings[*].flags` for
`"spamhaus_zen"` or similar). Columns: **URL | Verdict | Reason**.

If no unsafe URLs exist, omit this section entirely.

### Trust Note
If `scoring_report.adjustment_note` is not null, display it as a
blockquote at the end of the report.
