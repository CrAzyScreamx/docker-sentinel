---
name: docker-sentinel
description: >
  Scan Docker images for security issues — secrets, malicious binaries,
  dangerous scripts, risky URLs, persistence mechanisms, capability abuse,
  and more. Use when the user asks to scan, inspect, audit, or check the
  security of a Docker image. Triggers on phrases like "scan nginx:latest",
  "check this image for vulnerabilities", "is redis:7 safe to use",
  "audit my Docker image".
triggers:
  - /docker-sentinel
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
CLI tool. The CLI runs all analysis tools locally (no API key required for
`--raw-findings`) and writes one flat text file per analysis category. You then
coordinate four specialised subagents — profiler, scorer, rater, and shower —
to analyse those files and render the final security report.

## Step 1 — Identify the image

Extract the Docker image name from the user's message (e.g. `nginx:latest`,
`redis:7`, `myrepo/myapp:1.2.3`). If no image name is provided, ask before
proceeding.

Derive the **file prefix** used to name every output file:

1. Split the full image string on `:` → `IMAGE_PART` (everything before)
   and `VERSION` (everything after; default `latest` if no tag present).
2. Replace any `/` in `IMAGE_PART` with `-`.
3. `FILE_PREFIX = "<IMAGE_PART>-<VERSION>"`

Examples:

| User input           | FILE_PREFIX              |
|----------------------|--------------------------|
| `nginx:latest`       | `nginx-latest`           |
| `redis:7`            | `redis-7`                |
| `myrepo/myapp:1.2.3` | `myrepo-myapp-1.2.3`     |
| `ubuntu`             | `ubuntu-latest`          |

## Step 2 — Create a temp directory

Use the Bash tool:

```bash
TMPDIR=$(mktemp -d)
echo $TMPDIR
```

Record the printed path as `TMPDIR` for use in all subsequent steps.

## Step 3 — Run raw findings

Use the Bash tool:

```bash
docker-sentinel <IMAGE_NAME> --raw-findings -o "$TMPDIR"
```

If the command exits with a non-zero code, report the error to the user and
stop — do not attempt to continue with partial output.

On success this step produces exactly four files in `$TMPDIR`:

- `metadata-<FILE_PREFIX>.txt`
- `static-<FILE_PREFIX>.txt`
- `dynamic-<FILE_PREFIX>.txt`
- `url-verdicts-<FILE_PREFIX>.txt`

## Step 4 — Profile and score in parallel

Launch **both** agents in the same response (two Agent tool calls side by side).
They read different files so they have zero dependencies on each other.

**Agent A — Profiler** (`subagent_type: "docker-sentinel-profiler"`):

```
input_file:  <TMPDIR>/metadata-<FILE_PREFIX>.txt
output_file: <TMPDIR>/profiler-result.txt
```

**Agent B — Scorer** (`subagent_type: "docker-sentinel-scorer"`):

```
static_file:       <TMPDIR>/static-<FILE_PREFIX>.txt
dynamic_file:      <TMPDIR>/dynamic-<FILE_PREFIX>.txt
url_verdicts_file: <TMPDIR>/url-verdicts-<FILE_PREFIX>.txt
output_file:       <TMPDIR>/scorer-<FILE_PREFIX>.txt
```

Wait for **both** agents to complete before proceeding.

## Step 5 — Rate the image

The rater depends on the scorer's output from Step 4.

Launch the rater (`subagent_type: "docker-sentinel-rater"`):

```
input_file:  <TMPDIR>/scorer-<FILE_PREFIX>.txt
output_file: <TMPDIR>/rater-result.txt
```

Wait for the agent to complete before proceeding.

## Step 6 — Render the report

The shower depends on the rater and scorer output files from Steps 4–5.

Launch the shower (`subagent_type: "docker-sentinel-shower"`):

```
scorer_file: <TMPDIR>/scorer-<FILE_PREFIX>.txt
rater_file:  <TMPDIR>/rater-result.txt
```

The shower renders the final report directly to the console. Do not add any
further output after launching this agent.
