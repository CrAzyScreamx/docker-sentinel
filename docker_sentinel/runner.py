"""
runner.py — M13 pipeline orchestration for docker-sentinel.

Implements a 7-step pipeline where static and dynamic analysis tools
run directly in Python (zero LLM overhead) and only 4 lightweight LLM
agents are invoked. Exposes run_pipeline() as the single synchronous
entry point consumed by cli.py.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
import docker.errors

# Skip the remote model-cost-map fetch — avoids a noisy startup warning
# when the GitHub raw URL is unreachable (e.g. offline or firewalled).
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm

# LiteLLM emits TimeoutError tracebacks from its logging worker when the
# event loop closes. Raising the log level to CRITICAL silences these.
logging.getLogger("LiteLLM").setLevel(logging.CRITICAL)
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich.console import Console

from docker_sentinel.agents.image_profiler import build_image_profiler_agent
from docker_sentinel.agents.rater import build_rater_agent
from docker_sentinel.agents.scorer import build_scorer_agent
from docker_sentinel.tools.url_validator import validate_urls
from docker_sentinel.config import settings
from docker_sentinel.models import FinalReport, RaterReport, RawFindings, ScoringReport
from docker_sentinel.tools.capability_analyzer import analyze_capabilities
from docker_sentinel.tools.docker_hub import check_docker_hub_status
from docker_sentinel.tools.docker_meta import extract_image_metadata
from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis
from docker_sentinel.tools.env_analyzer import analyze_env_vars
from docker_sentinel.tools.history_analyzer import analyze_history
from docker_sentinel.tools.layer_analyzer import analyze_image_layers
from docker_sentinel.tools.manifest_analyzer import analyze_manifests
from docker_sentinel.tools.persistence_analyzer import analyze_persistence
from docker_sentinel.tools.script_analyzer import analyze_scripts
from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan
from docker_sentinel.tools.url_extractor import extract_urls


# Suppress LiteLLM's background logging worker. Without this, async
# callbacks time out when the event loop closes and emit noisy tracebacks.
litellm.callbacks = []
litellm.success_callback = []
litellm.failure_callback = []
litellm._async_success_callback = []
litellm._async_failure_callback = []

_APP_NAME = "docker_sentinel"
_USER_ID = "runner"

_console = Console()
_log = logging.getLogger("docker_sentinel.runner")

def _pull_image_if_needed(image_name: str) -> None:
    """
    Ensure the Docker image is present in the local daemon cache.

    Checks whether the image already exists locally. If it does, prints
    a single "cached" notice. If it is absent, streams the pull event
    log from the Docker daemon and prints one dim line per layer on
    completion (Pull complete / Already exists) plus the final status
    message, mirroring the output style of `docker pull`.

    Failures are logged as warnings rather than raised so that the
    pipeline can still attempt to proceed (individual tools perform
    their own pull fallback).
    """
    try:
        client = docker.from_env()
    except docker.errors.DockerException as exc:
        _log.warning("Docker unreachable during image pre-pull: %s", exc)
        return

    try:
        client.images.get(image_name)
        _console.print("[dim]  Image found in local cache.[/dim]")
        return
    except docker.errors.ImageNotFound:
        pass

    _console.print(
        f"[dim]  {image_name!r} not found locally — pulling...[/dim]"
    )
    try:
        seen_layers: set[str] = set()
        for event in client.api.pull(image_name, stream=True, decode=True):
            status = event.get("status", "")
            layer_id = event.get("id", "")
            if status in ("Pull complete", "Already exists") and layer_id:
                if layer_id not in seen_layers:
                    seen_layers.add(layer_id)
                    _console.print(
                        f"[dim]  {layer_id[:12]}: {status}[/dim]"
                    )
            elif status.startswith("Status:"):
                _console.print(f"[dim]  {status}[/dim]")
    except docker.errors.APIError as exc:
        _log.warning("Image pull failed: %s", exc)
        _console.print(
            f"[yellow]  Warning: pull failed — {exc}[/yellow]"
        )


# Maps each raw_static tool key to its findings list key.
# Used by _filter_empty_findings to skip tools with no results.
_STATIC_TOOL_FINDINGS_KEYS: dict[str, str] = {
    "trufflehog":   "secrets",
    "layer":        "layer_findings",
    "scripts":      "script_findings",
    "env":          "env_findings",
    "manifests":    "manifest_findings",
    "persistence":  "persistence_findings",
    "history":      "history_findings",
    "capabilities": "capability_findings",
}


async def _run_agent(
    agent,
    initial_state: dict,
    prompt: str,
) -> Any:
    """
    Run a single LLM agent in a fresh, fully isolated ADK session.

    Creates a new InMemorySessionService seeded with initial_state,
    drains the run_async event stream, reads the agent's output_key
    from session state, and returns the output validated against
    output_schema. Each call is isolated — no state leaks between
    agent invocations.
    """
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name=_APP_NAME,
        user_id=_USER_ID,
        state=initial_state,
    )
    runner = Runner(
        app_name=_APP_NAME,
        agent=agent,
        session_service=session_service,
    )
    async for event in runner.run_async(
        user_id=_USER_ID,
        session_id=session.id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text=prompt)],
        ),
    ):
        if hasattr(event, "error_message") and event.error_message:
            raise RuntimeError(
                f"Agent '{agent.name}' failed: {event.error_message}"
            )

    final_session = await session_service.get_session(
        app_name=_APP_NAME,
        user_id=_USER_ID,
        session_id=session.id,
    )
    if agent.output_key not in final_session.state:
        raise RuntimeError(
            f"Agent '{agent.name}' produced no output. "
            "Check that DOCKER_SENTINEL_AI_KEY is valid and the model string is correct "
            f"(current: {agent.model})."
        )
    raw = final_session.state[agent.output_key]
    return agent.output_schema.model_validate(raw)


def _filter_empty_findings(
    raw_static: dict,
    dynamic_result: dict,
    url_verdicts: list,
) -> dict:
    """
    Build a flat dict of non-empty findings for the Scorer agent.

    Skips static tool results whose findings list is empty to keep
    the Scorer's context focused on actionable items. URL verdicts
    are filtered to "Not Safe" entries only. Dynamic probes are
    filtered to checks that produced at least one anomaly.
    """
    filtered: dict = {}

    for tool_key, findings_key in _STATIC_TOOL_FINDINGS_KEYS.items():
        findings = raw_static.get(tool_key, {}).get(findings_key, [])
        if findings:
            filtered[tool_key] = findings

    unsafe_urls = [
        verdict for verdict in url_verdicts
        if isinstance(verdict, dict)
        and verdict.get("verdict") == "Not Safe"
    ]
    if unsafe_urls:
        filtered["url_verdicts"] = unsafe_urls

    active_probes = [
        check for check in dynamic_result.get("checks", [])
        if check.get("anomalies")
    ]
    if active_probes:
        filtered["dynamic"] = active_probes

    return filtered


async def _run_pipeline_async(
    image_name: str,
    model: str,
) -> FinalReport:
    """
    Execute the 7-step M13 pipeline and return a FinalReport.

    Step 1  — Pull image into the local daemon cache (with progress).
    Step 2  — Profile image via Hub API + LLM structuring.
    Step 3  — Run all 9 static analysis tools, one at a time.
    Step 4  — Validate flagged URLs (filter → Google DoH → Spamhaus ZEN).
    Step 5  — Run all 7 dynamic probes inside an isolated container.
    Step 6  — Score every non-empty finding with the Scorer agent.
    Step 7  — Assign a final risk rating with the Rater agent.
    """
    # ------------------------------------------------------------------ #
    # Step 1 — Pull image (show layer progress; fast no-op when cached)   #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][1/7][/cyan] Pulling image...")
    _pull_image_if_needed(image_name)

    # ------------------------------------------------------------------ #
    # Step 2 — Image Profiler (Hub API + LLM structuring)                 #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][2/7][/cyan] Profiling image...")
    _log.info("Step 2: check_docker_hub_status(%s)", image_name)
    hub_status = check_docker_hub_status(image_name)
    _log.info("Step 2: extract_image_metadata(%s)", image_name)
    image_meta = extract_image_metadata(image_name)
    _log.info("Step 2: running image_profiler agent (model=%s)", model)
    profile = await _run_agent(
        build_image_profiler_agent(model),
        {
            "image_name": image_name,
            "hub_status": json.dumps(hub_status),
            "image_meta": json.dumps(image_meta),
        },
        "Populate the ImageProfile from the provided hub_status and image_meta data.",
    )
    _log.info("Step 2: profile=%s", profile)

    # ------------------------------------------------------------------ #
    # Step 3 — Static Analysis (9 tools run in parallel via thread pool)  #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][3/7][/cyan] Static analysis")

    # Print all tool names before dispatching so the user sees what is
    # about to run. The tools are independent and share no state, so
    # they can safely execute concurrently in the default thread pool.
    for _label in (
        "secrets (trufflehog)",
        "layer analysis",
        "scripts",
        "urls",
        "env vars",
        "manifests",
        "persistence",
        "history",
        "capabilities",
    ):
        _console.print(f"[dim]  ► {_label}[/dim]")

    _loop = asyncio.get_running_loop()
    (
        trufflehog_result,
        layer_result,
        scripts_result,
        urls_result,
        env_result,
        manifests_result,
        persistence_result,
        history_result,
        capabilities_result,
    ) = await asyncio.gather(
        _loop.run_in_executor(None, run_trufflehog_scan, image_name),
        _loop.run_in_executor(None, analyze_image_layers, image_name),
        _loop.run_in_executor(None, analyze_scripts, image_name),
        _loop.run_in_executor(None, extract_urls, image_name),
        _loop.run_in_executor(None, analyze_env_vars, image_name),
        _loop.run_in_executor(None, analyze_manifests, image_name),
        _loop.run_in_executor(None, analyze_persistence, image_name),
        _loop.run_in_executor(None, analyze_history, image_name),
        _loop.run_in_executor(None, analyze_capabilities, image_name),
    )
    _log.info(
        "Step 3: complete — trufflehog=%s layer=%s scripts=%s urls=%s "
        "env=%s manifests=%s persistence=%s history=%s capabilities=%s",
        trufflehog_result, layer_result, scripts_result, urls_result,
        env_result, manifests_result, persistence_result,
        history_result, capabilities_result,
    )

    raw_static = {
        "trufflehog":   trufflehog_result,
        "layer":        layer_result,
        "scripts":      scripts_result,
        "urls":         urls_result,
        "env":          env_result,
        "manifests":    manifests_result,
        "persistence":  persistence_result,
        "history":      history_result,
        "capabilities": capabilities_result,
    }

    # ------------------------------------------------------------------ #
    # Step 4 — URL Validator (deterministic: filter → DoH → Spamhaus)    #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][4/7][/cyan] Validating URLs...")
    flagged_urls = raw_static["urls"].get("url_findings", [])
    _log.info("Step 4: flagged_urls count=%d", len(flagged_urls))
    if flagged_urls:
        # validate_urls performs blocking network I/O (Google DoH +
        # Spamhaus DNSBL lookups), so it runs in the thread pool.
        url_verdicts = await _loop.run_in_executor(
            None, validate_urls, flagged_urls[:50]
        )
    else:
        _console.print("[dim]  No flagged URLs — skipping.[/dim]")
        url_verdicts = []
    _log.info("Step 4: url_verdicts=%s", url_verdicts)

    # ------------------------------------------------------------------ #
    # Step 5 — Dynamic Analysis (7 probes inside an isolated container)   #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][5/7][/cyan] Dynamic analysis")

    def _on_probe(probe_name: str) -> None:
        """Print the probe label in dim gray before each probe fires."""
        label = probe_name.replace("_", " ")
        _console.print(f"[dim]  ► {label}[/dim]")

    dynamic_result = run_dynamic_analysis(image_name, on_probe=_on_probe)
    _log.info("Step 5: dynamic=%s", dynamic_result)

    # ------------------------------------------------------------------ #
    # Filter — build the flat findings dict passed to the Scorer           #
    # (internal step; no user-visible output)                              #
    # ------------------------------------------------------------------ #
    filtered = _filter_empty_findings(raw_static, dynamic_result, url_verdicts)
    _log.info("Filtered finding keys: %s", list(filtered.keys()))

    # ------------------------------------------------------------------ #
    # Step 6 — Scorer (LLM agent)                                         #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][6/7][/cyan] Scoring findings...")
    _log.info("Step 6: running scorer agent")
    scoring: ScoringReport = await _run_agent(
        build_scorer_agent(model),
        {
            "image_profile": json.dumps(profile.model_dump()),
            "filtered_findings": json.dumps(filtered),
        },
        "Score these findings.",
    )
    _log.info("Step 6: scored_findings count=%d", len(scoring.scored_findings))

    # ------------------------------------------------------------------ #
    # Step 7 — Rater (LLM agent) + FinalReport assembly                   #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][7/7][/cyan] Rating image...")
    _log.info("Step 7: running rater agent")
    rating: RaterReport = await _run_agent(
        build_rater_agent(model),
        {"scoring_report": json.dumps(scoring.model_dump())},
        "Rate this image.",
    )
    _log.info(
        "Step 7: final_rating=%s  summary=%s",
        rating.final_rating,
        rating.summary,
    )

    _console.print("[green]Done.[/green]\n")

    return FinalReport(
        schema_version=settings.schema_version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        image_name=image_name,
        profile=profile,
        url_verdicts=url_verdicts,
        scored_findings=[
            finding.model_dump() for finding in scoring.scored_findings
        ],
        final_rating=rating.final_rating,
        summary=rating.summary,
    )


def run_pipeline(
    image_name: str,
    model: str | None = None,
) -> FinalReport:
    """
    Run the docker-sentinel pipeline and return the assembled FinalReport.

    Synchronous entry point consumed by cli.py. Resolves the effective
    model string, applies the Windows ProactorEventLoop policy when
    needed, and delegates to the async implementation.

    LiteLLM resolves Anthropic credentials from the standard
    ANTHROPIC_API_KEY environment variable. We forward our custom-named
    DOCKER_SENTINEL_AI_KEY to that variable here so that users only ever
    need to set DOCKER_SENTINEL_AI_KEY.

    Args:
        image_name: Docker image reference to inspect.
        model: Optional LiteLLM model string override. Falls back to
               settings.docker_sentinel_model when not provided.

    Returns:
        A fully assembled FinalReport from the 7-step M13 pipeline.
    """
    if settings.docker_sentinel_ai_key:
        os.environ["ANTHROPIC_API_KEY"] = settings.docker_sentinel_ai_key

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsProactorEventLoopPolicy()
        )

    effective_model = model or settings.docker_sentinel_model
    return asyncio.run(_run_pipeline_async(image_name, effective_model))


async def _run_raw_findings_async(
    image_name: str,
    output_dir: str,
) -> RawFindings:
    """
    Execute only the Python analysis tools and return raw findings.

    No LLM agents are invoked. Runs the same pull, static analysis,
    and dynamic analysis steps as the full pipeline but stops before
    URL validation, scoring, and rating. The result is written to a
    JSON file in output_dir for downstream consumers (e.g. Claude Code
    skills) to process with their own model access.

    Step 1 — Pull image into the local daemon cache.
    Step 2 — Run all 9 static tools in parallel via thread pool.
    Step 3 — Run all 7 dynamic probes inside an isolated container.
    """
    # ------------------------------------------------------------------ #
    # Step 1 — Pull image                                                  #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][1/3][/cyan] Pulling image...")
    _pull_image_if_needed(image_name)

    # ------------------------------------------------------------------ #
    # Step 2 — Static Analysis (9 tools, parallel)                        #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][2/3][/cyan] Running static analysis...")

    for _label in (
        "secrets (trufflehog)",
        "layer analysis",
        "scripts",
        "urls",
        "env vars",
        "manifests",
        "persistence",
        "history",
        "capabilities",
    ):
        _console.print(f"[dim]  ► {_label}[/dim]")

    _loop = asyncio.get_running_loop()
    (
        trufflehog_result,
        layer_result,
        scripts_result,
        urls_result,
        env_result,
        manifests_result,
        persistence_result,
        history_result,
        capabilities_result,
    ) = await asyncio.gather(
        _loop.run_in_executor(None, run_trufflehog_scan, image_name),
        _loop.run_in_executor(None, analyze_image_layers, image_name),
        _loop.run_in_executor(None, analyze_scripts, image_name),
        _loop.run_in_executor(None, extract_urls, image_name),
        _loop.run_in_executor(None, analyze_env_vars, image_name),
        _loop.run_in_executor(None, analyze_manifests, image_name),
        _loop.run_in_executor(None, analyze_persistence, image_name),
        _loop.run_in_executor(None, analyze_history, image_name),
        _loop.run_in_executor(None, analyze_capabilities, image_name),
    )

    raw_static = {
        "trufflehog":   trufflehog_result,
        "layer":        layer_result,
        "scripts":      scripts_result,
        "urls":         urls_result,
        "env":          env_result,
        "manifests":    manifests_result,
        "persistence":  persistence_result,
        "history":      history_result,
        "capabilities": capabilities_result,
    }

    # ------------------------------------------------------------------ #
    # Step 3 — Dynamic Analysis                                            #
    # ------------------------------------------------------------------ #
    _console.print("[cyan][3/3][/cyan] Running dynamic analysis...")

    def _on_probe(probe_name: str) -> None:
        """Print the probe label in dim gray before each probe fires."""
        label = probe_name.replace("_", " ")
        _console.print(f"[dim]  ► {label}[/dim]")

    dynamic_result = run_dynamic_analysis(image_name, on_probe=_on_probe)

    _console.print("[green]Done.[/green]\n")

    findings = RawFindings(
        schema_version=settings.schema_version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        image_name=image_name,
        static=raw_static,
        dynamic=dynamic_result,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = Path(output_dir) / f"sentinel_raw_{timestamp}.json"
    output_path.write_text(
        json.dumps(findings.model_dump(), indent=2),
        encoding="utf-8",
    )
    _console.print(f"[dim]Raw findings written to: {output_path}[/dim]")

    return findings


def run_raw_findings(
    image_name: str,
    output_dir: str = ".",
) -> RawFindings:
    """
    Run only the Python analysis tools and write raw findings to disk.

    No LLM agents are invoked — does not require DOCKER_SENTINEL_AI_KEY.
    Used by the --raw-findings CLI flag and Claude Code skills.

    Args:
        image_name: Docker image reference to inspect.
        output_dir: Directory to write the sentinel_raw_*.json file.

    Returns:
        A RawFindings instance containing all static and dynamic tool
        outputs with no LLM-derived fields.
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsProactorEventLoopPolicy()
        )

    return asyncio.run(_run_raw_findings_async(image_name, output_dir))
