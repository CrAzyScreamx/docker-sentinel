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
from typing import Any

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
from docker_sentinel.agents.url_validator import build_url_validator_agent
from docker_sentinel.config import settings
from docker_sentinel.models import FinalReport, RaterReport, ScoringReport
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
            "Check that ANTHROPIC_API_KEY is valid and the model string is correct "
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
    Execute the full 7-step M13 pipeline and return a FinalReport.

    Steps 1, 3, 6, and 7 invoke LLM agents via _run_agent. Steps 2
    and 4 call static and dynamic tools directly in Python with zero
    LLM overhead. Step 5 filters combined results before scoring.
    """
    # Step 1 — Image Profiler (direct tool calls + LLM structuring)
    _console.print("[cyan][1/7][/cyan] Profiling image...")
    _log.info("Step 1: calling check_docker_hub_status(%s)", image_name)
    hub_status = check_docker_hub_status(image_name)
    _log.info("Step 1: hub_status=%s", hub_status)
    _log.info("Step 1: calling extract_image_metadata(%s)", image_name)
    image_meta = extract_image_metadata(image_name)
    _log.info("Step 1: image_meta=%s", image_meta)
    _log.info("Step 1: running image_profiler agent with model=%s", model)
    profile = await _run_agent(
        build_image_profiler_agent(model),
        {
            "image_name": image_name,
            "hub_status": json.dumps(hub_status),
            "image_meta": json.dumps(image_meta),
        },
        "Populate the ImageProfile from the provided hub_status and image_meta data.",
    )
    _log.info("Step 1: profile=%s", profile)

    # Step 2 — Static Analysis (direct Python calls, zero LLM overhead)
    _console.print("[cyan][2/7][/cyan] Running static analysis...")
    _log.info("Step 2: starting static analysis")
    _log.info("Step 2: run_trufflehog_scan …")
    trufflehog_result = run_trufflehog_scan(image_name)
    _log.info("Step 2: trufflehog=%s", trufflehog_result)
    _log.info("Step 2: analyze_image_layers …")
    layer_result = analyze_image_layers(image_name)
    _log.info("Step 2: layer=%s", layer_result)
    _log.info("Step 2: analyze_scripts …")
    scripts_result = analyze_scripts(image_name)
    _log.info("Step 2: scripts=%s", scripts_result)
    _log.info("Step 2: extract_urls …")
    urls_result = extract_urls(image_name)
    _log.info("Step 2: urls=%s", urls_result)
    _log.info("Step 2: analyze_env_vars …")
    env_result = analyze_env_vars(image_name)
    _log.info("Step 2: env=%s", env_result)
    _log.info("Step 2: analyze_manifests …")
    manifests_result = analyze_manifests(image_name)
    _log.info("Step 2: manifests=%s", manifests_result)
    _log.info("Step 2: analyze_persistence …")
    persistence_result = analyze_persistence(image_name)
    _log.info("Step 2: persistence=%s", persistence_result)
    _log.info("Step 2: analyze_history …")
    history_result = analyze_history(image_name)
    _log.info("Step 2: history=%s", history_result)
    _log.info("Step 2: analyze_capabilities …")
    capabilities_result = analyze_capabilities(image_name)
    _log.info("Step 2: capabilities=%s", capabilities_result)
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
    _log.info("Step 2: complete")

    # Step 3 — URL Validator (conditional — skipped if no flagged URLs)
    _console.print("[cyan][3/7][/cyan] Validating URLs...")
    flagged_urls = raw_static["urls"].get("url_findings", [])
    _log.info("Step 3: flagged_urls count=%d", len(flagged_urls))
    if flagged_urls:
        url_report = await _run_agent(
            build_url_validator_agent(model),
            {"url_findings": json.dumps(flagged_urls[:50])},
            "Classify these URLs.",
        )
        url_verdicts = [v.model_dump() for v in url_report.verdicts]
    else:
        url_verdicts = []
    _log.info("Step 3: url_verdicts=%s", url_verdicts)

    # Step 4 — Dynamic Analysis (direct Python call)
    _console.print("[cyan][4/7][/cyan] Running dynamic analysis...")
    _log.info("Step 4: run_dynamic_analysis …")
    dynamic_result = run_dynamic_analysis(image_name)
    _log.info("Step 4: dynamic=%s", dynamic_result)

    # Step 5 — Filter empty findings
    _console.print("[cyan][5/7][/cyan] Filtering findings...")
    filtered = _filter_empty_findings(
        raw_static, dynamic_result, url_verdicts
    )
    _log.info("Step 5: filtered keys=%s", list(filtered.keys()))

    # Step 6 — Scorer (LLM agent)
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

    # Step 7 — Rater (LLM agent) + FinalReport assembly
    _console.print("[cyan][7/7][/cyan] Rating image...")
    _log.info("Step 7: running rater agent")
    rating: RaterReport = await _run_agent(
        build_rater_agent(model),
        {"scoring_report": json.dumps(scoring.model_dump())},
        "Rate this image.",
    )
    _log.info("Step 7: final_rating=%s  summary=%s", rating.final_rating, rating.summary)

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

    Args:
        image_name: Docker image reference to inspect.
        model: Optional LiteLLM model string override. Falls back to
               settings.docker_sentinel_model when not provided.

    Returns:
        A fully assembled FinalReport from the 7-step M13 pipeline.
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsProactorEventLoopPolicy()
        )

    effective_model = model or settings.docker_sentinel_model
    return asyncio.run(_run_pipeline_async(image_name, effective_model))
