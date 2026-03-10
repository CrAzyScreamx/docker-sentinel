"""
runner.py — Async ADK pipeline bridge for docker-sentinel.

Exposes a single synchronous run_pipeline entry point that builds the
agent pipeline, seeds session state with the target image name, drains
the SequentialAgent event stream, and assembles a FinalReport from the
four agents' session state outputs.
"""

import asyncio
import sys
from datetime import datetime, timezone

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich.console import Console

from docker_sentinel.agents.pipeline import build_pipeline
from docker_sentinel.config import settings
from docker_sentinel.models import (
    DynamicFindings,
    FinalReport,
    ImageProfile,
    StaticFindings,
    SynthesisReport,
)

_APP_NAME = "docker_sentinel"
_USER_ID = "runner"

_console = Console()

# Maps each agent name to the human-readable stage label shown during the run.
_STAGE_LABELS = {
    "image_profiler": "[1/4] Profiling image",
    "static_scanner": "[2/4] Running static analysis",
    "dynamic_scanner": "[3/4] Running dynamic analysis",
    "synthesizer": "[4/4] Synthesising findings",
}


async def _run_pipeline_async(
    image_name: str,
    model: str,
) -> FinalReport:
    """
    Build and run the full agent pipeline, returning an assembled FinalReport.

    Creates a fresh in-memory ADK session seeded with the image name,
    runs the SequentialAgent pipeline to completion, then reads each
    agent's output_key from session state and assembles the FinalReport.
    Each output_schema-backed key is stored as a dict by ADK, so
    model_validate() is used to convert them back into typed models.
    """
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name=_APP_NAME,
        user_id=_USER_ID,
        state={"image_name": image_name},
    )

    pipeline = build_pipeline(model)
    runner = Runner(
        app_name=_APP_NAME,
        agent=pipeline,
        session_service=session_service,
    )

    _console.print(
        f"\n[bold]Scanning[/bold] [cyan]{image_name}[/cyan]\n"
    )

    current_stage = None
    async for event in runner.run_async(
        user_id=_USER_ID,
        session_id=session.id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text=f"Inspect the image: {image_name}")],
        ),
    ):
        author = getattr(event, "author", None)
        if author and author in _STAGE_LABELS and author != current_stage:
            current_stage = author
            _console.print(
                f"  [cyan]>>[/cyan] {_STAGE_LABELS[author]}..."
            )

    _console.print()

    final_session = await session_service.get_session(
        app_name=_APP_NAME,
        user_id=_USER_ID,
        session_id=session.id,
    )

    state = final_session.state

    return FinalReport(
        schema_version=settings.schema_version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        image_name=image_name,
        profile=ImageProfile.model_validate(state["image_profile"]),
        static=StaticFindings.model_validate(state["static_findings"]),
        dynamic=DynamicFindings.model_validate(state["dynamic_findings"]),
        synthesis=SynthesisReport.model_validate(state["synthesis_report"]),
    )


def run_pipeline(
    image_name: str,
    model: str | None = None,
) -> FinalReport:
    """
    Run the docker-sentinel pipeline and return the assembled FinalReport.

    Synchronous entry point consumed by cli.py. Resolves the effective
    model string, applies the Windows ProactorEventLoop policy when needed,
    and delegates to the async implementation.

    Args:
        image_name: Docker image reference to inspect.
        model: Optional LiteLLM model string override. Falls back to
               settings.docker_sentinel_model when not provided.

    Returns:
        A fully assembled FinalReport containing all four agent outputs.
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsProactorEventLoopPolicy()
        )

    effective_model = model or settings.docker_sentinel_model
    return asyncio.run(_run_pipeline_async(image_name, effective_model))
