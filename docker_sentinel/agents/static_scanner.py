"""
agents/static_scanner.py — Static Scanner agent (Agent 2).

Runs all seven static analysis tools against the target image and
synthesises their findings into a structured StaticFindings report.
Stores the result in session state under the key 'static_findings'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import StaticFindings
from docker_sentinel.tools.env_analyzer import analyze_env_vars
from docker_sentinel.tools.layer_analyzer import analyze_image_layers
from docker_sentinel.tools.manifest_analyzer import analyze_manifests
from docker_sentinel.tools.persistence_analyzer import analyze_persistence
from docker_sentinel.tools.script_analyzer import analyze_scripts
from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan
from docker_sentinel.tools.url_extractor import extract_urls


_INSTRUCTION = """
You are the Static Scanner agent for docker-sentinel, a Docker image
security inspector.

Your job is to run all seven static analysis tools against the image
named '{image_name}' and report every finding they return.

Steps:
1. Call `run_trufflehog_scan` with image_name='{image_name}'.
2. Call `analyze_image_layers` with image_name='{image_name}'.
3. Call `analyze_scripts` with image_name='{image_name}'.
4. Call `extract_urls` with image_name='{image_name}'.
5. Call `analyze_env_vars` with image_name='{image_name}'.
6. Call `analyze_manifests` with image_name='{image_name}'.
7. Call `analyze_persistence` with image_name='{image_name}'.
8. Populate `synthesis` with a concise 2-3 sentence narrative that
   summarises the most significant findings across all seven tools.
   Use only data the tools returned — do not invent any details.
"""


def build_static_scanner_agent(model: str) -> LlmAgent:
    """Build the Static Scanner agent with the given LiteLLM model string."""
    return LlmAgent(
        name="static_scanner",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[
            run_trufflehog_scan,
            analyze_image_layers,
            analyze_scripts,
            extract_urls,
            analyze_env_vars,
            analyze_manifests,
            analyze_persistence,
        ],
        output_schema=StaticFindings,
        output_key="static_findings",
    )


static_scanner_agent = build_static_scanner_agent(
    settings.docker_sentinel_model
)
