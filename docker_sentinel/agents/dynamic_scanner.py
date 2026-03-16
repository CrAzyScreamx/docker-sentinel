# RETIRED — superseded by M13 pipeline. Not used in production.
"""
agents/dynamic_scanner.py — Dynamic Scanner agent (Agent 3).

Starts a fully isolated container from the target image, executes
four runtime probes (processes, SUID files, env vars, crontab), and
synthesises the results into a structured DynamicFindings report.
Stores the result in session state under the key 'dynamic_findings'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import DynamicFindings
from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis


_INSTRUCTION = """
You are the Dynamic Scanner agent for docker-sentinel, a Docker image
security inspector.

Your job is to execute runtime probes against the image named
'{image_name}' inside a fully isolated container and report the results.

Steps:
1. Call `run_dynamic_analysis` with image_name='{image_name}'.
2. Populate `synthesis` with a concise 2-3 sentence narrative that
   highlights the most significant anomalies found across all probes.
   Use only data the tool returned — do not invent any details.
"""


def build_dynamic_scanner_agent(model: str) -> LlmAgent:
    """
    Build the Dynamic Scanner agent with the given LiteLLM model string.
    """
    return LlmAgent(
        name="dynamic_scanner",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[run_dynamic_analysis],
        output_schema=DynamicFindings,
        output_key="dynamic_findings",
    )


dynamic_scanner_agent = build_dynamic_scanner_agent(
    settings.docker_sentinel_model
)
