"""
agents/image_profiler.py — Image Profiler agent (Agent 1).

Pure reasoning agent. Receives pre-fetched Docker Hub and daemon
metadata from runner.py and structures it into a validated ImageProfile.
Tool calls (check_docker_hub_status, extract_image_metadata) have been
moved to direct Python calls in runner.py so that output_schema and
tool-calling do not conflict inside the same agent.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import ImageProfile


_INSTRUCTION = """
You are the Image Profiler agent for docker-sentinel, a Docker image
security inspector.

You have been given two pre-fetched JSON blobs in session state:
  - {hub_status}   : result of check_docker_hub_status
  - {image_meta}   : result of extract_image_metadata

Populate every field of the output schema strictly from those two
blobs. Do not invent any detail that is not present in the data.
If a field is not available in the data use an empty string, empty
list, or zero as appropriate for the field type.
"""


def build_image_profiler_agent(model: str) -> LlmAgent:
    """Build the Image Profiler agent with the given LiteLLM model string."""
    return LlmAgent(
        name="image_profiler",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[],
        output_schema=ImageProfile,
        output_key="image_profile",
    )


image_profiler_agent = build_image_profiler_agent(
    settings.docker_sentinel_model
)
