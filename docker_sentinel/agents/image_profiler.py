"""
agents/image_profiler.py — Image Profiler agent (Agent 1).

Calls Docker Hub and the Docker daemon to gather identity and runtime
metadata for the target image. Stores the result as a validated
ImageProfile in session state under the key 'image_profile'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import ImageProfile
from docker_sentinel.tools.docker_hub import check_docker_hub_status
from docker_sentinel.tools.docker_meta import extract_image_metadata


_INSTRUCTION = """
You are the Image Profiler agent for docker-sentinel, a Docker image
security inspector.

Steps:
1. Call `check_docker_hub_status` with image_name='{image_name}'.
2. Call `extract_image_metadata` with image_name='{image_name}'.
3. Populate the output schema fields from the tool results only.
   Do not invent any details not present in the tool responses.
"""


def build_image_profiler_agent(model: str) -> LlmAgent:
    """Build the Image Profiler agent with the given LiteLLM model string."""
    return LlmAgent(
        name="image_profiler",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[check_docker_hub_status, extract_image_metadata],
        output_schema=ImageProfile,
        output_key="image_profile",
    )


image_profiler_agent = build_image_profiler_agent(
    settings.docker_sentinel_model
)
