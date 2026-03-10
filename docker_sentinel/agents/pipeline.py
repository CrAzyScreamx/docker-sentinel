"""
agents/pipeline.py — Full orchestration pipeline for docker-sentinel.

Assembles the four LlmAgents into a SequentialAgent that runs them in
order: image profiling → static scanning → dynamic scanning → synthesis.
Exposes build_pipeline() for runtime model overrides and a default
root_agent instance for convenience.
"""

from google.adk.agents import SequentialAgent

from docker_sentinel.agents.dynamic_scanner import build_dynamic_scanner_agent
from docker_sentinel.agents.image_profiler import build_image_profiler_agent
from docker_sentinel.agents.static_scanner import build_static_scanner_agent
from docker_sentinel.agents.synthesizer import build_synthesizer_agent
from docker_sentinel.config import settings


def build_pipeline(model: str) -> SequentialAgent:
    """
    Build a fresh DockerSentinel pipeline with the given LiteLLM model.

    Creates new agent instances so that a model string passed at runtime
    (e.g. from the CLI --model flag) is honoured by every sub-agent.
    """
    return SequentialAgent(
        name="DockerSentinelPipeline",
        sub_agents=[
            build_image_profiler_agent(model),
            build_static_scanner_agent(model),
            build_dynamic_scanner_agent(model),
            build_synthesizer_agent(model),
        ],
    )


root_agent = build_pipeline(settings.docker_sentinel_model)
