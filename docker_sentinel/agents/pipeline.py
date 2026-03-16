"""
agents/pipeline.py — ADK discovery entry point for docker-sentinel.

Exposes root_agent for `adk web` dev-mode discovery. In production,
the full M13 pipeline is orchestrated directly in runner.py — no
SequentialAgent graph is needed.
"""

from docker_sentinel.agents.image_profiler import build_image_profiler_agent
from docker_sentinel.config import settings


root_agent = build_image_profiler_agent(settings.docker_sentinel_model)
