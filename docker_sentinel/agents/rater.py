"""
agents/rater.py — Rater agent (M13 Agent 4).

Pure reasoning agent with no tools. Reads the ScoringReport from
session state, maps the highest individual score to a rating band,
and writes a one-sentence plain-English summary of the image's risk
posture. Stores the result as a RaterReport under 'rater_report'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import RaterReport


_INSTRUCTION = """
You are the Rater agent for docker-sentinel.

You will receive {scoring_report} — a JSON ScoringReport with a list
of scored_findings (each has source, description, score, rationale)
and an optional adjustment_note.

RATING RULES — apply the band of the highest score present:
  score >= 9  → CRITICAL
  score >= 7  → HIGH
  score >= 5  → MEDIUM
  score >= 3  → LOW
  score <  3  → INFO
  no findings → INFO

Produce:
- final_rating: exactly one of "INFO", "LOW", "MEDIUM", "HIGH",
  "CRITICAL" — the band that matches the highest score.
- summary: a single plain-English sentence naming the primary threat
  (or confirming the image is clean) and its potential impact.
  Do not use technical jargon. Do not mention score numbers.
  If adjustment_note is set, briefly note the trust context.

Use only the provided data — do not invent findings.
"""


def build_rater_agent(model: str) -> LlmAgent:
    """Build the Rater agent with the given LiteLLM model string."""
    return LlmAgent(
        name="rater",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[],
        output_schema=RaterReport,
        output_key="rater_report",
    )


rater_agent = build_rater_agent(settings.docker_sentinel_model)
