"""
agents/url_validator.py — URL Validator agent (M13 Agent 2).

Pure reasoning agent with no tools. Reads the list of flagged URL
findings from session state and classifies each URL as 'Safe' or
'Not Safe' based on domain, port, path, and flag content. Stores the
result as a URLValidationReport under the key 'url_validation_report'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import URLValidationReport


_INSTRUCTION = """
You are the URL Validator agent for docker-sentinel.

You will receive a JSON list of flagged URL findings as {url_findings}.
Each entry has: url, source_file, flags.

Classify every URL as exactly "Safe" or "Not Safe" using these rules:

SAFE domains (always Safe unless another rule overrides):
- docker.io, registry-1.docker.io, index.docker.io
- ghcr.io, gcr.io, quay.io
- amazonaws.com, googleapis.com
- github.com, raw.githubusercontent.com

NOT SAFE if ANY of the following apply:
- The URL host is a bare IP address (e.g. http://1.2.3.4/...)
- The flags list contains "raw IP address"
- The URL uses a non-standard port (flags contain "non-standard port")
- The host matches a free dynamic DNS provider
  (flags contain "dynamic DNS domain")
- The URL path contains a suspicious keyword such as download,
  install, setup, payload, or shell
  (flags contain "suspicious path keyword")
- The URL host is not in the Safe domain list and uses http://
  (unencrypted) with a suspicious path or an IP address

For every URL produce one verdict with:
- url: the exact URL string from the input
- verdict: "Safe" or "Not Safe"
- reason: one concise sentence explaining the classification decision

Use only the provided data — do not fetch URLs or invent information.
"""


def build_url_validator_agent(model: str) -> LlmAgent:
    """Build the URL Validator agent with the given LiteLLM model string."""
    return LlmAgent(
        name="url_validator",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[],
        output_schema=URLValidationReport,
        output_key="url_validation_report",
    )


url_validator_agent = build_url_validator_agent(
    settings.docker_sentinel_model
)
