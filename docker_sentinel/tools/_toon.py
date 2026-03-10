"""
tools/_toon.py — TOON encoding helper for tool return values.

Converts Python dicts to TOON (Token-Oriented Object Notation) strings
before they are passed back to the LLM as tool results. TOON eliminates
repeated field names in uniform arrays, typically saving 30–60% of the
input tokens that JSON would consume for the same data.

Session state values (written via output_key) continue to flow as JSON
between agents — only the in-context tool result strings are encoded here.
"""

import json
import logging

from toon import encode

logger = logging.getLogger(__name__)


def to_toon(data: dict) -> str:
    """
    Encode a dict as a TOON string for LLM tool result consumption.

    Falls back to compact JSON if TOON encoding fails, so a bad encode
    never silently kills a tool call. ADK places string return values
    directly into the tool response without its own JSON serialisation,
    which is why returning a string is safe here.

    Args:
        data: The dict to encode.

    Returns:
        A TOON-formatted string, or minified JSON on encoding failure.
    """
    try:
        return encode(data)
    except Exception as exc:
        logger.warning(
            "TOON encode failed (%s); falling back to JSON.", exc
        )
        return json.dumps(data, separators=(",", ":"))
