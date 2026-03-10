"""
tools/env_analyzer.py — Docker image environment variable analysis.

Reads all environment variables baked into a Docker image and flags
any entry whose key name matches common credential patterns or whose
value resembles a known secret format such as JWTs, AWS keys, PEM
headers, or high-entropy hex / base64 strings.
"""

import re

import docker
import docker.errors

from docker_sentinel.tools._toon import to_toon


# Key name substrings that suggest the variable holds a credential.
# Matched case-insensitively against the full key name.
_CREDENTIAL_KEY_RE = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY"
    r"|AUTH|CREDENTIAL|ACCESS_KEY|DATABASE_URL",
    re.IGNORECASE,
)

# Value patterns for well-known secret formats.
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]+-----")

# Fullmatch patterns for high-entropy encoded strings.
# Hex is checked before base64 because the hex charset is a subset of
# the base64 charset; matching both for the same value would be redundant.
_HEX_RE = re.compile(r"[0-9a-fA-F]{32,}")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _get_or_pull_image(
    client: docker.DockerClient,
    image_name: str,
):
    """
    Return the local image object, pulling from the registry if absent.

    Tries to retrieve the image from the local Docker daemon first. If
    it is not found locally, pulls it from the registry before
    returning. Raises docker.errors.APIError if the pull fails.
    """
    try:
        return client.images.get(image_name)
    except docker.errors.ImageNotFound:
        return client.images.pull(image_name)


def _parse_env_string(env_string: str) -> tuple[str, str]:
    """
    Split a Docker env string into a (key, value) pair.

    Docker encodes environment variables as 'KEY=VALUE' strings where
    the value itself may contain '=' signs. Partitioning on the first
    '=' handles that correctly. Variables without a value separator
    are returned with an empty value string.
    """
    if "=" in env_string:
        key, _, value = env_string.partition("=")
        return key, value
    return env_string, ""


def _redact_value(value: str) -> str:
    """
    Return a redacted representation of a secret value.

    Keeps the first four characters so analysts can identify the
    secret type at a glance (e.g. 'AKIA' for AWS keys, 'eyJ' for
    JWTs) while preventing the full secret from appearing in reports.
    """
    if not value:
        return "***"
    return value[:4] + "***"


def _check_key_is_credential(key: str) -> str | None:
    """
    Return a reason string if the key name suggests a credential.

    Uses a case-insensitive substring search so that compound names
    such as 'DB_PASSWORD' or 'OAUTH_TOKEN' are matched correctly.
    Returns None if no credential pattern is found.
    """
    if _CREDENTIAL_KEY_RE.search(key):
        return f"key '{key}' matches a credential naming pattern"
    return None


def _check_value_for_secrets(value: str) -> list[str]:
    """
    Return a list of reasons if the value resembles a known secret format.

    Checks are applied in specificity order. Hex is evaluated before
    base64 to avoid reporting the same high-entropy value under both
    labels, since every hex character is also a valid base64 character.
    An empty list is returned when no secret pattern is matched.
    """
    if not value:
        return []

    reasons = []
    stripped = value.strip()

    if _JWT_RE.search(stripped):
        reasons.append("value resembles a JWT token (eyJ...)")

    if _AWS_KEY_RE.search(stripped):
        reasons.append("value resembles an AWS access key (AKIA...)")

    if _PEM_HEADER_RE.search(value):
        reasons.append("value contains a PEM key header")

    if _HEX_RE.fullmatch(stripped):
        reasons.append(
            f"value is a hex-encoded secret ({len(stripped)} chars)"
        )
    elif _BASE64_RE.fullmatch(stripped):
        reasons.append(
            f"value is a base64-encoded secret ({len(stripped)} chars)"
        )

    return reasons


def _analyze_env_var(key: str, value: str) -> dict | None:
    """
    Analyse a single environment variable and return a finding or None.

    Combines key-name and value-content checks. Returns a finding dict
    when at least one reason is found, or None when the variable looks
    benign. The returned dict always includes a redacted value so the
    report never exposes raw secrets.
    """
    reasons: list[str] = []

    key_reason = _check_key_is_credential(key)
    if key_reason:
        reasons.append(key_reason)

    reasons.extend(_check_value_for_secrets(value))

    if not reasons:
        return None

    return {
        "key": key,
        "value_redacted": _redact_value(value),
        "reasons": reasons,
    }


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when env analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "env_findings": [],
        "error": error_message,
    }


def analyze_env_vars(image_name: str) -> str:
    """
    Flag environment variables whose names suggest credentials (PASSWORD,
    SECRET, TOKEN, API_KEY, etc.) or whose values resemble known secret
    formats (JWT, AWS key, PEM header, high-entropy hex/base64).

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'env_findings' (list of {key, value_redacted, reasons})
        and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return to_toon(_build_error_result(str(exc)))

    try:
        config = (image.attrs or {}).get("Config") or {}
        env_strings = config.get("Env") or []
    except Exception as exc:
        return to_toon(_build_error_result(str(exc)))

    findings = []
    for env_string in env_strings:
        key, value = _parse_env_string(env_string)
        finding = _analyze_env_var(key, value)
        if finding is not None:
            findings.append(finding)

    return to_toon({
        "env_findings": findings,
        "error": None,
    })
