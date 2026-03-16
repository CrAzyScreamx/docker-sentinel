"""
tools/history_analyzer.py — Docker image build history analysis.

Inspects the build history of a Docker image and checks each layer's
CreatedBy command string for patterns that commonly indicate malicious
build steps: pipe-to-shell downloads, base64 decoding, privilege setup,
remote ADD instructions, eval calls, and execution chaining.
"""

import re

import docker
import docker.errors


# Each tuple is (compiled_regex, label). Checked against the
# CreatedBy field of every history entry; the first match wins per layer.
_HISTORY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"curl\s+\S.*\|\s*(ba)?sh", re.IGNORECASE),
        "curl pipe-to-shell",
    ),
    (
        re.compile(r"wget\s+\S.*\|\s*sh", re.IGNORECASE),
        "wget pipe-to-shell",
    ),
    (
        re.compile(r"base64\s+-d", re.IGNORECASE),
        "base64 decode",
    ),
    (
        re.compile(r"chmod\s+\+x\s+\S"),
        "chmod +x on file",
    ),
    (
        re.compile(r"\b(useradd|adduser)\b", re.IGNORECASE),
        "user account creation",
    ),
    (
        re.compile(r"\bADD\s+https?://", re.IGNORECASE),
        "ADD from remote URL",
    ),
    (
        re.compile(r"&&\s*sh\b"),
        "shell execution chaining (&& sh)",
    ),
    (
        re.compile(r";\s*sh\b"),
        "shell execution chaining (; sh)",
    ),
    (
        re.compile(r"\beval\s*[\(\"]"),
        "eval call",
    ),
    (
        re.compile(r"python[23]?\s+-c\s+['\"]"),
        "inline Python execution",
    ),
]


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


def _match_first_pattern(command: str) -> str | None:
    """
    Return the label of the first pattern that matches the command string.

    Iterates _HISTORY_PATTERNS in definition order and returns the label
    of the first regex that matches. Returns None when no pattern fires.
    One finding per layer is sufficient to flag a suspicious layer.
    """
    for pattern, label in _HISTORY_PATTERNS:
        if pattern.search(command):
            return label
    return None


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when history analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "history_findings": [],
        "error": error_message,
    }


def analyze_history(image_name: str) -> dict:
    """
    Inspect the build history of a Docker image for suspicious patterns.

    Iterates each layer's CreatedBy command string and checks it against
    _HISTORY_PATTERNS. Records at most one finding per layer (first match
    wins). Handles ImageNotFound and generic Docker exceptions gracefully.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'history_findings' (list of {layer_index,
        command_snippet, pattern_matched}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return _build_error_result(str(exc))

    try:
        history = image.history()
    except docker.errors.DockerException as exc:
        return _build_error_result(str(exc))

    findings = []
    for layer_index, entry in enumerate(history):
        command = entry.get("CreatedBy", "") or ""
        matched_label = _match_first_pattern(command)
        if matched_label is not None:
            findings.append({
                "layer_index": layer_index,
                "command_snippet": command[:200],
                "pattern_matched": matched_label,
            })

    return {
        "history_findings": findings,
        "error": None,
    }
