"""
tools/trufflehog_runner.py — TruffleHog secret detection.

Runs the trufflesecurity/trufflehog Docker image against a target image
to detect secrets and credentials baked into the image layers. Output
is parsed from JSONL format into a structured list of findings.
"""

import json

import docker
import docker.errors

from docker_sentinel.config import settings

# Docker socket path mounted into the TruffleHog container so it can
# reach the host daemon to inspect target image layers.
_DOCKER_SOCKET_PATH = "/var/run/docker.sock"


def _parse_trufflehog_line(line: str) -> dict | None:
    """
    Parse a single JSONL line from TruffleHog output into a finding dict.

    Returns None for blank lines or lines that fail JSON parsing so the
    caller can safely skip them without crashing. Redacts the raw secret
    value to the first four characters followed by '***'.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    # File path and line number are nested inside SourceMetadata.
    docker_meta = (
        data.get("SourceMetadata", {})
            .get("Data", {})
            .get("Docker", {})
    )

    raw_value = data.get("Raw", "")
    redacted_snippet = (raw_value[:4] + "***") if raw_value else "***"

    return {
        "detector": data.get("DetectorName", "unknown"),
        "file_path": docker_meta.get("file", ""),
        "line_number": docker_meta.get("line", 0),
        "redacted_snippet": redacted_snippet,
    }


def _parse_jsonl_output(raw_output: str) -> list[dict]:
    """
    Convert TruffleHog's JSONL stdout into a list of finding dicts.

    Blank lines and malformed JSON lines are silently skipped because
    TruffleHog may emit progress or status messages between result lines.
    """
    findings = []
    for line in raw_output.splitlines():
        finding = _parse_trufflehog_line(line)
        if finding is not None:
            findings.append(finding)
    return findings


def _decode_output(raw_output: bytes | str) -> str:
    """
    Ensure container output is a UTF-8 string regardless of source type.

    Docker SDK may return bytes or str depending on the call path; this
    normalises both to str so the JSONL parser always receives a string.
    """
    if isinstance(raw_output, bytes):
        return raw_output.decode("utf-8", errors="replace")
    return raw_output


def run_trufflehog_scan(image_name: str) -> dict:
    """
    Run TruffleHog against a Docker image to detect embedded secrets.
    Mounts the Docker socket read-only; parses JSONL output into findings.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'secrets' (list of {detector, file_path, line_number,
        redacted_snippet}) and 'error'.
    """
    socket_volume = {
        _DOCKER_SOCKET_PATH: {
            "bind": _DOCKER_SOCKET_PATH,
            "mode": "ro",
        }
    }

    try:
        client = docker.from_env()
        raw_output = client.containers.run(
            image=settings.trufflehog_image,
            command=f"docker --image {image_name} --json",
            volumes=socket_volume,
            remove=True,
            stderr=False,
        )
    except docker.errors.ContainerError as exc:
        # Non-zero exit means secrets were found; output holds the JSONL.
        raw_output = exc.output or b""
    except docker.errors.DockerException as exc:
        return ({"secrets": [], "error": str(exc)})

    return ({
        "secrets": _parse_jsonl_output(_decode_output(raw_output)),
        "error": None,
    })
