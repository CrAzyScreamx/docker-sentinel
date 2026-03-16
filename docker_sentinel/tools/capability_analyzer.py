"""
tools/capability_analyzer.py — Docker image privilege and capability checks.

Inspects the image configuration and filesystem layers for four
privilege-related issues: running as root, exposing privileged ports,
privileged environment labels, and setcap usage inside layer files.
"""

import io
import re
import tarfile

import docker
import docker.errors

from docker_sentinel.tools.layer_analyzer import _get_layer_fileobjs


# Users that mean the container runs as root.
_ROOT_USERS = frozenset({"", "root", "0", "0:0"})

# Ports strictly below this threshold are considered privileged on Linux.
_PRIVILEGED_PORT_THRESHOLD = 1024

# Regex applied case-insensitively to label keys and env var key parts.
_PRIVILEGED_KEYWORD_PATTERN = re.compile(
    r"PRIVILEGED|DOCKER_SOCK|CAP_",
    re.IGNORECASE,
)

# Byte-level pattern searched inside every layer file for setcap calls.
_SETCAP_PATTERN = re.compile(rb"\bsetcap\b")


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


def _reassemble_image_bytes(image) -> io.BytesIO:
    """
    Collect all chunks from image.save() into a seekable BytesIO buffer.

    image.save() returns a generator of raw byte chunks. Joining them
    into a single BytesIO allows tarfile to seek within the stream,
    which is required when extracting nested layer tars.
    """
    buffer = io.BytesIO()
    for chunk in image.save():
        buffer.write(chunk)
    buffer.seek(0)
    return buffer


def _check_runs_as_root(cfg: dict) -> list[dict]:
    """
    Return a finding if the image is configured to run as root.

    The Docker User field defaults to root when empty. An explicit
    "root", "0", or "0:0" value is equally risky. Any of these values
    triggers a single CapabilityFinding.
    """
    user = cfg.get("User", "")
    if user not in _ROOT_USERS:
        return []
    return [{
        "finding_type": "runs_as_root",
        "evidence": f"User={user!r}",
        "detail": "Container runs as root by default",
    }]


def _check_privileged_ports(cfg: dict) -> list[dict]:
    """
    Return one finding per exposed port below 1024.

    Ports below 1024 are privileged on Linux and binding to them
    requires CAP_NET_BIND_SERVICE or running as root, indicating
    elevated privilege requirements.
    """
    findings = []
    exposed_ports = cfg.get("ExposedPorts") or {}
    for port_spec in exposed_ports:
        # port_spec format is "80/tcp", "443/udp", etc.
        numeric_part = port_spec.split("/")[0]
        try:
            port_number = int(numeric_part)
        except ValueError:
            continue
        if port_number < _PRIVILEGED_PORT_THRESHOLD:
            findings.append({
                "finding_type": "privileged_port",
                "evidence": port_spec,
                "detail": (
                    f"Port {port_number} is a privileged port "
                    f"(< {_PRIVILEGED_PORT_THRESHOLD})"
                ),
            })
    return findings


def _check_privileged_labels(cfg: dict) -> list[dict]:
    """
    Return findings for labels or env vars suggesting elevated privileges.

    Scans image label keys and environment variable key names for the
    patterns PRIVILEGED, DOCKER_SOCK, and CAP_ (case-insensitive).
    These patterns indicate the image was designed to run with special
    Docker capabilities or host socket access.
    """
    findings = []

    for label_key in (cfg.get("Labels") or {}):
        if _PRIVILEGED_KEYWORD_PATTERN.search(label_key):
            findings.append({
                "finding_type": "privileged_label",
                "evidence": f"Label key: {label_key}",
                "detail": (
                    "Label key matches privileged keyword pattern"
                ),
            })

    for env_entry in (cfg.get("Env") or []):
        key_part = env_entry.split("=", 1)[0]
        if _PRIVILEGED_KEYWORD_PATTERN.search(key_part):
            findings.append({
                "finding_type": "privileged_label",
                "evidence": f"Env var key: {key_part}",
                "detail": (
                    "Env var key matches privileged keyword pattern"
                ),
            })

    return findings


def _check_setcap_in_scripts(image) -> list[dict]:
    """
    Return findings for any layer file that contains a setcap call.

    Walks all image filesystem layers via _get_layer_fileobjs. For
    each regular file, reads its raw bytes and searches for the setcap
    command. One finding is produced per file that contains setcap.
    """
    findings = []
    try:
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            for layer_fobj in _get_layer_fileobjs(outer_tar):
                try:
                    with tarfile.open(fileobj=layer_fobj) as inner_tar:
                        for entry in inner_tar.getmembers():
                            if not entry.isfile():
                                continue
                            file_obj = inner_tar.extractfile(entry)
                            if file_obj is None:
                                continue
                            content = file_obj.read()
                            if _SETCAP_PATTERN.search(content):
                                findings.append({
                                    "finding_type": "setcap_in_script",
                                    "evidence": entry.name,
                                    "detail": (
                                        "File contains setcap — may "
                                        "grant Linux capabilities "
                                        "to binaries"
                                    ),
                                })
                except tarfile.TarError:
                    pass
    except (tarfile.TarError, OSError):
        pass
    return findings


def analyze_capabilities(image_name: str) -> dict:
    """
    Check the image for privilege and capability issues.

    Four checks are performed: runs_as_root (default user is root),
    privileged_port (exposed port below 1024), privileged_label (label
    or env var key matching PRIVILEGED/DOCKER_SOCK/CAP_), and
    setcap_in_script (setcap call found in any layer file).

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'capability_findings' (list of {finding_type,
        evidence, detail}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return {"capability_findings": [], "error": str(exc)}

    try:
        cfg = image.attrs["Config"]
    except (KeyError, docker.errors.DockerException) as exc:
        return {"capability_findings": [], "error": str(exc)}

    findings: list[dict] = []
    findings.extend(_check_runs_as_root(cfg))
    findings.extend(_check_privileged_ports(cfg))
    findings.extend(_check_privileged_labels(cfg))
    findings.extend(_check_setcap_in_scripts(image))

    return {"capability_findings": findings, "error": None}
