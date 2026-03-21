"""
tools/dynamic_runner.py — Runtime container analysis.

Starts a Docker image in a fully isolated, read-only container with
all Linux capabilities dropped and no network access, then runs a set
of non-destructive probes to inspect the container's runtime state.
The container is always stopped and removed when analysis finishes,
regardless of whether probes succeed or fail.
"""

import re

import docker
import docker.errors
import docker.models.containers


# ---------------------------------------------------------------------------
# Isolation configuration
# ---------------------------------------------------------------------------

# Memory ceiling for the probe container. Keeps a runaway process from
# consuming all available host memory during analysis.
_CONTAINER_MEM_LIMIT = "256m"

# Keeps the container alive without executing its own workload so that
# exec probes can be run safely against a fully initialised filesystem.
_IDLE_ENTRYPOINT = ["tail", "-f", "/dev/null"]


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------

# Commands requiring shell features (output redirection, error
# suppression) are wrapped in ["sh", "-c", "..."].
_PROBES: list[dict] = [
    {
        "name": "running_processes",
        "command": ["ps", "aux"],
    },
    {
        "name": "suid_files",
        "command": ["sh", "-c", "find / -perm -4000 2>/dev/null"],
    },
    {
        "name": "environment_variables",
        "command": ["env"],
    },
    {
        "name": "crontab",
        "command": ["sh", "-c", "cat /etc/crontab 2>/dev/null"],
    },
    {
        "name": "listening_services",
        "command": [
            "sh", "-c",
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        ],
    },
    {
        "name": "sudoers",
        "command": ["sh", "-c", "cat /etc/sudoers 2>/dev/null"],
    },
    {
        "name": "active_services",
        "command": [
            "sh", "-c",
            "systemctl list-units --type=service --state=active 2>/dev/null",
        ],
    },
]


# ---------------------------------------------------------------------------
# Anomaly detection constants
# ---------------------------------------------------------------------------

# Process names that should never appear in a clean container at
# startup and indicate active post-exploitation or staging activity.
_SUSPICIOUS_PROCESS_NAMES = frozenset({
    "nc", "netcat", "ncat", "nmap", "socat", "tcpdump",
    "wget", "curl", "python", "python3", "perl", "ruby",
})

# SUID binaries commonly present in standard Linux distributions.
# Files found outside this set are flagged as unexpected.
_KNOWN_SUID_PATHS = frozenset({
    "/usr/bin/passwd",       "/usr/bin/sudo",
    "/usr/bin/su",           "/bin/su",
    "/usr/bin/newgrp",       "/usr/bin/chsh",
    "/usr/bin/chfn",         "/usr/bin/gpasswd",
    "/bin/mount",            "/bin/umount",
    "/usr/bin/mount",        "/usr/bin/umount",
    "/usr/bin/pkexec",       "/usr/lib/openssh/ssh-keysign",
    "/usr/bin/ssh-agent",    "/sbin/unix_chkpwd",
    "/usr/sbin/unix_chkpwd",
})

# Ports expected to be in a listening state in standard images. Any
# port bound to all interfaces (0.0.0.0 or :::) outside this set is flagged.
_KNOWN_SAFE_PORTS = frozenset({22, 80, 443, 3306, 5432, 6379, 27017})

# Systemd service units considered normal in a standard Linux container.
# Any active unit not in this set is flagged as potentially unexpected.
_KNOWN_SAFE_SERVICES = frozenset({
    "systemd-journald", "systemd-udevd", "dbus", "sshd", "cron",
    "rsyslog", "docker", "containerd", "systemd-logind",
    "systemd-networkd", "systemd-resolved",
})

# Key name patterns that suggest an environment variable holds a secret
# that should not be present in a runtime container environment.
_CREDENTIAL_KEY_RE = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AUTH",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

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


def _start_isolated_container(
    client: docker.DockerClient,
    image_name: str,
) -> docker.models.containers.Container:
    """
    Create and start a fully isolated container for runtime probing.

    The container is configured with the strictest practical isolation:
      - No network access (network_mode="none").
      - All Linux capabilities dropped (cap_drop=["ALL"]).
      - Read-only root filesystem (read_only=True).
      - Hard memory ceiling of 256 MB (mem_limit).
      - Privilege escalation blocked (security_opt=no-new-privileges).
      - Idle entrypoint (tail -f /dev/null) keeps it alive without
        running the image's own workload.
    """
    return client.containers.run(
        image_name,
        entrypoint=_IDLE_ENTRYPOINT,
        detach=True,
        network_mode="none",
        cap_drop=["ALL"],
        read_only=True,
        mem_limit=_CONTAINER_MEM_LIMIT,
        security_opt=["no-new-privileges"],
        remove=False,
    )


def _stop_and_remove_container(
    container: docker.models.containers.Container,
) -> None:
    """
    Stop and forcibly remove a container, suppressing all errors.

    Errors are suppressed because the container may have already exited
    or been removed (e.g. if it was OOM-killed during a probe). The
    goal is a best-effort cleanup that never raises.
    """
    try:
        container.stop(timeout=5)
    except docker.errors.DockerException:
        pass
    try:
        container.remove(force=True)
    except docker.errors.DockerException:
        pass


def _decode_exec_output(raw_bytes: bytes | None) -> str:
    """
    Decode container exec output bytes to a UTF-8 string.

    None is returned by the Docker SDK when a command produces no
    output; this is normalised to an empty string so callers always
    receive a string rather than having to handle None.
    """
    if not raw_bytes:
        return ""
    return raw_bytes.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Anomaly flagging functions
# ---------------------------------------------------------------------------

def _flag_process_anomalies(raw_output: str) -> list[str]:
    """
    Scan ps aux output and flag suspicious running processes.

    The first line (header) is skipped. The COMMAND field (index 10)
    of each subsequent line is checked against the set of process names
    that should not appear in a clean container at startup.
    """
    anomalies = []
    lines = raw_output.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 11:
            continue
        command_field = parts[10]
        base_name = command_field.split("/")[-1].lower()
        if base_name in _SUSPICIOUS_PROCESS_NAMES:
            anomalies.append(f"suspicious process: {line.strip()}")
    return anomalies


def _flag_suid_anomalies(raw_output: str) -> list[str]:
    """
    Flag SUID files that are not on the known-safe list.

    Any file path returned by the find probe that is absent from the
    set of well-known system SUID binaries is reported as unexpected
    and worth investigating.
    """
    anomalies = []
    for line in raw_output.strip().splitlines():
        path = line.strip()
        if path and path not in _KNOWN_SUID_PATHS:
            anomalies.append(f"unexpected SUID file: {path}")
    return anomalies


def _flag_env_anomalies(raw_output: str) -> list[str]:
    """
    Flag environment variables whose names suggest embedded credentials.

    Credentials baked into a container's runtime environment are a
    common secret-management antipattern. Only the key name is checked
    to avoid logging any secret values in the findings.
    """
    anomalies = []
    for line in raw_output.strip().splitlines():
        if "=" not in line:
            continue
        key = line.split("=", 1)[0]
        if _CREDENTIAL_KEY_RE.search(key):
            anomalies.append(f"credential-like env var: {key}")
    return anomalies


def _flag_crontab_anomalies(raw_output: str) -> list[str]:
    """
    Flag active entries found in /etc/crontab.

    Crontab jobs in a container image are unusual and may indicate a
    persistence mechanism. Comment lines, blank lines, and variable
    assignments (SHELL=, PATH=, MAILTO=) are excluded from flagging.
    """
    anomalies = []
    for line in raw_output.strip().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Variable assignments at the top of a crontab are normal.
        if re.match(r"^[A-Z_]+=", stripped):
            continue
        anomalies.append(f"crontab entry: {stripped}")
    return anomalies


def _flag_listening_service_anomalies(raw_output: str) -> list[str]:
    """
    Flag ports bound to all interfaces that are not in the known-safe set.

    Parses the Local Address column from ss/netstat output. Only addresses
    starting with '0.0.0.0:' or ':::' are considered externally reachable.
    Ports in _KNOWN_SAFE_PORTS are excluded; everything else is flagged.
    """
    anomalies = []
    for line in raw_output.strip().splitlines()[1:]:
        for part in line.split():
            if not (part.startswith("0.0.0.0:") or part.startswith(":::")):
                continue
            port_str = part.rsplit(":", 1)[-1]
            try:
                port = int(port_str)
            except ValueError:
                continue
            if port not in _KNOWN_SAFE_PORTS:
                anomalies.append(f"unexpected listening port: {part}")
    return anomalies


def _flag_sudoers_anomalies(raw_output: str) -> list[str]:
    """
    Flag sudoers entries that grant passwordless privilege escalation.

    Comment lines and blank lines are skipped. Any active rule containing
    NOPASSWD is flagged — it allows processes to escalate to root without
    authentication, which is unsafe in a container context.
    """
    anomalies = []
    for line in raw_output.strip().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "NOPASSWD" in stripped:
            anomalies.append(f"sudoers NOPASSWD entry: {stripped}")
    return anomalies


def _flag_active_service_anomalies(raw_output: str) -> list[str]:
    """
    Flag systemd service units not present in the known-safe baseline.

    Parses unit names ending in '.service' from 'systemctl list-units'
    output. Units outside _KNOWN_SAFE_SERVICES are unexpected for a
    minimal container and may indicate a persistent backdoor or sidecar.
    """
    anomalies = []
    for line in raw_output.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0]
        if not unit.endswith(".service"):
            continue
        unit_name = unit[: -len(".service")]
        if unit_name not in _KNOWN_SAFE_SERVICES:
            anomalies.append(f"unexpected active service: {unit}")
    return anomalies


# Dispatch table: probe name → anomaly checker function.
# Defined after all checker functions so direct references are valid.
_ANOMALY_CHECKERS = {
    "running_processes":     _flag_process_anomalies,
    "suid_files":            _flag_suid_anomalies,
    "environment_variables": _flag_env_anomalies,
    "crontab":               _flag_crontab_anomalies,
    "listening_services":    _flag_listening_service_anomalies,
    "sudoers":               _flag_sudoers_anomalies,
    "active_services":       _flag_active_service_anomalies,
}


# ---------------------------------------------------------------------------
# Probe runner
# ---------------------------------------------------------------------------

def _run_single_probe(
    container: docker.models.containers.Container,
    probe: dict,
) -> dict:
    """
    Execute one probe command inside the container and return results.

    Returns a dict with the probe name, raw decoded output, and any
    anomalies detected. If the exec call itself fails, the error
    message is placed in the anomalies list so the failure is visible
    in the final report without crashing the pipeline.
    """
    try:
        result = container.exec_run(probe["command"])
        raw_output = _decode_exec_output(result.output)
    except docker.errors.DockerException as exc:
        return {
            "probe": probe["name"],
            "anomalies": [f"probe failed: {exc}"],
        }

    checker = _ANOMALY_CHECKERS.get(probe["name"])
    anomalies = checker(raw_output) if checker else []

    return {
        "probe": probe["name"],
        "anomalies": anomalies,
    }


def _execute_all_probes(
    container: docker.models.containers.Container,
    on_probe=None,
) -> list[dict]:
    """
    Run every defined probe sequentially and return all results.

    Probes are intentionally run one at a time so that each captures a
    consistent snapshot without interference from concurrent commands.
    If on_probe is provided it is called with the probe name just before
    each probe executes, allowing the caller to display progress.
    """
    results = []
    for probe in _PROBES:
        if on_probe is not None:
            on_probe(probe["name"])
        results.append(_run_single_probe(container, probe))
    return results


# ---------------------------------------------------------------------------
# Error result and public API
# ---------------------------------------------------------------------------

def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when dynamic analysis fails.

    Returns an empty checks list and carries the failure reason in the
    'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "container_id": "",
        "checks": [],
        "error": error_message,
    }


def run_dynamic_analysis(image_name: str, on_probe=None) -> dict:
    """
    Run seven runtime probes inside a fully isolated container.

    Probes: running processes, SUID files, environment variables, crontab,
    listening services, sudoers, and active systemd services. The container
    runs with no network, all capabilities dropped, a read-only filesystem,
    and a 256 MB memory limit. It is always cleaned up after analysis.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".
        on_probe: Optional callable(probe_name: str) invoked just before
                  each probe fires, for progress display in the caller.

    Returns:
        dict with 'container_id', 'checks' (list of {probe, anomalies}),
        and 'error'.
    """
    try:
        client = docker.from_env()
        _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return _build_error_result(str(exc))

    container = None
    checks: list[dict] = []

    try:
        container = _start_isolated_container(client, image_name)
        checks = _execute_all_probes(container, on_probe=on_probe)
    except docker.errors.DockerException as exc:
        return _build_error_result(str(exc))
    finally:
        if container is not None:
            _stop_and_remove_container(container)

    return {
        "container_id": container.id,
        "checks": checks,
        "error": None,
    }
