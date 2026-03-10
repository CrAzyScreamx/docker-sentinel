"""
tools/persistence_analyzer.py — Docker image persistence mechanism detection.

Walks every filesystem layer in a Docker image to identify files
associated with persistence techniques: cron jobs, init scripts,
systemd units, LD_PRELOAD hooks, shell profile backdoors, and SSH
authorized_keys files. Uses layer-last-wins semantics to mirror
Docker's overlay filesystem behaviour.
"""

import io
import json
import tarfile

import docker
import docker.errors

from docker_sentinel.tools._toon import to_toon


# Exact file paths that map directly to a persistence type.
_PERSISTENCE_EXACT_PATHS: dict[str, str] = {
    "/etc/crontab": "cron",
    "/etc/ld.so.preload": "ld_preload",
    "/etc/rc.local": "init",
}

# Path prefixes mapped to persistence types. Checked in order;
# the first matching prefix wins.
_PERSISTENCE_PREFIX_MAP: list[tuple[str, str]] = [
    ("/etc/cron.d/", "cron"),
    ("/etc/cron.hourly/", "cron"),
    ("/etc/cron.daily/", "cron"),
    ("/etc/cron.weekly/", "cron"),
    ("/etc/cron.monthly/", "cron"),
    ("/var/spool/cron/", "cron"),
    ("/etc/init.d/", "init"),
    ("/etc/rc.d/", "init"),
    ("/etc/systemd/system/", "systemd"),
    ("/lib/systemd/system/", "systemd"),
    ("/usr/lib/systemd/system/", "systemd"),
]

# Path suffixes mapped to persistence types. Checked in order;
# the first matching suffix wins.
_PERSISTENCE_SUFFIX_MAP: list[tuple[str, str]] = [
    ("/.ssh/authorized_keys", "ssh_authorized_keys"),
    ("/.bashrc", "shell_profile"),
    ("/.bash_profile", "shell_profile"),
    ("/.profile", "shell_profile"),
    ("/.zshrc", "shell_profile"),
]

# Maximum total persistence findings returned. Standard Linux images
# can contain hundreds of systemd units and cron files; capping keeps
# the LLM context compact while preserving all high-risk entries.
_MAX_PERSISTENCE_FINDINGS = 20

# Types that trigger CRITICAL risk — always included regardless of cap.
_HIGH_RISK_PERSISTENCE_TYPES = frozenset({"ld_preload", "ssh_authorized_keys"})


def _normalise_path(file_path: str) -> str:
    """
    Normalise a tar entry path to an absolute Unix path string.

    Tar entries may begin with './' or lack a leading slash. This
    function strips the './' prefix when present and ensures a single
    leading slash so path comparisons are consistent.
    """
    if file_path.startswith("./"):
        file_path = file_path[2:]
    return "/" + file_path.lstrip("/")


def _classify_persistence(normalised_path: str) -> str | None:
    """
    Return the persistence type for the given path, or None.

    Applies three rule sets in priority order: exact path match,
    path prefix match, path suffix match. Returns the first match
    found, or None if no rule applies.
    """
    if normalised_path in _PERSISTENCE_EXACT_PATHS:
        return _PERSISTENCE_EXACT_PATHS[normalised_path]

    for prefix, persistence_type in _PERSISTENCE_PREFIX_MAP:
        if normalised_path.startswith(prefix):
            return persistence_type

    for suffix, persistence_type in _PERSISTENCE_SUFFIX_MAP:
        if normalised_path.endswith(suffix):
            return persistence_type

    return None


def _get_layer_fileobjs(
    outer_tar: tarfile.TarFile,
) -> list[io.BytesIO]:
    """
    Return file objects for each layer tar in the image archive.

    Handles two formats:
      - Classic Docker V1.2: layers stored as {hash}/layer.tar entries.
      - OCI image format: layers stored as blobs/sha256/{hash} entries,
        with paths listed in manifest.json.
    """
    classic = [
        m for m in outer_tar.getmembers()
        if m.name.endswith("/layer.tar")
    ]
    if classic:
        fileobjs = []
        for m in classic:
            fobj = outer_tar.extractfile(m)
            if fobj is not None:
                fileobjs.append(fobj)
        return fileobjs

    # OCI format: parse manifest.json for layer blob paths.
    try:
        manifest_fobj = outer_tar.extractfile(
            outer_tar.getmember("manifest.json")
        )
        manifests = json.loads(manifest_fobj.read())
    except (KeyError, json.JSONDecodeError):
        return []

    fileobjs = []
    for image_manifest in manifests:
        for layer_path in image_manifest.get("Layers", []):
            try:
                fobj = outer_tar.extractfile(
                    outer_tar.getmember(layer_path)
                )
                if fobj is not None:
                    fileobjs.append(fobj)
            except KeyError:
                pass
    return fileobjs


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


def _collect_persistence_findings(
    outer_tar: tarfile.TarFile,
) -> list[dict]:
    """
    Walk all image layers and collect persistence-mechanism findings.

    Applies layer-last-wins semantics: if the same path appears in
    multiple layers, the later layer's entry overwrites the earlier one,
    mirroring Docker's overlay filesystem. Only the final state of each
    matched path is included in the returned findings.

    Returns a list of dicts with keys: file_path, layer_index,
    persistence_type, and evidence.
    """
    # Map normalised_path → (layer_index, persistence_type); later
    # layers overwrite earlier entries for the same path.
    seen: dict[str, tuple[int, str]] = {}

    for layer_index, layer_fileobj in enumerate(
        _get_layer_fileobjs(outer_tar)
    ):
        try:
            with tarfile.open(fileobj=layer_fileobj) as inner_tar:
                for entry in inner_tar.getmembers():
                    normalised = _normalise_path(entry.name)
                    persistence_type = _classify_persistence(normalised)
                    if persistence_type is not None:
                        seen[normalised] = (layer_index, persistence_type)
        except tarfile.TarError:
            # Malformed or empty layer tars are skipped gracefully.
            pass

    return [
        {
            "file_path": path,
            "layer_index": layer_index,
            "persistence_type": persistence_type,
            "evidence": f"File present in layer {layer_index}",
        }
        for path, (layer_index, persistence_type) in seen.items()
    ]


def _cap_persistence_findings(findings: list[dict]) -> list[dict]:
    """
    Cap the findings list while always retaining high-risk entries.

    ld_preload and ssh_authorized_keys trigger CRITICAL risk and are
    always included. The remaining slots are filled with other types
    (cron, init, systemd, shell_profile) up to _MAX_PERSISTENCE_FINDINGS.
    This prevents standard Linux service files from flooding the output.
    """
    high_risk = [
        f for f in findings
        if f["persistence_type"] in _HIGH_RISK_PERSISTENCE_TYPES
    ]
    others = [
        f for f in findings
        if f["persistence_type"] not in _HIGH_RISK_PERSISTENCE_TYPES
    ]
    remaining_slots = max(0, _MAX_PERSISTENCE_FINDINGS - len(high_risk))
    return high_risk + others[:remaining_slots]


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when persistence analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "persistence_findings": [],
        "error": error_message,
    }


def analyze_persistence(image_name: str) -> str:
    """
    Detect persistence mechanism files across all image layers: cron jobs,
    init scripts, systemd units, LD_PRELOAD hooks, shell profile backdoors,
    and SSH authorized_keys. Uses layer-last-wins semantics.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'persistence_findings' (list of {file_path, layer_index,
        persistence_type, evidence}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return to_toon(_build_error_result(str(exc)))

    try:
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            findings = _collect_persistence_findings(outer_tar)
    except (tarfile.TarError, OSError) as exc:
        return to_toon(_build_error_result(str(exc)))

    return to_toon({
        "persistence_findings": _cap_persistence_findings(findings),
        "error": None,
    })
