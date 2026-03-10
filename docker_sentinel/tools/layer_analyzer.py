"""
tools/layer_analyzer.py — Docker image layer analysis.

Saves a Docker image to a tar archive, then walks each embedded
layer tar to detect SUID/SGID permission bits and suspicious hidden
files in locations where they are not normally expected.
"""

import io
import json
import tarfile

import docker
import docker.errors

from docker_sentinel.tools._toon import to_toon


# Directories where hidden (dot-prefixed) files are considered normal.
# A hidden file found outside these path prefixes is flagged.
_EXPECTED_HIDDEN_FILE_DIRS = ("/home/", "/root/", "/root")

_SUID_BIT = 0o4000
_SGID_BIT = 0o2000

# Basenames of binaries commonly dropped by cryptominers, rootkits,
# post-exploitation frameworks, and network scanners. Checked
# case-insensitively against every file found in image layers.
_MALICIOUS_BINARY_NAMES = frozenset({
    "xmrig", "kdevtmpfsi", "kworkerds", "pty86", "java2",
    "kinsing", "sysrv", "tsunami", "dota3", "mimikatz",
    "meterpreter", "linpeas", "pspy", "pspy64", "pspy32",
    "chisel", "frpc", "ligolo", "masscan", "zmap",
})

# Path prefixes where finding an executable is suspicious. Legitimate
# images should not ship executables in world-writable runtime dirs.
_SUSPICIOUS_EXEC_PATH_PREFIXES = ("/tmp/", "/dev/shm/")

# Any combination of owner/group/other execute bits.
_EXEC_BITS = 0o111

# Caps applied when building the final findings list.
# High-priority types (known_malicious_binary, executable_in_suspicious_path)
# are always kept in full; these limits apply to the noisier types that
# standard Linux images produce in large numbers from system binaries.
_MAX_SUID_FINDINGS = 15
_MAX_SGID_FINDINGS = 15
_MAX_HIDDEN_FILE_FINDINGS = 10


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


def _has_suid_bit(tarinfo: tarfile.TarInfo) -> bool:
    """
    Return True if the tarfile entry has the SUID permission bit set.

    SUID on an executable causes it to run as the file owner's UID
    rather than the invoking user's UID, which is a common privilege-
    escalation vector.
    """
    return bool(tarinfo.mode & _SUID_BIT)


def _has_sgid_bit(tarinfo: tarfile.TarInfo) -> bool:
    """
    Return True if the tarfile entry has the SGID permission bit set.

    SGID works similarly to SUID but applies to the group identity,
    and can also be used to grant elevated group permissions.
    """
    return bool(tarinfo.mode & _SGID_BIT)


def _is_hidden_filename(name: str) -> bool:
    """
    Return True if the final path component starts with a dot.

    Only the base name is inspected so a hidden file nested inside a
    visible directory is still detected. The special entries '.' and
    '..' are excluded.
    """
    base_name = name.rstrip("/").rsplit("/", 1)[-1]
    return base_name.startswith(".") and base_name not in (".", "..")


def _normalise_path(file_path: str) -> str:
    """
    Normalise a tar entry path to an absolute Unix path string.

    Tar entries may begin with './' or lack a leading slash. This
    function strips the './' prefix when present and then ensures a
    single leading slash so path-prefix comparisons are consistent.
    """
    if file_path.startswith("./"):
        file_path = file_path[2:]
    return "/" + file_path.lstrip("/")


def _is_in_unusual_directory(file_path: str) -> bool:
    """
    Return True if the path is outside directories where dotfiles are
    normally expected.

    Hidden files are common under /home and /root. A hidden file found
    anywhere else — /bin, /tmp, /etc, /var, etc. — is considered
    unusual and worth flagging as a potential backdoor or stealthy
    artifact.
    """
    normalised = _normalise_path(file_path)
    for expected_prefix in _EXPECTED_HIDDEN_FILE_DIRS:
        if normalised.startswith(expected_prefix):
            return False
    return True


def _is_known_malicious_binary(file_path: str) -> bool:
    """
    Return True if the file's basename matches a known malicious binary.

    Uses a static list of binary names commonly dropped by cryptominers,
    rootkits, post-exploitation frameworks, and network scanners. Only
    the basename is checked case-insensitively so path variations do
    not bypass detection.
    """
    base_name = file_path.rstrip("/").rsplit("/", 1)[-1].lower()
    return base_name in _MALICIOUS_BINARY_NAMES


def _is_executable_in_suspicious_path(
    entry: tarfile.TarInfo,
) -> bool:
    """
    Return True if the entry is an executable file under /tmp or /dev/shm.

    Dropping executables into world-writable runtime directories is a
    common malware technique to avoid detection in permanent filesystem
    locations. Both the executable bit and the path prefix must match
    for a finding to be raised.
    """
    if not entry.isfile():
        return False
    if not (entry.mode & _EXEC_BITS):
        return False
    normalised = _normalise_path(entry.name)
    return any(
        normalised.startswith(prefix)
        for prefix in _SUSPICIOUS_EXEC_PATH_PREFIXES
    )


def _cap_layer_findings(findings: list[dict]) -> list[dict]:
    """
    Apply priority-stratified caps to keep the findings list compact.

    High-priority types are always retained in full because they
    trigger CRITICAL/HIGH risk ratings. The noisier types (suid, sgid,
    suspicious_hidden_file) are capped to prevent standard system
    binaries from flooding the output and the LLM context window.
    """
    high_priority = [
        f for f in findings
        if f["finding_type"] in (
            "known_malicious_binary", "executable_in_suspicious_path"
        )
    ]
    suid = [f for f in findings if f["finding_type"] == "suid"]
    sgid = [f for f in findings if f["finding_type"] == "sgid"]
    hidden = [
        f for f in findings
        if f["finding_type"] == "suspicious_hidden_file"
    ]
    return (
        high_priority
        + suid[:_MAX_SUID_FINDINGS]
        + sgid[:_MAX_SGID_FINDINGS]
        + hidden[:_MAX_HIDDEN_FILE_FINDINGS]
    )


def _analyze_layer_entries(
    inner_tar: tarfile.TarFile,
    layer_index: int,
) -> list[dict]:
    """
    Walk all entries in a single layer tar and collect security findings.

    Each entry is checked for SUID/SGID permission bits, hidden files
    outside expected home directories, known malicious binary names,
    and executables dropped into /tmp or /dev/shm. Returns a list of
    finding dicts with 'finding_type', 'file_path', 'mode', and
    'layer_index' keys.
    """
    findings = []

    for entry in inner_tar.getmembers():
        finding_base = {
            "file_path": entry.name,
            "mode": oct(entry.mode),
            "layer_index": layer_index,
        }

        if _has_suid_bit(entry):
            findings.append({**finding_base, "finding_type": "suid"})

        if _has_sgid_bit(entry):
            findings.append({**finding_base, "finding_type": "sgid"})

        if (
            _is_hidden_filename(entry.name)
            and _is_in_unusual_directory(entry.name)
        ):
            findings.append(
                {**finding_base, "finding_type": "suspicious_hidden_file"}
            )

        if _is_known_malicious_binary(entry.name):
            findings.append(
                {**finding_base, "finding_type": "known_malicious_binary"}
            )

        if _is_executable_in_suspicious_path(entry):
            findings.append(
                {
                    **finding_base,
                    "finding_type": "executable_in_suspicious_path",
                }
            )

    return findings


def _collect_layer_findings(
    outer_tar: tarfile.TarFile,
) -> list[dict]:
    """
    Walk the outer image tar and analyse every embedded layer.tar.

    The outer archive from image.save() contains one directory per
    layer, each holding a 'layer.tar' with the filesystem delta. Each
    inner tar is opened in memory and delegated to
    _analyze_layer_entries. Malformed or empty layer tars are skipped.
    """
    all_findings = []
    for layer_index, layer_fileobj in enumerate(
        _get_layer_fileobjs(outer_tar)
    ):
        try:
            with tarfile.open(fileobj=layer_fileobj) as inner_tar:
                findings = _analyze_layer_entries(inner_tar, layer_index)
                all_findings.extend(findings)
        except tarfile.TarError:
            # Malformed or empty layer tars are skipped gracefully.
            pass

    return all_findings


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when layer analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "layer_findings": [],
        "error": error_message,
    }


def analyze_image_layers(image_name: str) -> str:
    """
    Inspect every filesystem layer for SUID/SGID files, hidden files in
    unusual directories, known malicious binaries, and executables in /tmp
    or /dev/shm.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'layer_findings' (list of {finding_type, file_path,
        mode, layer_index}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return to_toon(_build_error_result(str(exc)))

    try:
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            findings = _collect_layer_findings(outer_tar)
    except (tarfile.TarError, OSError) as exc:
        return to_toon(_build_error_result(str(exc)))

    return to_toon({
        "layer_findings": _cap_layer_findings(findings),
        "error": None,
    })
