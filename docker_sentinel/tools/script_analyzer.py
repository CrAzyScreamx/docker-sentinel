"""
tools/script_analyzer.py — Shell script discovery and analysis.

Walks every filesystem layer in a Docker image to identify shell
scripts by extension or shebang line, then scans their content for
dangerous patterns such as pipe-to-shell downloads, obfuscated
payloads, and destructive commands.
"""

import io
import json
import re
import tarfile

import docker
import docker.errors

from docker_sentinel.tools._toon import to_toon


# Known paths that are always treated as entrypoints regardless of
# extension or shebang.
_KNOWN_ENTRYPOINT_PATHS = frozenset({
    "/entrypoint.sh",
    "/docker-entrypoint.sh",
    "/start.sh",
    "/run.sh",
})

# Shebang tokens that identify a file as a shell script.
_SHELL_TOKENS = (b"sh", b"bash", b"ash", b"dash", b"zsh")

# Compiled byte-level patterns and their human-readable names,
# grouped by attack category. Patterns are applied per line; all
# matches on each line are recorded. Additional categories are added
# by tasks 6.2–6.7 within the appropriate section below.
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[bytes], str]] = [

    # ── General / Download Execution ──────────────────────────────────
    (
        re.compile(rb"curl\s+\S.*\|\s*(ba)?sh"),
        "pipe-to-shell (curl)",
    ),
    (
        re.compile(rb"wget\s+\S.*\|\s*sh"),
        "pipe-to-shell (wget)",
    ),
    (
        re.compile(rb"chmod\s+\+x\s+\S"),
        "chmod +x on download",
    ),

    # ── Reverse Shell ─────────────────────────────────────────────────
    # Tightened from bare \bnc\b|\bnetcat\b to require the -e shell
    # flag, eliminating false positives from legitimate netcat use.
    (
        re.compile(rb"\bnc\b.*-e\s+/bin/(ba)?sh"),
        "netcat reverse shell",
    ),
    (
        re.compile(rb"bash\s+.*>\s*/dev/tcp/"),
        "bash /dev/tcp reverse shell",
    ),
    (
        re.compile(rb"bash\s+.*>&\s*/dev/tcp/"),
        "bash /dev/tcp reverse shell (stderr)",
    ),
    (
        re.compile(
            rb"/dev/(tcp|udp)/\d{1,3}(\.\d{1,3}){3}/\d+"
        ),
        "raw /dev/tcp|udp channel",
    ),
    (
        re.compile(rb"mkfifo\s+\S"),
        "mkfifo named pipe",
    ),
    (
        re.compile(rb"socket\.connect\s*\("),
        "Python socket.connect",
    ),
    (
        re.compile(
            rb"socket\.socket\s*\(.*subprocess", re.DOTALL
        ),
        "Python socket+subprocess shell",
    ),
    (
        re.compile(
            rb"exec\s*\(\s*.*\.decode\s*\(", re.DOTALL
        ),
        "Python exec(decode())",
    ),
    (
        re.compile(
            rb"perl.*socket.*exec",
            re.DOTALL | re.IGNORECASE,
        ),
        "Perl socket reverse shell",
    ),
    (
        re.compile(rb"perl.*IO::Socket", re.IGNORECASE),
        "Perl IO::Socket reverse shell",
    ),
    (
        re.compile(rb"ncat\s+\S+\s+\d+\s+-e"),
        "ncat reverse shell",
    ),

    # ── Obfuscation ───────────────────────────────────────────────────
    (
        re.compile(rb"eval\s*\("),
        "eval() call",
    ),
    (
        re.compile(rb"base64\s+-d"),
        "base64 decode",
    ),
    (
        re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),
        "long base64 blob",
    ),

    # ── Destructive Commands ──────────────────────────────────────────
    (
        re.compile(rb"rm\s+-rf\s+/"),
        "destructive rm -rf /",
    ),
    (
        re.compile(rb"\bdd\s+if="),
        "destructive dd command",
    ),

    # ── Cryptominer / C2 ──────────────────────────────────────────────
    (
        re.compile(rb"stratum\+tcp://"),
        "mining stratum protocol",
    ),
    (
        re.compile(
            rb"(supportxmr|xmrpool|moneropool|nanopool|xmr\.)",
            re.IGNORECASE,
        ),
        "known XMR pool domain",
    ),
    (
        re.compile(rb"--donate-level\b"),
        "XMRig --donate-level flag",
    ),
    (
        re.compile(rb"\bxmrig\b", re.IGNORECASE),
        "xmrig binary reference",
    ),
    (
        re.compile(
            rb"\b(C2_HOST|C2_SERVER|DROPPER_URL|STAGE2_URL"
            rb"|PAYLOAD_URL|BACKDOOR_URL|EXFIL_SERVER)\s*="
        ),
        "C2/dropper variable assignment",
    ),

    # ── Persistence ───────────────────────────────────────────────────
    (
        re.compile(rb"crontab\s+-[il]"),
        "crontab modification",
    ),
    (
        re.compile(rb"echo\s+.*>\s*/var/spool/cron"),
        "direct cron spool write",
    ),
    (
        re.compile(rb"@reboot"),
        "cron @reboot entry",
    ),
    (
        re.compile(rb"LD_PRELOAD\s*="),
        "LD_PRELOAD injection",
    ),
    (
        re.compile(rb"/etc/ld\.so\.preload"),
        "ld.so.preload write",
    ),
    (
        re.compile(
            rb">>\s*~?/?(\.bashrc|\.bash_profile|\.profile|\.zshrc)"
        ),
        "shell profile backdoor",
    ),
    (
        re.compile(rb">>\s*/etc/rc\.local"),
        "rc.local persistence",
    ),
    (
        re.compile(rb">\s*/etc/systemd/system/.*\.service"),
        "systemd service file write",
    ),

    # ── History / Process Hiding ───────────────────────────────────────
    (
        re.compile(rb"unset\s+HISTFILE"),
        "HISTFILE unset",
    ),
    (
        re.compile(rb"HISTSIZE\s*=\s*0"),
        "HISTSIZE=0",
    ),
    (
        re.compile(rb"HISTFILESIZE\s*=\s*0"),
        "HISTFILESIZE=0",
    ),
    (
        re.compile(rb"history\s+-c"),
        "history -c (clear history)",
    ),
    (
        re.compile(rb"export\s+HISTFILE=/dev/null"),
        "HISTFILE redirected to /dev/null",
    ),

    # ── Container Escape ──────────────────────────────────────────────
    (
        re.compile(rb"nsenter\s+--target\s+1"),
        "nsenter host PID 1 escape",
    ),
    (
        re.compile(rb"chroot\s+/host"),
        "chroot escape to /host",
    ),
    (
        re.compile(rb"/proc/sysrq-trigger"),
        "sysrq-trigger access",
    ),

    # ── Advanced Obfuscation / Dropper Chaining ───────────────────────
    (
        re.compile(rb"eval.*base64", re.IGNORECASE),
        "eval+base64 chained obfuscation",
    ),
    (
        re.compile(rb"eval.*\$\(echo", re.IGNORECASE),
        "eval+echo subshell obfuscation",
    ),
    (
        re.compile(rb"\$'\\x[0-9a-fA-F]{2}"),
        "ANSI-C hex escape obfuscation",
    ),
    (
        re.compile(rb"cat\s*<<\s*'?\w+'?\s*\|\s*(ba)?sh"),
        "heredoc pipe-to-shell",
    ),
    (
        re.compile(rb"base64\s+-d\s*\|"),
        "base64 decode piped to command",
    ),
]


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


def _collect_entrypoint_paths(image) -> frozenset[str]:
    """
    Build the full set of paths that should be treated as entrypoints.

    Merges the static known-entrypoint list with any absolute paths
    found in the image's configured Entrypoint array. Non-path tokens
    such as flags or interpreter arguments are ignored.
    """
    config = (image.attrs or {}).get("Config") or {}
    configured = config.get("Entrypoint") or []
    custom_paths = {
        token for token in configured
        if isinstance(token, str) and token.startswith("/")
    }
    return _KNOWN_ENTRYPOINT_PATHS | custom_paths


def _normalise_path(file_path: str) -> str:
    """
    Normalise a tar entry path to an absolute Unix path string.

    Tar entries may begin with './' or lack a leading slash. This
    function strips the './' prefix when present and then ensures a
    single leading slash so path comparisons are consistent.
    """
    if file_path.startswith("./"):
        file_path = file_path[2:]
    return "/" + file_path.lstrip("/")


def _has_shell_shebang(content: bytes) -> bool:
    """
    Return True if the file content opens with a shell interpreter shebang.

    Only the first line is inspected. The check is case-insensitive and
    covers common shell variants (sh, bash, ash, dash, zsh). Files with
    Python or other non-shell shebangs are not matched.
    """
    if not content.startswith(b"#!"):
        return False
    first_line = content.split(b"\n", 1)[0].lower()
    return any(token in first_line for token in _SHELL_TOKENS)


def _classify_script_type(
    normalised_path: str,
    entrypoint_paths: frozenset[str],
) -> str:
    """
    Return 'entrypoint' if the path is a known entrypoint, else 'generic'.

    Entrypoint scripts receive higher scrutiny in the report because
    they execute automatically every time the container starts.
    """
    if normalised_path in entrypoint_paths:
        return "entrypoint"
    return "generic"


def _scan_script_content(content: bytes) -> list[dict]:
    """
    Scan script byte content line by line for dangerous patterns.

    Each line is tested against every compiled pattern. A match dict
    is appended for each (line, pattern) pair that matches. The line
    snippet is truncated to 200 bytes and decoded lossily so the
    result is always a safe string.
    """
    matches = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern, pattern_name in _DANGEROUS_PATTERNS:
            if pattern.search(line):
                matches.append({
                    "pattern": pattern_name,
                    "line_number": line_number,
                    "line_snippet": line[:200].decode(
                        "utf-8", errors="replace"
                    ),
                })
    return matches


def _collect_scripts(
    outer_tar: tarfile.TarFile,
    entrypoint_paths: frozenset[str],
) -> dict[str, tuple[bytes, str]]:
    """
    Walk all image layers and return the final state of each script.

    Docker images use a layered overlay filesystem: a file present in
    multiple layers resolves to its topmost (latest) version. This
    function processes layers in tar order (base to top) and overwrites
    earlier versions so only the final content of each script is kept.

    Returns a dict mapping normalised path → (content, script_type).
    """
    scripts: dict[str, tuple[bytes, str]] = {}

    for layer_fileobj in _get_layer_fileobjs(outer_tar):
        try:
            with tarfile.open(fileobj=layer_fileobj) as inner_tar:
                for entry in inner_tar.getmembers():
                    if not entry.isfile():
                        continue

                    normalised_path = _normalise_path(entry.name)
                    is_known_entrypoint = (
                        normalised_path in entrypoint_paths
                    )
                    has_sh_extension = normalised_path.endswith(".sh")

                    file_obj = inner_tar.extractfile(entry)
                    if file_obj is None:
                        continue

                    content = file_obj.read()

                    if not (
                        is_known_entrypoint
                        or has_sh_extension
                        or _has_shell_shebang(content)
                    ):
                        continue

                    script_type = _classify_script_type(
                        normalised_path, entrypoint_paths
                    )
                    scripts[normalised_path] = (content, script_type)

        except tarfile.TarError:
            # Malformed or empty layer tars are skipped gracefully.
            pass

    return scripts


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when script analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "script_findings": [],
        "error": error_message,
    }


def analyze_scripts(image_name: str) -> str:
    """
    Discover and scan shell scripts across all image layers for dangerous
    patterns: reverse shells, pipe-to-shell downloads, cryptominer refs,
    persistence mechanisms, obfuscation, and container escape techniques.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'script_findings' (list of {file_path, script_type,
        matches: [{pattern, line_number, line_snippet}]}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return to_toon(_build_error_result(str(exc)))

    try:
        entrypoint_paths = _collect_entrypoint_paths(image)
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            scripts = _collect_scripts(outer_tar, entrypoint_paths)
    except (tarfile.TarError, OSError) as exc:
        return to_toon(_build_error_result(str(exc)))

    findings = []
    for path, (content, script_type) in scripts.items():
        matches = _scan_script_content(content)
        if matches:
            findings.append({
                "file_path": path,
                "script_type": script_type,
                "matches": matches,
            })

    return to_toon({
        "script_findings": findings,
        "error": None,
    })
