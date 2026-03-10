"""
tools/url_extractor.py — URL and IP extraction from Docker image content.

Extracts HTTP/HTTPS URLs and bare IP addresses from three sources
within a Docker image: text and script files across every filesystem
layer, environment variable values, and image labels. Extracted
entries are then evaluated against flagging rules that highlight
suspicious characteristics such as non-standard ports, dynamic DNS
providers, and sensitive path keywords.
"""

import io
import re
import tarfile
from urllib.parse import urlparse

import docker
import docker.errors

from docker_sentinel.tools._toon import to_toon


# Byte-level patterns applied directly to file content.
_URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]+")
_IP_BYTES_PATTERN = re.compile(rb"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# String-level pattern used to check whether a URL host is a bare IP.
_BARE_IP_STR_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Ports that are unusual for legitimate services and frequently used
# by malware for C2 channels or reverse shells.
_SUSPICIOUS_PORTS = frozenset({4444, 1337, 31337, 6666, 9999, 8080, 8443})

# Domain suffixes belonging to free dynamic DNS providers that are
# commonly abused for command-and-control or data exfiltration.
_DYNAMIC_DNS_SUFFIXES = (
    ".ngrok.io",
    ".ngrok.app",
    ".duckdns.org",
    ".no-ip.com",
    ".no-ip.org",
    ".ddns.net",
    ".hopto.org",
    ".zapto.org",
    ".sytes.net",
)

# Path keywords that suggest a URL is used to fetch and execute
# remote content or deliver a payload.
_SUSPICIOUS_PATH_KEYWORDS = frozenset({
    "download", "install", "setup", "payload", "shell",
})

# File extensions that indicate a text-based file worth scanning.
_TEXT_EXTENSIONS = frozenset({
    ".sh", ".bash", ".py", ".rb", ".js", ".ts",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".conf",
    ".ini", ".env", ".txt", ".xml", ".html", ".htm",
    ".php", ".pl", ".lua", ".go", ".rs", ".java",
    ".c", ".h", ".cpp", ".cs", ".md", ".rst",
    ".sql", ".dockerfile", ".properties", ".gradle",
})

# Files larger than this are skipped to avoid memory pressure from
# large binaries that happen to be present in the image.
_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


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


def _has_text_extension(normalised_path: str) -> bool:
    """
    Return True if the file has a known text-based extension.

    The check is case-insensitive. Files with no extension return
    False here and are screened later by content inspection.
    """
    base_name = normalised_path.rsplit("/", 1)[-1].lower()
    dot_index = base_name.rfind(".")
    if dot_index == -1:
        return False
    return base_name[dot_index:] in _TEXT_EXTENSIONS


def _is_likely_text_content(content: bytes) -> bool:
    """
    Return True if the file content appears to be text rather than binary.

    Null bytes within the first 512 bytes reliably indicate binary
    content (executables, compressed archives, images). Text files
    virtually never contain null bytes.
    """
    return b"\x00" not in content[:512]


def _should_scan_entry(entry: tarfile.TarInfo) -> bool:
    """
    Return True if a layer tar entry is a candidate for URL scanning.

    Directories, symlinks, and files exceeding the size limit are
    excluded immediately. Regular files pass if they have a known text
    extension or no extension at all (e.g. Dockerfile, Makefile).
    Files with no extension undergo a content check afterwards.
    """
    if not entry.isfile():
        return False
    if entry.size > _MAX_FILE_SIZE_BYTES:
        return False
    normalised = _normalise_path(entry.name)
    base_name = normalised.rsplit("/", 1)[-1].lower()
    has_no_extension = "." not in base_name
    return _has_text_extension(normalised) or has_no_extension


def _extract_raw_matches(content: bytes) -> list[str]:
    """
    Return all URL and bare IP strings found in a byte content block.

    HTTP/HTTPS URLs are extracted first. Bare IP addresses are then
    extracted, but any IP that already appears as a substring of a
    matched URL is skipped to avoid double-reporting the same host.
    """
    url_strings = [
        m.group().decode("utf-8", errors="replace")
        for m in _URL_PATTERN.finditer(content)
    ]

    ip_strings = []
    for match in _IP_BYTES_PATTERN.finditer(content):
        ip_str = match.group().decode("utf-8", errors="replace")
        if not any(ip_str in url for url in url_strings):
            ip_strings.append(ip_str)

    return url_strings + ip_strings


def _extract_urls_from_layers(
    outer_tar: tarfile.TarFile,
) -> list[tuple[str, str]]:
    """
    Walk all image layers and collect (url_or_ip, source_path) pairs.

    Processes layers in tar order (base to top). Each qualifying text
    file is scanned for URL and IP patterns. Results are deduplicated
    by (match, source_path) so the same URL in the same file is never
    reported twice even if the file appears in multiple layers.
    """
    seen: set[tuple[str, str]] = set()
    results: list[tuple[str, str]] = []

    for member in outer_tar.getmembers():
        if not member.name.endswith("/layer.tar"):
            continue

        layer_fileobj = outer_tar.extractfile(member)
        if layer_fileobj is None:
            continue

        try:
            with tarfile.open(fileobj=layer_fileobj) as inner_tar:
                for entry in inner_tar.getmembers():
                    if not _should_scan_entry(entry):
                        continue

                    file_obj = inner_tar.extractfile(entry)
                    if file_obj is None:
                        continue

                    content = file_obj.read()
                    if not _is_likely_text_content(content):
                        continue

                    source_path = _normalise_path(entry.name)
                    for raw_match in _extract_raw_matches(content):
                        pair = (raw_match, source_path)
                        if pair not in seen:
                            seen.add(pair)
                            results.append(pair)

        except tarfile.TarError:
            pass

    return results


def _extract_urls_from_env_vars(image) -> list[tuple[str, str]]:
    """
    Extract URLs and IPs from the image's configured environment variables.

    Each KEY=VALUE string in the Env list is scanned in full so that
    URLs embedded in values (e.g. DATABASE_URL=postgres://...) are
    captured. The source identifier is set to 'config:env'.
    """
    config = (image.attrs or {}).get("Config") or {}
    env_vars = config.get("Env") or []
    results = []
    for env_string in env_vars:
        encoded = env_string.encode("utf-8", errors="replace")
        for raw_match in _extract_raw_matches(encoded):
            results.append((raw_match, "config:env"))
    return results


def _extract_urls_from_labels(image) -> list[tuple[str, str]]:
    """
    Extract URLs and IPs from the image's label key-value pairs.

    Both the label key and its value are scanned together. The source
    identifier is set to 'config:labels'.
    """
    config = (image.attrs or {}).get("Config") or {}
    labels = config.get("Labels") or {}
    results = []
    for label_key, label_value in labels.items():
        combined = f"{label_key}={label_value}"
        encoded = combined.encode("utf-8", errors="replace")
        for raw_match in _extract_raw_matches(encoded):
            results.append((raw_match, "config:labels"))
    return results


def _compute_flags(url_string: str) -> list[str]:
    """
    Evaluate a URL or IP string against all flagging rules.

    Returns a list of human-readable flag strings, one per suspicious
    characteristic found. An empty list means the entry is clean.
    Flagging rules:
      - Bare IP address (no HTTP scheme).
      - Non-standard port matching the suspicious port list.
      - Host is a raw IP address (inside an HTTP URL).
      - Host matches a free dynamic DNS provider suffix.
      - URL path contains a suspicious keyword.
    """
    flags: list[str] = []

    # Bare IPs have no scheme; flag immediately without further parsing.
    if not url_string.startswith("http"):
        flags.append("raw IP address")
        return flags

    try:
        parsed = urlparse(url_string)
    except ValueError:
        return flags

    port = parsed.port
    if port is not None and port in _SUSPICIOUS_PORTS:
        flags.append(f"non-standard port ({port})")

    domain = (parsed.hostname or "").lower()
    if _BARE_IP_STR_PATTERN.match(domain):
        flags.append("raw IP address")

    for suffix in _DYNAMIC_DNS_SUFFIXES:
        if domain.endswith(suffix):
            flags.append(
                f"dynamic DNS domain ({suffix.lstrip('.')})"
            )
            break

    path_lower = parsed.path.lower()
    for keyword in _SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path_lower:
            flags.append(f"suspicious path keyword: {keyword}")

    return flags


def _build_findings(
    raw_entries: list[tuple[str, str]],
) -> list[dict]:
    """
    Convert (url_or_ip, source_file) pairs into flagged finding dicts.

    Only entries that trigger at least one flag are included so the
    findings list stays focused on actionable items. Each finding dict
    contains 'url', 'source_file', and 'flags'.
    """
    findings = []
    for url_string, source_file in raw_entries:
        flags = _compute_flags(url_string)
        if flags:
            findings.append({
                "url": url_string,
                "source_file": source_file,
                "flags": flags,
            })
    return findings


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when URL extraction fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "url_findings": [],
        "error": error_message,
    }


def extract_urls(image_name: str) -> str:
    """
    Extract and flag suspicious HTTP/HTTPS URLs and bare IPs from image
    layers, env vars, and labels. Flags non-standard ports, raw IPs,
    dynamic DNS domains, and suspicious path keywords.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'url_findings' (list of {url, source_file, flags})
        and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return to_toon(_build_error_result(str(exc)))

    try:
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            layer_entries = _extract_urls_from_layers(outer_tar)
    except (tarfile.TarError, OSError) as exc:
        return to_toon(_build_error_result(str(exc)))

    env_entries = _extract_urls_from_env_vars(image)
    label_entries = _extract_urls_from_labels(image)

    all_entries = layer_entries + env_entries + label_entries
    findings = _build_findings(all_entries)

    return to_toon({
        "url_findings": findings,
        "error": None,
    })
