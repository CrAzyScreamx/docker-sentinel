"""
tools/manifest_analyzer.py — Package manifest discovery and risk detection.

Walks every filesystem layer in a Docker image to locate known package
manifest files, parses each into (package, version) tuples, and then
applies per-ecosystem detection rules to flag risky dependencies:
typosquatted or confirmed-malicious names, unpinned version specifiers,
and packages pinned to known-vulnerable version ranges.
"""

import io
import json
import re
import tarfile
import tomllib

import docker
import docker.errors


# ---------------------------------------------------------------------------
# Manifest identification
# ---------------------------------------------------------------------------

# Maps a manifest file's base name to its ecosystem label.
# System manifests identified by full path are handled separately.
_MANIFEST_BASENAMES: dict[str, str] = {
    "requirements.txt": "python",
    "Pipfile": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "package.json": "node",
    "yarn.lock": "node",
    "package-lock.json": "node",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
}

# Full normalised paths for system package database files.
_SYSTEM_MANIFEST_PATHS: dict[str, str] = {
    "/var/lib/dpkg/status": "debian",
    "/var/lib/rpm/Packages": "rpm",
}


# ---------------------------------------------------------------------------
# Risk data
# ---------------------------------------------------------------------------

# Python packages confirmed or widely reported as malicious/typosquats.
# Keys are lowercase-normalised (hyphens); values are reason strings.
_PYTHON_RISKY_PACKAGES: dict[str, str] = {
    "colourama":        "typosquat of 'colorama' — known malicious",
    "request":          "typosquat of 'requests'",
    "urlib3":           "typosquat of 'urllib3'",
    "urllib":           "typosquat of 'urllib3'",
    "setup-tools":      "typosquat of 'setuptools'",
    "python-openssl":   "typosquat of 'pyOpenSSL'",
    "diango":           "typosquat of 'django'",
    "matploltib":       "typosquat of 'matplotlib'",
    "pyton-dateutil":   "typosquat of 'python-dateutil'",
    "python3-dateutil": "typosquat of 'python-dateutil'",
    "jeIlyfish":        "known malicious obfuscated package",
    "acqusition":       "known malicious package",
    "apidev-coop":      "known malicious package",
    "bzip":             "known malicious package",
    "crypt":            "abandoned/suspicious package",
}

# (package_lower, min_safe_version, cve_description).
# A package is flagged when pinned to a version strictly below min_safe.
_PYTHON_VULNERABLE_VERSIONS: list[tuple[str, str, str]] = [
    ("requests",    "2.20.0", "CVE-2018-18074: credential exposure"),
    ("pillow",      "8.3.0",  "multiple CVEs: buffer overflow, DoS"),
    ("django",      "2.2.24", "multiple CVEs: XSS, SQL injection"),
    ("cryptography","3.3.2",  "CVE-2020-36242: memory corruption"),
    ("pyyaml",      "5.4",    "CVE-2020-14343: arbitrary code exec"),
    ("jinja2",      "2.11.3", "CVE-2020-28493: ReDoS"),
    ("paramiko",    "2.7.2",  "CVE-2018-7750: auth bypass"),
    ("urllib3",     "1.26.5", "CVE-2021-33503: ReDoS"),
    ("lxml",        "4.6.3",  "CVE-2021-28957: XSS"),
]

# Node packages confirmed as malicious or highly suspicious.
_NODE_RISKY_PACKAGES: dict[str, str] = {
    "crossenv":              "known malicious package",
    "flatmap-stream":        "known targeted supply-chain attack",
    "eslint-scope":          "compromised in 2018 (backdoor)",
    "getcookies":            "known malicious package",
    "event-source-polyfill": "known malicious version",
    "bb-builder":            "known malicious package",
    "d3.js":                 "typosquat of 'd3'",
    "jquery.js":             "typosquat of 'jquery'",
    "mongose":               "typosquat of 'mongoose'",
}

# Version strings that mean "any version" in Node manifests.
_NODE_UNPINNED_SPECS: frozenset[str] = frozenset({"*", "latest", ""})


# ---------------------------------------------------------------------------
# Utility helpers
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


def _normalise_package_name(name: str) -> str:
    """
    Normalise a package name for case-insensitive lookup.

    Lowercases and replaces underscores with hyphens to match the
    canonical forms used in the risky-package lookup tables.
    """
    return name.lower().replace("_", "-")


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """
    Parse a dotted version string into a comparable integer tuple.

    Non-numeric leading segments (e.g. 'rc1', 'post2') are truncated
    to their numeric prefix so comparisons still work for pre-releases.
    """
    parts = []
    for segment in version_str.split("."):
        numeric = re.match(r"\d+", segment)
        parts.append(int(numeric.group()) if numeric else 0)
    return tuple(parts)


def _is_version_below(version_str: str, threshold: str) -> bool:
    """
    Return True if version_str is strictly less than threshold.

    Uses integer-tuple comparison after splitting on '.'. Returns False
    for empty or non-parseable strings to avoid false positives.
    """
    if not version_str:
        return False
    return (
        _parse_version_tuple(version_str)
        < _parse_version_tuple(threshold)
    )


# ---------------------------------------------------------------------------
# Manifest parsers — each returns list[tuple[str, str]] (name, version)
# ---------------------------------------------------------------------------

def _parse_requirements_txt(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a requirements.txt file into (package, version_spec) tuples.

    Handles pinned (==), ranged (>=, <=, ~=), and unpinned entries.
    Comment lines, blank lines, and pip directives (-r, -c, -e) are
    skipped. The version is the raw specifier string (e.g. '==1.2.3')
    or an empty string for entries with no version constraint.
    """
    entry_re = re.compile(
        r"^([A-Za-z0-9_\-\.]+)\s*"
        r"((?:[><=!~]{1,2}\s*[\w\.\*]+"
        r"(?:\s*,\s*[><=!~]{1,2}\s*[\w\.\*]+)*))?"
    )
    packages = []
    text = content.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip().split("#")[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        match = entry_re.match(stripped)
        if match and match.group(1):
            packages.append((match.group(1), (match.group(2) or "").strip()))
    return packages


def _parse_pipfile(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a Pipfile into (package, version) tuples using tomllib.

    Reads the [packages] and [dev-packages] tables. Falls back to a
    regex scan if the file is not valid TOML (e.g. uses Pipfile-
    specific syntax extensions that break strict parsing).
    """
    text = content.decode("utf-8", errors="replace")
    try:
        data = tomllib.loads(text)
        packages = []
        for section in ("packages", "dev-packages"):
            deps = data.get(section) or {}
            for name, version in deps.items():
                ver = version if isinstance(version, str) else ""
                packages.append((name, ver))
        return packages
    except tomllib.TOMLDecodeError:
        pass

    # Regex fallback for non-standard Pipfiles.
    entry_re = re.compile(
        r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']([^"\']*)["\']'
    )
    return [
        (m.group(1), m.group(2))
        for line in text.splitlines()
        if (m := entry_re.match(line.strip()))
    ]


def _parse_pyproject_toml(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a pyproject.toml file into (package, version_spec) tuples.

    Handles both PEP 517 [project.dependencies] string lists and
    Poetry [tool.poetry.dependencies] / [tool.poetry.dev-dependencies]
    tables. Returns an empty list if the file is not valid TOML.
    """
    text = content.decode("utf-8", errors="replace")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    packages = []
    dep_name_re = re.compile(
        r"^([A-Za-z0-9_\-\.]+)\s*([><=!~][^\s;]*)?"
    )

    # PEP 517: [project.dependencies] is a list of PEP 508 strings.
    project_deps = (data.get("project") or {}).get("dependencies") or []
    for dep_string in project_deps:
        match = dep_name_re.match(str(dep_string))
        if match:
            packages.append((match.group(1), match.group(2) or ""))

    # Poetry: dependencies are dicts with name → version string.
    poetry = (data.get("tool") or {}).get("poetry") or {}
    poetry_sections = [
        "dependencies",
        "dev-dependencies",
        "group.dev.dependencies",
    ]
    for section_key in poetry_sections:
        deps = poetry.get(section_key) or {}
        for name, version in deps.items():
            if name.lower() == "python":
                continue
            ver = version if isinstance(version, str) else ""
            packages.append((name, ver))

    return packages


def _parse_package_json(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a package.json file into (package, version_spec) tuples.

    Reads both 'dependencies' and 'devDependencies' objects. Returns
    an empty list if the file is not valid JSON or lacks both keys.
    """
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    packages = []
    for section_key in ("dependencies", "devDependencies"):
        section = data.get(section_key) or {}
        if isinstance(section, dict):
            for name, version in section.items():
                packages.append((name, str(version)))
    return packages


def _parse_yarn_lock(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a yarn.lock file into (package, resolved_version) tuples.

    Extracts package names from header lines and resolved versions from
    the 'version "x.y.z"' lines that follow. Only the first resolution
    of each package name is kept to avoid duplicates from multi-range
    entries in the same lockfile.
    """
    text = content.decode("utf-8", errors="replace")
    header_re = re.compile(r'^"?(@?[A-Za-z0-9_\-\./]+)@', re.MULTILINE)
    version_re = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)

    headers = list(header_re.finditer(text))
    versions = list(version_re.finditer(text))

    seen: dict[str, str] = {}
    for header, version in zip(headers, versions):
        name = header.group(1)
        if name not in seen:
            seen[name] = version.group(1)

    return list(seen.items())


def _parse_package_lock_json(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a package-lock.json file into (package, version) tuples.

    Supports lockfile v2/v3 ('packages' flat object keyed by
    'node_modules/name') and v1 ('dependencies' nested object).
    Returns an empty list on parse errors.
    """
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    # v2/v3: flat 'packages' object.
    lock_packages = data.get("packages") or {}
    if lock_packages:
        packages = []
        for path_key, meta in lock_packages.items():
            if not path_key or not isinstance(meta, dict):
                continue
            name = path_key.replace("node_modules/", "").strip("/")
            if name:
                packages.append((name, meta.get("version", "")))
        return packages

    # v1: nested 'dependencies' object.
    dependencies = data.get("dependencies") or {}
    return [
        (name, meta.get("version", ""))
        for name, meta in dependencies.items()
        if isinstance(meta, dict)
    ]


def _parse_gemfile(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a Gemfile into (gem_name, version_constraint) tuples.

    Matches 'gem "name"' and 'gem "name", "version"' lines in both
    single and double quote variants. Version is empty when not given.
    """
    text = content.decode("utf-8", errors="replace")
    gem_re = re.compile(
        r"""gem\s+['"]([A-Za-z0-9_\-\.]+)['"]\s*"""
        r"""(?:,\s*['"]([^'"]*)['"]\s*)?"""
    )
    return [
        (m.group(1), m.group(2) or "")
        for m in gem_re.finditer(text)
    ]


def _parse_gemfile_lock(content: bytes) -> list[tuple[str, str]]:
    """
    Parse a Gemfile.lock into (gem_name, version) tuples.

    Reads the GEM specs section where resolved gems appear as
    '    name (version)' lines. The fixed four-space indent
    distinguishes top-level gem entries from their sub-dependencies.
    """
    text = content.decode("utf-8", errors="replace")
    spec_re = re.compile(
        r"^    ([A-Za-z0-9_\-\.]+)\s+\(([^\)]+)\)\s*$",
        re.MULTILINE,
    )
    return [
        (m.group(1), m.group(2))
        for m in spec_re.finditer(text)
    ]


def _parse_dpkg_status(content: bytes) -> list[tuple[str, str]]:
    """
    Parse /var/lib/dpkg/status into (package, version) tuples.

    The file contains stanzas separated by blank lines. Each stanza
    holds key-value pairs; only 'Package' and 'Version' are extracted.
    Entries not in the 'installed' state are skipped.
    """
    text = content.decode("utf-8", errors="replace")
    packages = []
    for stanza in text.split("\n\n"):
        pkg_name = ""
        pkg_version = ""
        is_installed = False
        for line in stanza.splitlines():
            if line.startswith("Package:"):
                pkg_name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                pkg_version = line.split(":", 1)[1].strip()
            elif line.startswith("Status:") and "installed" in line:
                is_installed = True
        if pkg_name and pkg_version and is_installed:
            packages.append((pkg_name, pkg_version))
    return packages


# Dispatch table: base filename → parser function.
# Defined after all parser functions to allow direct references.
_PARSERS = {
    "requirements.txt":  _parse_requirements_txt,
    "Pipfile":           _parse_pipfile,
    "pyproject.toml":    _parse_pyproject_toml,
    "package.json":      _parse_package_json,
    "yarn.lock":         _parse_yarn_lock,
    "package-lock.json": _parse_package_lock_json,
    "Gemfile":           _parse_gemfile,
    "Gemfile.lock":      _parse_gemfile_lock,
    "status":            _parse_dpkg_status,
}


def _parse_manifest(
    normalised_path: str,
    content: bytes,
) -> list[tuple[str, str]]:
    """
    Dispatch content to the appropriate parser based on the file path.

    Returns a list of (package, version) tuples, or an empty list if
    no parser is registered for the given base name (e.g. RPM binary
    database files are skipped because they require a native library).
    """
    base_name = normalised_path.rsplit("/", 1)[-1]
    parser = _PARSERS.get(base_name)
    if parser is None:
        return []
    try:
        return parser(content)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Risk detectors
# ---------------------------------------------------------------------------

def _check_python_package(
    name: str,
    version_spec: str,
) -> list[str]:
    """
    Return a list of risk reasons for a Python package entry.

    Two checks are applied:
      1. Known-risky name: typosquatted or confirmed-malicious packages.
      2. Pinned vulnerable version: only exact '==' specifiers are
         compared against the minimum-safe-version table.
    """
    reasons = []
    normalised_name = _normalise_package_name(name)

    risky_reason = _PYTHON_RISKY_PACKAGES.get(normalised_name)
    if risky_reason:
        reasons.append(risky_reason)

    # Unpinned specs cannot be evaluated against a version threshold.
    if version_spec.startswith("=="):
        pinned_version = version_spec[2:].strip()
        for pkg, min_safe, cve_desc in _PYTHON_VULNERABLE_VERSIONS:
            if normalised_name == pkg and _is_version_below(
                pinned_version, min_safe
            ):
                reasons.append(
                    f"pinned version {pinned_version} is below safe "
                    f"minimum {min_safe} — {cve_desc}"
                )

    return reasons


def _check_node_package(
    name: str,
    version_spec: str,
) -> list[str]:
    """
    Return a list of risk reasons for a Node.js package entry.

    Two checks are applied:
      1. Known-risky name: malicious or typosquatted npm packages.
      2. Unpinned version: '*', 'latest', or empty string allow
         arbitrary future versions to be installed at build time.
    """
    reasons = []
    normalised_name = _normalise_package_name(name)

    risky_reason = _NODE_RISKY_PACKAGES.get(normalised_name)
    if risky_reason:
        reasons.append(risky_reason)

    cleaned_spec = version_spec.strip().lower()
    if cleaned_spec in _NODE_UNPINNED_SPECS:
        reasons.append(
            f"unpinned version spec '{version_spec}' — arbitrary "
            "future versions can be installed"
        )

    return reasons


def _build_package_findings(
    packages: list[tuple[str, str]],
    manifest_file: str,
    ecosystem: str,
) -> list[dict]:
    """
    Run ecosystem-appropriate risk checks and return finding dicts.

    Only packages that produce at least one reason are included. Each
    finding records the manifest path, package name, version spec, and
    the list of reasons it was flagged.
    """
    findings = []
    for name, version in packages:
        if not name:
            continue

        if ecosystem == "python":
            reasons = _check_python_package(name, version)
        elif ecosystem == "node":
            reasons = _check_node_package(name, version)
        else:
            reasons = []

        if reasons:
            findings.append({
                "manifest_file": manifest_file,
                "package": name,
                "version": version or "unspecified",
                "reasons": reasons,
            })

    return findings


# ---------------------------------------------------------------------------
# Layer walker
# ---------------------------------------------------------------------------

def _identify_manifest_ecosystem(normalised_path: str) -> str | None:
    """
    Return the ecosystem label for a path, or None if not a manifest.

    Exact system paths are checked first; all other files are matched
    by base filename against the known manifest basename table.
    """
    if normalised_path in _SYSTEM_MANIFEST_PATHS:
        return _SYSTEM_MANIFEST_PATHS[normalised_path]
    base_name = normalised_path.rsplit("/", 1)[-1]
    return _MANIFEST_BASENAMES.get(base_name)


def _collect_manifests(
    outer_tar: tarfile.TarFile,
) -> dict[str, tuple[bytes, str]]:
    """
    Walk all image layers and return the final content of each manifest.

    Later layers overwrite earlier ones, matching Docker overlay FS
    behaviour. Files inside 'node_modules' directories are excluded to
    avoid processing thousands of transitive dependency manifests.

    Returns a dict mapping normalised path → (content_bytes, ecosystem).
    """
    manifests: dict[str, tuple[bytes, str]] = {}

    for member in outer_tar.getmembers():
        if not member.name.endswith("/layer.tar"):
            continue

        layer_fileobj = outer_tar.extractfile(member)
        if layer_fileobj is None:
            continue

        try:
            with tarfile.open(fileobj=layer_fileobj) as inner_tar:
                for entry in inner_tar.getmembers():
                    if not entry.isfile():
                        continue

                    normalised_path = _normalise_path(entry.name)
                    if "node_modules" in normalised_path:
                        continue

                    ecosystem = _identify_manifest_ecosystem(
                        normalised_path
                    )
                    if ecosystem is None:
                        continue

                    file_obj = inner_tar.extractfile(entry)
                    if file_obj is None:
                        continue

                    manifests[normalised_path] = (
                        file_obj.read(), ecosystem
                    )

        except tarfile.TarError:
            pass

    return manifests


# ---------------------------------------------------------------------------
# Error result and public API
# ---------------------------------------------------------------------------

def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when manifest analysis fails.

    Returns an empty findings list and carries the failure reason in
    the 'error' key so the pipeline can continue and surface the issue.
    """
    return {
        "manifest_findings": [],
        "error": error_message,
    }


def analyze_manifests(image_name: str) -> dict:
    """
    Detect risky packages in Python, Node, Ruby, and Debian manifests found
    across image layers: typosquats, known-malicious names, vulnerable pinned
    versions, and unpinned Node dependencies. Only flagged packages returned.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        dict with 'manifest_findings' (list of {manifest_file, package,
        version, reasons}) and 'error'.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return (_build_error_result(str(exc)))

    try:
        image_bytes = _reassemble_image_bytes(image)
        with tarfile.open(fileobj=image_bytes) as outer_tar:
            manifests = _collect_manifests(outer_tar)
    except (tarfile.TarError, OSError) as exc:
        return (_build_error_result(str(exc)))

    all_findings = []
    for normalised_path, (content, ecosystem) in manifests.items():
        packages = _parse_manifest(normalised_path, content)
        findings = _build_package_findings(
            packages, normalised_path, ecosystem
        )
        all_findings.extend(findings)

    return ({
        "manifest_findings": all_findings,
        "error": None,
    })
