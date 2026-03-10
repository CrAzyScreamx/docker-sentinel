"""
tools/docker_hub.py — Docker Hub API integration.

Queries the Docker Hub v2 REST API to check whether an image is an
official or verified-publisher image and retrieves basic repository
metadata. Images from other registries (ghcr.io, gcr.io, etc.) are
returned with Hub-specific fields zeroed and a correct registry URL.
"""

import re

import requests

from docker_sentinel.config import settings

from docker_sentinel.tools._toon import to_toon

# Registry hostnames that resolve to Docker Hub.
_DOCKER_HUB_REGISTRIES = {
    "",
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io",
}


def _parse_image_name(image_name: str) -> tuple[str, str, str]:
    """
    Split an image reference into (registry, namespace, repository).

    Captures the registry prefix (if present), strips tags (:tag) and
    digests (@sha256:...), and defaults the namespace to 'library' for
    single-segment names — the namespace Docker Hub uses for Official Images.

    Examples:
        "nginx"                          -> ("", "library", "nginx")
        "nginx:latest"                   -> ("", "library", "nginx")
        "grafana/grafana:10.0.0"         -> ("", "grafana", "grafana")
        "docker.io/library/nginx"        -> ("docker.io", "library", "nginx")
        "ghcr.io/owner/repo:latest"      -> ("ghcr.io", "owner", "repo")
        "gcr.io/google-containers/pause" -> ("gcr.io", "google-containers",
                                             "pause")
    """
    parts = image_name.split("/")

    registry = ""
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        image_name = "/".join(parts[1:])

    image_name = re.split(r"[:@]", image_name)[0]

    segments = image_name.split("/", 1)
    if len(segments) == 1:
        return registry, "library", segments[0]
    return registry, segments[0], segments[1]


def _is_docker_hub(registry: str) -> bool:
    """
    Return True if the registry resolves to Docker Hub.

    An empty registry string means no prefix was given, which Docker
    defaults to Hub. Explicit docker.io aliases are also included.
    """
    return registry in _DOCKER_HUB_REGISTRIES


def _build_image_url(registry: str, namespace: str, repo: str) -> str:
    """
    Return the canonical page URL for an image on its registry.

    Docker Hub official images use the /_/{repo} path convention;
    other Hub images use /r/{namespace}/{repo}. Every other registry
    gets a plain https://{registry}/{namespace}/{repo} URL.
    """
    if _is_docker_hub(registry):
        if namespace == "library":
            return f"https://hub.docker.com/_/{repo}"
        return f"https://hub.docker.com/r/{namespace}/{repo}"
    return f"https://{registry}/{namespace}/{repo}"


def _fetch_namespace_badge(namespace: str) -> str:
    """
    Fetch the trust badge for a Docker Hub namespace via the orgs endpoint.

    The /v2/orgs/{namespace}/ response carries a 'badge' field that Docker
    Hub uses to classify namespaces. Known values are 'verified_publisher',
    'open_source', or empty string for plain namespaces. The v2 repositories
    endpoint no longer exposes publisher trust fields, so this is the only
    reliable source.

    Returns an empty string on any network or HTTP error so callers can
    treat a missing badge as an unsigned namespace without crashing.
    """
    url = f"https://hub.docker.com/v2/orgs/{namespace}/"
    try:
        response = requests.get(url, timeout=settings.request_timeout)
        response.raise_for_status()
        return response.json().get("badge", "") or ""
    except requests.exceptions.RequestException:
        return ""


def _build_error_result(
    registry: str,
    namespace: str,
    repo: str,
    error_message: str,
) -> dict:
    """
    Build a safe-default result dict for when the API call fails.

    All boolean fields are False and counts are zero. The 'error' key
    contains the reason string so callers can log or surface the failure
    without crashing the pipeline.
    """
    return {
        "is_official": False,
        "is_verified_publisher": False,
        "publisher": namespace,
        "repository_url": _build_image_url(registry, namespace, repo),
        "pull_count": 0,
        "error": error_message,
    }


def check_docker_hub_status(image_name: str) -> str:
    """
    Query Docker Hub for the trust status and metadata of an image.

    Parses the image reference into registry/namespace/repo. Images from
    non-Hub registries (ghcr.io, gcr.io, etc.) are returned immediately
    with Hub-specific fields zeroed and a correct registry URL — no Hub
    API calls are made. For Hub images, calls the v2 repositories endpoint
    and the orgs endpoint to extract official/verified flags, publisher
    name, pull count, and the canonical page URL.

    Args:
        image_name: Docker image reference, e.g. "nginx:latest",
                    "grafana/grafana:10.0.0", or
                    "ghcr.io/owner/repo:latest".

    Returns:
        A dict containing:
            is_official (bool): True for Docker Official Images.
            is_verified_publisher (bool): True for Verified Publishers.
            publisher (str): Human-readable publisher name.
            repository_url (str): Canonical page URL for the image.
            pull_count (int): Total Hub pulls (0 for non-Hub images).
            error (str | None): Failure reason, or None on success.
    """
    registry, namespace, repo = _parse_image_name(image_name)

    # Non-Hub registries have no Docker Hub metadata — return immediately
    # with a correct URL for the actual registry rather than a bogus Hub URL.
    if not _is_docker_hub(registry):
        return to_toon({
            "is_official": False,
            "is_verified_publisher": False,
            "publisher": namespace,
            "repository_url": _build_image_url(registry, namespace, repo),
            "pull_count": 0,
            "error": f"Image is hosted on {registry}, not Docker Hub.",
        })

    api_url = f"{settings.docker_hub_api_base}/{namespace}/{repo}/"

    try:
        response = requests.get(api_url, timeout=settings.request_timeout)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as exc:
        error_message = (
            f"HTTP {exc.response.status_code}: {exc.response.reason}"
        )
        return to_toon(_build_error_result(registry, namespace, repo, error_message))
    except requests.exceptions.RequestException as exc:
        return to_toon(_build_error_result(registry, namespace, repo, str(exc)))

    # Docker Official Images always live in the 'library' namespace —
    # more reliable than the 'is_official' field in the API response.
    is_official = namespace == "library" or bool(
        data.get("is_official", False)
    )
    publisher = (
        "Docker Official Images"
        if is_official
        else data.get("user", namespace)
    )

    # Verified-publisher status is only exposed on the orgs endpoint via
    # the 'badge' field; the repositories endpoint no longer carries it.
    badge = _fetch_namespace_badge(namespace)
    is_verified_publisher = badge == "verified_publisher"

    return to_toon({
        "is_official": is_official,
        "is_verified_publisher": is_verified_publisher,
        "publisher": publisher,
        "repository_url": _build_image_url(registry, namespace, repo),
        "pull_count": data.get("pull_count", 0),
        "error": None,
    })
