"""
tools/docker_meta.py — Docker daemon metadata extraction.

Uses the Docker SDK to inspect a local or remote image, pulling it first
if it is not already present, and returns structured metadata from the
image's Config and RootFS attributes.
"""

import docker
import docker.errors

def _get_or_pull_image(
    client: docker.DockerClient,
    image_name: str,
):
    """
    Return the local image object, pulling from the registry if absent.

    Tries to retrieve the image from the local Docker daemon first. If
    it is not found locally, pulls it from the registry before returning.
    Raises docker.errors.APIError if the pull fails.
    """
    try:
        return client.images.get(image_name)
    except docker.errors.ImageNotFound:
        return client.images.pull(image_name)


def _extract_config_fields(config: dict) -> dict:
    """
    Pull the relevant fields out of an image's Config attribute dict.

    Handles None values that the Docker daemon may return for optional
    fields (Entrypoint, Cmd, ExposedPorts, Labels) by substituting safe
    empty defaults so callers never receive None.
    """
    return {
        "labels": config.get("Labels") or {},
        "env_vars": config.get("Env") or [],
        "entrypoint": config.get("Entrypoint") or [],
        "cmd": config.get("Cmd") or [],
        "exposed_ports": list(config.get("ExposedPorts") or {}),
    }


def _build_error_result(error_message: str) -> dict:
    """
    Build a safe-default result dict for when metadata extraction fails.

    All collection fields are empty and numeric fields are zero. The
    'error' key contains the reason string so callers can surface the
    failure without crashing the pipeline.
    """
    return {
        "labels": {},
        "env_vars": [],
        "entrypoint": [],
        "cmd": [],
        "exposed_ports": [],
        "layer_count": 0,
        "architecture": "",
        "os": "",
        "created": "",
        "size_bytes": 0,
        "error": error_message,
    }


def extract_image_metadata(image_name: str) -> dict:
    """
    Extract runtime metadata from a Docker image via the Docker SDK.

    Connects to the local Docker daemon, pulling the image first if it
    is not already present, then reads Config (labels, env vars,
    entrypoint, cmd, exposed ports) and top-level attributes
    (architecture, OS, creation timestamp, size, layer count).

    Args:
        image_name: Docker image reference, e.g. "nginx:latest".

    Returns:
        A dict containing:
            labels (dict[str, str]): Image labels.
            env_vars (list[str]): Env variables as KEY=VALUE strings.
            entrypoint (list[str]): Entrypoint command and arguments.
            cmd (list[str]): Default command and arguments.
            exposed_ports (list[str]): Declared exposed port strings.
            layer_count (int): Number of filesystem layers.
            architecture (str): CPU architecture (e.g. "amd64").
            os (str): Operating system (e.g. "linux").
            created (str): ISO 8601 creation timestamp.
            size_bytes (int): Uncompressed image size in bytes.
            error (str | None): Failure reason, or None on success.
    """
    try:
        client = docker.from_env()
        image = _get_or_pull_image(client, image_name)
    except docker.errors.DockerException as exc:
        return (_build_error_result(str(exc)))

    try:
        attrs = image.attrs
        config = attrs.get("Config") or {}
        layers = (attrs.get("RootFS") or {}).get("Layers") or []

        result = _extract_config_fields(config)
        result.update({
            "layer_count": len(layers),
            "architecture": attrs.get("Architecture", ""),
            "os": attrs.get("Os", ""),
            "created": attrs.get("Created", ""),
            "size_bytes": attrs.get("Size", 0),
            "error": None,
        })
        return (result)
    except Exception as exc:
        return (_build_error_result(str(exc)))
