"""
tests/test_toon_revert.py — Contract tests for the _toon revert.

Verifies that all 10 public tool functions:
  1. Return a dict (not str or any other type).
  2. Return a dict with the correct top-level keys on the error path,
     with the 'error' key populated (non-None, non-empty).
  3. Return a dict with the correct top-level keys on the success path,
     with 'error' set to None.

No real Docker daemon is required — all Docker SDK calls are mocked.
"""

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# check_docker_hub_status
# ---------------------------------------------------------------------------

class TestCheckDockerHubStatus:
    """Tests for docker_hub.check_docker_hub_status."""

    EXPECTED_KEYS = {
        "is_official", "is_verified_publisher", "publisher",
        "repository_url", "pull_count", "error",
    }

    def test_returns_dict_on_http_error(self):
        """Error path via HTTPError must return a dict."""
        import requests
        from docker_sentinel.tools.docker_hub import check_docker_hub_status

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.reason = "Not Found"
        http_error = requests.exceptions.HTTPError(response=mock_response)

        with patch("docker_sentinel.tools.docker_hub.requests.get",
                   side_effect=http_error):
            result = check_docker_hub_status("nonexistent/image")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict must contain every expected top-level key."""
        import requests
        from docker_sentinel.tools.docker_hub import check_docker_hub_status

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.reason = "Internal Server Error"
        http_error = requests.exceptions.HTTPError(response=mock_response)

        with patch("docker_sentinel.tools.docker_hub.requests.get",
                   side_effect=http_error):
            result = check_docker_hub_status("someuser/somerepo")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_path_error_key_is_populated(self):
        """'error' must be a non-empty string on the error path."""
        import requests
        from docker_sentinel.tools.docker_hub import check_docker_hub_status

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.reason = "Service Unavailable"
        http_error = requests.exceptions.HTTPError(response=mock_response)

        with patch("docker_sentinel.tools.docker_hub.requests.get",
                   side_effect=http_error):
            result = check_docker_hub_status("someuser/somerepo")

        assert result["error"] is not None
        assert isinstance(result["error"], str)
        assert len(result["error"]) > 0

    def test_non_hub_registry_returns_dict_with_error_set(self):
        """ghcr.io images are returned immediately — still a dict."""
        from docker_sentinel.tools.docker_hub import check_docker_hub_status

        result = check_docker_hub_status("ghcr.io/owner/repo:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        # error is set to an explanatory string, not None
        assert result["error"] is not None

    def test_success_path_returns_dict(self):
        """Happy path: API responds 200 → dict with error=None."""
        from docker_sentinel.tools.docker_hub import check_docker_hub_status

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "is_official": True,
            "user": "library",
            "pull_count": 1_000_000,
        }

        # First call = repositories endpoint, second = orgs endpoint.
        with patch(
            "docker_sentinel.tools.docker_hub.requests.get",
            return_value=mock_response,
        ):
            result = check_docker_hub_status("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None


# ---------------------------------------------------------------------------
# extract_image_metadata
# ---------------------------------------------------------------------------

class TestExtractImageMetadata:
    """Tests for docker_meta.extract_image_metadata."""

    EXPECTED_KEYS = {
        "labels", "env_vars", "entrypoint", "cmd",
        "exposed_ports", "layer_count", "architecture",
        "os", "created", "size_bytes", "error",
    }

    def _make_docker_exception(self):
        """Return a docker.errors.DockerException instance."""
        import docker.errors
        return docker.errors.DockerException("daemon not running")

    def test_returns_dict_on_docker_error(self):
        """DockerException on from_env → dict returned."""
        from docker_sentinel.tools.docker_meta import extract_image_metadata

        with patch(
            "docker_sentinel.tools.docker_meta.docker.from_env",
            side_effect=self._make_docker_exception(),
        ):
            result = extract_image_metadata("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict must have all expected keys."""
        from docker_sentinel.tools.docker_meta import extract_image_metadata

        with patch(
            "docker_sentinel.tools.docker_meta.docker.from_env",
            side_effect=self._make_docker_exception(),
        ):
            result = extract_image_metadata("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated_on_docker_error(self):
        """'error' is non-None when Docker is unavailable."""
        from docker_sentinel.tools.docker_meta import extract_image_metadata

        with patch(
            "docker_sentinel.tools.docker_meta.docker.from_env",
            side_effect=self._make_docker_exception(),
        ):
            result = extract_image_metadata("nginx:latest")

        assert result["error"] is not None
        assert isinstance(result["error"], str)

    def test_success_path_returns_dict_with_error_none(self):
        """Happy path: image found locally → dict with error=None."""
        from docker_sentinel.tools.docker_meta import extract_image_metadata

        mock_image = MagicMock()
        mock_image.attrs = {
            "Config": {
                "Labels": {"version": "1.0"},
                "Env": ["PATH=/usr/bin"],
                "Entrypoint": ["/bin/sh"],
                "Cmd": ["-c", "echo hi"],
                "ExposedPorts": {"80/tcp": {}},
            },
            "RootFS": {"Layers": ["sha256:abc", "sha256:def"]},
            "Architecture": "amd64",
            "Os": "linux",
            "Created": "2024-01-01T00:00:00Z",
            "Size": 123456,
        }

        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.docker_meta.docker.from_env",
            return_value=mock_client,
        ):
            result = extract_image_metadata("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["layer_count"] == 2


# ---------------------------------------------------------------------------
# run_trufflehog_scan
# ---------------------------------------------------------------------------

class TestRunTrufflehogScan:
    """Tests for trufflehog_runner.run_trufflehog_scan."""

    EXPECTED_KEYS = {"secrets", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict with error populated."""
        import docker.errors
        from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan

        with patch(
            "docker_sentinel.tools.trufflehog_runner.docker.from_env",
            side_effect=docker.errors.DockerException("no socket"),
        ):
            result = run_trufflehog_scan("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict must have 'secrets' and 'error'."""
        import docker.errors
        from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan

        with patch(
            "docker_sentinel.tools.trufflehog_runner.docker.from_env",
            side_effect=docker.errors.DockerException("no socket"),
        ):
            result = run_trufflehog_scan("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_is_populated_on_failure(self):
        """'error' is non-None and non-empty on Docker failure."""
        import docker.errors
        from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan

        with patch(
            "docker_sentinel.tools.trufflehog_runner.docker.from_env",
            side_effect=docker.errors.DockerException("timeout"),
        ):
            result = run_trufflehog_scan("nginx:latest")

        assert result["error"] is not None
        assert len(result["error"]) > 0

    def test_success_path_error_is_none(self):
        """Happy path: container runs and returns empty JSONL → error=None."""
        from docker_sentinel.tools.trufflehog_runner import run_trufflehog_scan

        mock_client = MagicMock()
        mock_client.containers.run.return_value = b""

        with patch(
            "docker_sentinel.tools.trufflehog_runner.docker.from_env",
            return_value=mock_client,
        ):
            result = run_trufflehog_scan("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["secrets"] == []


# ---------------------------------------------------------------------------
# analyze_image_layers
# ---------------------------------------------------------------------------

class TestAnalyzeImageLayers:
    """Tests for layer_analyzer.analyze_image_layers."""

    EXPECTED_KEYS = {"layer_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException on from_env → dict."""
        import docker.errors
        from docker_sentinel.tools.layer_analyzer import analyze_image_layers

        with patch(
            "docker_sentinel.tools.layer_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_image_layers("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict keys must match expected set."""
        import docker.errors
        from docker_sentinel.tools.layer_analyzer import analyze_image_layers

        with patch(
            "docker_sentinel.tools.layer_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_image_layers("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.layer_analyzer import analyze_image_layers

        with patch(
            "docker_sentinel.tools.layer_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("permission denied"),
        ):
            result = analyze_image_layers("nginx:latest")

        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path with empty tar → layer_findings=[], error=None."""
        import io
        import tarfile
        from docker_sentinel.tools.layer_analyzer import analyze_image_layers

        # Build a minimal valid outer tar with no layer.tar entries.
        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w"):
            pass
        outer_buf.seek(0)

        mock_image = MagicMock()
        mock_image.save.return_value = [outer_buf.read()]
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.layer_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_image_layers("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert isinstance(result["layer_findings"], list)


# ---------------------------------------------------------------------------
# analyze_scripts
# ---------------------------------------------------------------------------

class TestAnalyzeScripts:
    """Tests for script_analyzer.analyze_scripts."""

    EXPECTED_KEYS = {"script_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict."""
        import docker.errors
        from docker_sentinel.tools.script_analyzer import analyze_scripts

        with patch(
            "docker_sentinel.tools.script_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("failed"),
        ):
            result = analyze_scripts("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict has expected keys."""
        import docker.errors
        from docker_sentinel.tools.script_analyzer import analyze_scripts

        with patch(
            "docker_sentinel.tools.script_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("failed"),
        ):
            result = analyze_scripts("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.script_analyzer import analyze_scripts

        with patch(
            "docker_sentinel.tools.script_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("failed"),
        ):
            result = analyze_scripts("nginx:latest")

        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path with empty tar → script_findings=[], error=None."""
        import io
        import tarfile
        from docker_sentinel.tools.script_analyzer import analyze_scripts

        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w"):
            pass
        outer_buf.seek(0)

        mock_image = MagicMock()
        mock_image.attrs = {"Config": {"Entrypoint": None}}
        mock_image.save.return_value = [outer_buf.read()]
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.script_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_scripts("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None


# ---------------------------------------------------------------------------
# extract_urls
# ---------------------------------------------------------------------------

class TestExtractUrls:
    """Tests for url_extractor.extract_urls."""

    EXPECTED_KEYS = {"url_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict."""
        import docker.errors
        from docker_sentinel.tools.url_extractor import extract_urls

        with patch(
            "docker_sentinel.tools.url_extractor.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = extract_urls("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict keys match expected set."""
        import docker.errors
        from docker_sentinel.tools.url_extractor import extract_urls

        with patch(
            "docker_sentinel.tools.url_extractor.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = extract_urls("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.url_extractor import extract_urls

        with patch(
            "docker_sentinel.tools.url_extractor.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = extract_urls("nginx:latest")

        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path with empty tar → url_findings=[], error=None."""
        import io
        import tarfile
        from docker_sentinel.tools.url_extractor import extract_urls

        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w"):
            pass
        outer_buf.seek(0)

        mock_image = MagicMock()
        mock_image.attrs = {"Config": {"Env": [], "Labels": {}}}
        mock_image.save.return_value = [outer_buf.read()]
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.url_extractor.docker.from_env",
            return_value=mock_client,
        ):
            result = extract_urls("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None


# ---------------------------------------------------------------------------
# analyze_env_vars
# ---------------------------------------------------------------------------

class TestAnalyzeEnvVars:
    """Tests for env_analyzer.analyze_env_vars."""

    EXPECTED_KEYS = {"env_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict."""
        import docker.errors
        from docker_sentinel.tools.env_analyzer import analyze_env_vars

        with patch(
            "docker_sentinel.tools.env_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_env_vars("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict keys match expected set."""
        import docker.errors
        from docker_sentinel.tools.env_analyzer import analyze_env_vars

        with patch(
            "docker_sentinel.tools.env_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_env_vars("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.env_analyzer import analyze_env_vars

        with patch(
            "docker_sentinel.tools.env_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_env_vars("nginx:latest")

        assert result["error"] is not None

    def test_success_path_clean_image_error_is_none(self):
        """Image with no credential vars → env_findings=[], error=None."""
        from docker_sentinel.tools.env_analyzer import analyze_env_vars

        mock_image = MagicMock()
        mock_image.attrs = {
            "Config": {"Env": ["PATH=/usr/bin", "HOME=/root"]}
        }
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.env_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_env_vars("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["env_findings"] == []

    def test_success_path_credential_var_is_flagged(self):
        """IMAGE with PASSWORD env var → finding in env_findings."""
        from docker_sentinel.tools.env_analyzer import analyze_env_vars

        mock_image = MagicMock()
        mock_image.attrs = {
            "Config": {"Env": ["DB_PASSWORD=supersecret"]}
        }
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.env_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_env_vars("nginx:latest")

        assert result["error"] is None
        assert len(result["env_findings"]) == 1
        finding = result["env_findings"][0]
        assert finding["key"] == "DB_PASSWORD"
        assert "value_redacted" in finding
        assert "reasons" in finding


# ---------------------------------------------------------------------------
# analyze_manifests
# ---------------------------------------------------------------------------

class TestAnalyzeManifests:
    """Tests for manifest_analyzer.analyze_manifests."""

    EXPECTED_KEYS = {"manifest_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict."""
        import docker.errors
        from docker_sentinel.tools.manifest_analyzer import analyze_manifests

        with patch(
            "docker_sentinel.tools.manifest_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_manifests("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict has expected keys."""
        import docker.errors
        from docker_sentinel.tools.manifest_analyzer import analyze_manifests

        with patch(
            "docker_sentinel.tools.manifest_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_manifests("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.manifest_analyzer import analyze_manifests

        with patch(
            "docker_sentinel.tools.manifest_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_manifests("nginx:latest")

        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path with empty tar → manifest_findings=[], error=None."""
        import io
        import tarfile
        from docker_sentinel.tools.manifest_analyzer import analyze_manifests

        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w"):
            pass
        outer_buf.seek(0)

        mock_image = MagicMock()
        mock_image.save.return_value = [outer_buf.read()]
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.manifest_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_manifests("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["manifest_findings"] == []


# ---------------------------------------------------------------------------
# analyze_persistence
# ---------------------------------------------------------------------------

class TestAnalyzePersistence:
    """Tests for persistence_analyzer.analyze_persistence."""

    EXPECTED_KEYS = {"persistence_findings", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException → dict."""
        import docker.errors
        from docker_sentinel.tools.persistence_analyzer import (
            analyze_persistence,
        )

        with patch(
            "docker_sentinel.tools.persistence_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_persistence("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict has expected keys."""
        import docker.errors
        from docker_sentinel.tools.persistence_analyzer import (
            analyze_persistence,
        )

        with patch(
            "docker_sentinel.tools.persistence_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_persistence("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on failure."""
        import docker.errors
        from docker_sentinel.tools.persistence_analyzer import (
            analyze_persistence,
        )

        with patch(
            "docker_sentinel.tools.persistence_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = analyze_persistence("nginx:latest")

        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path with empty tar → persistence_findings=[], error=None."""
        import io
        import tarfile
        from docker_sentinel.tools.persistence_analyzer import (
            analyze_persistence,
        )

        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w"):
            pass
        outer_buf.seek(0)

        mock_image = MagicMock()
        mock_image.save.return_value = [outer_buf.read()]
        mock_client = MagicMock()
        mock_client.images.get.return_value = mock_image

        with patch(
            "docker_sentinel.tools.persistence_analyzer.docker.from_env",
            return_value=mock_client,
        ):
            result = analyze_persistence("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["persistence_findings"] == []


# ---------------------------------------------------------------------------
# run_dynamic_analysis
# ---------------------------------------------------------------------------

class TestRunDynamicAnalysis:
    """Tests for dynamic_runner.run_dynamic_analysis."""

    EXPECTED_KEYS = {"container_id", "checks", "error"}

    def test_returns_dict_on_docker_error(self):
        """DockerException on from_env → dict."""
        import docker.errors
        from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis

        with patch(
            "docker_sentinel.tools.dynamic_runner.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = run_dynamic_analysis("nginx:latest")

        assert isinstance(result, dict)

    def test_error_path_has_correct_keys(self):
        """Error dict has 'container_id', 'checks', and 'error'."""
        import docker.errors
        from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis

        with patch(
            "docker_sentinel.tools.dynamic_runner.docker.from_env",
            side_effect=docker.errors.DockerException("no daemon"),
        ):
            result = run_dynamic_analysis("nginx:latest")

        assert self.EXPECTED_KEYS == result.keys()

    def test_error_key_populated(self):
        """'error' is non-None on Docker failure."""
        import docker.errors
        from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis

        with patch(
            "docker_sentinel.tools.dynamic_runner.docker.from_env",
            side_effect=docker.errors.DockerException("refused"),
        ):
            result = run_dynamic_analysis("nginx:latest")

        assert result["error"] is not None
        assert isinstance(result["error"], str)

    def test_container_start_failure_returns_error_dict(self):
        """DockerException on containers.run → error dict, not exception."""
        import docker.errors
        from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis

        mock_client = MagicMock()
        mock_client.images.get.return_value = MagicMock()
        mock_client.containers.run.side_effect = (
            docker.errors.DockerException("cannot start")
        )

        with patch(
            "docker_sentinel.tools.dynamic_runner.docker.from_env",
            return_value=mock_client,
        ):
            result = run_dynamic_analysis("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is not None

    def test_success_path_error_is_none(self):
        """Happy path: container starts and probes run → error=None."""
        from docker_sentinel.tools.dynamic_runner import run_dynamic_analysis

        mock_exec_result = MagicMock()
        mock_exec_result.output = b""

        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.exec_run.return_value = mock_exec_result

        mock_client = MagicMock()
        mock_client.images.get.return_value = MagicMock()
        mock_client.containers.run.return_value = mock_container

        with patch(
            "docker_sentinel.tools.dynamic_runner.docker.from_env",
            return_value=mock_client,
        ):
            result = run_dynamic_analysis("nginx:latest")

        assert isinstance(result, dict)
        assert self.EXPECTED_KEYS == result.keys()
        assert result["error"] is None
        assert result["container_id"] == "abc123"
        assert isinstance(result["checks"], list)
