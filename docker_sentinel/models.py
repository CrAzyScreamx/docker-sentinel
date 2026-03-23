"""
Data model schemas for docker-sentinel.

All models are Pydantic BaseModels with extra="forbid", which causes
Pydantic to emit additionalProperties: false in JSON Schema output.
Anthropic's API requires this on every object type when using structured
output. Models flow through ADK session state between agents via
.model_dump() / .model_validate().
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


# Shared config applied to every model so Anthropic's structured-output
# validation receives additionalProperties: false on all object schemas.
_STRICT = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Agent 1 output
# ---------------------------------------------------------------------------

class ImageProfile(BaseModel):
    """
    Describes the identity and configuration of a Docker image.

    Produced by the Image Profiler agent after calling Docker Hub and
    the Docker daemon. Stored in session state as 'image_profile'.
    """

    model_config = _STRICT

    image_name: str
    is_official: bool
    is_verified_publisher: bool
    publisher: str
    repository_url: str
    pull_count: int
    labels: list[str]           # "KEY=VALUE" strings, same format as env_vars
    env_vars: list[str]
    entrypoint: list[str]
    cmd: list[str]
    exposed_ports: list[str]
    layer_count: int
    architecture: str
    os: str
    created: str
    size_bytes: int


# ---------------------------------------------------------------------------
# Agent 2 sub-types
# ---------------------------------------------------------------------------

class SecretFinding(BaseModel):
    """A single secret or credential detected by TruffleHog."""

    model_config = _STRICT

    detector: str
    file_path: str
    line_number: int
    redacted_snippet: str


class MatchEntry(BaseModel):
    """A single dangerous pattern match inside a script file."""

    model_config = _STRICT

    pattern: str
    line_number: int
    line_content: str


class ScriptFinding(BaseModel):
    """
    Dangerous pattern detected inside a shell script or entrypoint file.

    Each match records the pattern name, the line number, and the raw
    line content so the synthesiser can quote it in its report.
    """

    model_config = _STRICT

    file_path: str
    script_type: str        # "entrypoint" | "generic"
    matches: list[MatchEntry]


class UrlFinding(BaseModel):
    """A URL or IP address extracted from the image that raised flags."""

    model_config = _STRICT

    url: str
    source_file: str
    flags: list[str]


class EnvFinding(BaseModel):
    """An environment variable whose key or value resembles a secret."""

    model_config = _STRICT

    key: str
    value_redacted: str     # first 4 chars + "***"
    reason: str


class ManifestFinding(BaseModel):
    """A package in a baked-in manifest that is risky or suspicious."""

    model_config = _STRICT

    manifest_file: str
    package: str
    version: str
    reason: str


class LayerFinding(BaseModel):
    """A file in an image layer with a suspicious permission bit or name."""

    model_config = _STRICT

    file_path: str
    layer_id: str
    finding_type: str       # "suid" | "sgid" | "hidden_file"
    mode_octal: str


class PersistenceFinding(BaseModel):
    """
    A file associated with a known persistence mechanism.

    Detected by walking image layers and matching paths against known
    persistence locations: cron, init scripts, systemd units, LD_PRELOAD
    hooks, shell profile backdoors, and SSH authorized_keys files.
    """

    model_config = _STRICT

    file_path: str
    layer_index: int
    persistence_type: str   # "cron" | "init" | "systemd" | "ld_preload"
                            # | "shell_profile" | "ssh_authorized_keys"
    evidence: str


class HistoryFinding(BaseModel):
    """A suspicious pattern detected in an image build-layer command."""

    model_config = _STRICT

    layer_index: int
    command_snippet: str    # first 200 chars of CreatedBy
    pattern_matched: str    # e.g. "curl pipe-to-shell"


class CapabilityFinding(BaseModel):
    """A privilege or capability issue detected in the image configuration."""

    model_config = _STRICT

    finding_type: str       # "runs_as_root" | "privileged_port"
                            # | "privileged_label" | "setcap_in_script"
    evidence: str
    detail: str


# ---------------------------------------------------------------------------
# Agent 2 output
# ---------------------------------------------------------------------------

class StaticFindings(BaseModel):
    """
    Aggregated results from all seven static analysis tools.

    Produced by the Static Scanner agent. Stored in session state as
    'static_findings'.
    """

    model_config = _STRICT

    secrets: list[SecretFinding]
    script_findings: list[ScriptFinding]
    url_findings: list[UrlFinding]
    env_findings: list[EnvFinding]
    manifest_findings: list[ManifestFinding]
    layer_findings: list[LayerFinding]
    persistence_findings: list[PersistenceFinding]
    history_findings: list[HistoryFinding]
    capability_findings: list[CapabilityFinding]


# ---------------------------------------------------------------------------
# Agent 3 sub-types and output
# ---------------------------------------------------------------------------

class ProbeResult(BaseModel):
    """Flagged anomalies from a single dynamic probe."""

    model_config = _STRICT

    probe: str              # "ps_aux" | "suid_files" | "env_vars" | "crontab"
    anomalies: list[str]


class DynamicFindings(BaseModel):
    """
    Results from running isolated runtime probes against the image.

    Produced by the Dynamic Scanner agent. Stored in session state as
    'dynamic_findings'.
    """

    model_config = _STRICT

    container_id: str
    checks: list[ProbeResult]


# ---------------------------------------------------------------------------
# M13 agent output types
# ---------------------------------------------------------------------------

class URLVerdict(BaseModel):
    """Classification of a single URL extracted from the image."""

    model_config = _STRICT

    url: str
    verdict: str            # "Safe" | "Not Safe"
    reason: str


class URLValidationReport(BaseModel):
    """Aggregated URL verdicts produced by the URL Validator agent."""

    model_config = _STRICT

    verdicts: list[URLVerdict]


class ScoredFinding(BaseModel):
    """A single finding with an LLM-assigned risk score."""

    model_config = _STRICT

    source: str             # e.g. "script_analyzer", "trufflehog"
    description: str
    score: int              # 1–10
    rationale: str


class ScoringReport(BaseModel):
    """All scored findings produced by the Scorer agent."""

    model_config = _STRICT

    scored_findings: list[ScoredFinding]
    adjustment_note: str | None = None


class RaterReport(BaseModel):
    """Final rating and plain-English summary produced by the Rater agent."""

    model_config = _STRICT

    final_rating: str       # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    summary: str            # one plain-English sentence


# ---------------------------------------------------------------------------
# Agent 4 sub-types and output  (DEPRECATED — superseded by M13 pipeline)
# ---------------------------------------------------------------------------

# DEPRECATED
class Recommendation(BaseModel):
    """A single prioritised remediation recommendation."""

    model_config = _STRICT

    priority: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    action: str
    detail: str


# DEPRECATED
class SynthesisReport(BaseModel):
    """
    Final risk assessment synthesised from all three prior agent outputs.

    Produced by the Synthesizer agent. Stored in session state as
    'synthesis_report'.
    """

    model_config = _STRICT

    risk_rating: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    risk_rationale: str
    key_findings: list[str]
    recommendations: list[Recommendation]
    executive_summary: str


# ---------------------------------------------------------------------------
# Final assembled report v2 (built by runner.py)
# ---------------------------------------------------------------------------

class FinalReport(BaseModel):
    """
    Top-level report assembled by runner.py from the M13 pipeline.

    Written to disk as JSON and rendered to the terminal by report.py.
    Schema version 2.0.0 — replaces the old static/dynamic/synthesis layout.
    """

    model_config = _STRICT

    schema_version: str
    generated_at: str
    image_name: str
    profile: ImageProfile
    url_verdicts: list[URLVerdict]
    scored_findings: list[ScoredFinding]
    final_rating: str
    summary: str


# ---------------------------------------------------------------------------
# M15 — raw findings report (no LLM; used by --raw-findings and skills)
# ---------------------------------------------------------------------------

class RawFindings(BaseModel):
    """
    Raw tool output collected without any LLM processing.

    Written to disk by run_raw_findings() when --raw-findings is passed.
    Consumed by Claude Code skills which perform their own LLM analysis
    using Claude Code's own model access instead of a user API key.

    Keys in `static`: trufflehog, layer, scripts, urls, env, manifests,
    persistence, history, capabilities.
    `dynamic` is the full dict returned by run_dynamic_analysis().
    """

    schema_version: str
    generated_at: str
    image_name: str
    static: dict
    dynamic: dict
