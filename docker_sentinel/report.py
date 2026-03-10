"""
report.py — Report renderer and JSON writer for docker-sentinel.

Provides generate_report(), the single entry point called by cli.py.
Writes the FinalReport to a timestamped JSON file and, unless
--json-only is set, renders a colour-coded Rich terminal report.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from docker_sentinel.models import FinalReport

_RISK_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "green",
}

# The model sometimes returns verbose forms; normalise them to the
# canonical keys used in _RISK_COLOURS before lookup.
_RATING_ALIASES = {
    "INFORMATIONAL": "INFO",
    "INFORMATION": "INFO",
    "INFORMATIVE": "INFO",
    "MINIMAL": "LOW",
}

_console = Console()


def _safe_image_name(image_name: str) -> str:
    """Convert an image reference into a filesystem-safe string."""
    return re.sub(r"[/:.@]", "_", image_name)


def _normalise_rating(rating: str) -> str:
    """
    Normalise a risk rating string to a canonical _RISK_COLOURS key.

    Uppercases the input and resolves known model-generated aliases
    (e.g. 'Informational' → 'INFO') so colour lookups always succeed.
    """
    upper = rating.upper()
    return _RATING_ALIASES.get(upper, upper)


def _risk_colour(rating: str) -> str:
    """Return the Rich colour string for a given risk rating."""
    return _RISK_COLOURS.get(_normalise_rating(rating), "white")


def _write_json(report: FinalReport, output_dir: str) -> str:
    """
    Serialise the FinalReport to a timestamped JSON file.

    Returns the absolute path to the written file.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = (
        f"sentinel_{_safe_image_name(report.image_name)}_{timestamp}.json"
    )
    output_path = Path(output_dir) / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.model_dump(), indent=2),
        encoding="utf-8",
    )
    return str(output_path)


def _render_header(report: FinalReport) -> None:
    """Render the top-level panel with risk rating and executive summary."""
    rating = _normalise_rating(report.synthesis.risk_rating)
    colour = _risk_colour(rating)

    title = Text()
    title.append("docker-sentinel  ", style="bold")
    title.append(report.image_name, style="bold cyan")

    body = Text()
    body.append("Risk Rating:  ", style="bold")
    body.append(f"{rating}\n", style=colour)
    body.append("Scanned:      ", style="bold")
    body.append(f"{report.generated_at}\n\n", style="dim")
    body.append(report.synthesis.executive_summary)

    _console.print(Panel(body, title=title, border_style=colour))


def _render_image_profile(report: FinalReport) -> None:
    """Render the Image Profile section."""
    profile = report.profile
    _console.print(Rule("[bold]Image Profile[/bold]"))

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold dim", width=22)
    table.add_column()

    official = "Yes" if profile.is_official else "No"
    verified = "Yes" if profile.is_verified_publisher else "No"

    table.add_row("Official Image", official)
    table.add_row("Verified Publisher", verified)
    table.add_row("Publisher", profile.publisher)
    table.add_row("Pull Count", f"{profile.pull_count:,}")
    table.add_row("Layers", str(profile.layer_count))
    table.add_row(
        "Architecture", f"{profile.architecture} / {profile.os}"
    )
    size_mb = profile.size_bytes / 1_048_576
    size_str = (
        f"{profile.size_bytes / 1024:.1f} KB"
        if size_mb < 0.1
        else f"{size_mb:.1f} MB"
    )
    table.add_row("Size", size_str)
    table.add_row("Created", profile.created)
    table.add_row("Repository", profile.repository_url)
    table.add_row("Description", profile.ai_description)

    _console.print(table)
    _console.print()


def _render_secrets(report: FinalReport) -> None:
    """Render the Secrets section from TruffleHog findings."""
    secrets = report.static.secrets
    _console.print(Rule(f"[bold]Secrets ({len(secrets)})[/bold]"))

    if not secrets:
        _console.print("  [dim]No secrets detected.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold red")
    table.add_column("Detector")
    table.add_column("File Path")
    table.add_column("Redacted Snippet")

    for secret in secrets:
        table.add_row(
            secret.detector,
            secret.file_path,
            secret.redacted_snippet,
        )

    _console.print(table)
    _console.print()


def _render_script_findings(report: FinalReport) -> None:
    """Render the Script Findings section."""
    findings = report.static.script_findings
    _console.print(
        Rule(f"[bold]Script Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print(
            "  [dim]No dangerous script patterns detected.[/dim]\n"
        )
        return

    for finding in findings:
        label = (
            f"  [bold]{finding.file_path}[/bold] "
            f"[[dim]{finding.script_type}[/dim]]"
        )
        _console.print(label)
        for match in finding.matches:
            _console.print(
                f"    [yellow]L{match.line_number}[/yellow] "
                f"[red]{match.pattern}[/red]: {match.line_content}"
            )
        _console.print()


def _render_url_findings(report: FinalReport) -> None:
    """Render the URL and IP Findings section."""
    findings = report.static.url_findings
    _console.print(
        Rule(f"[bold]URL / IP Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print(
            "  [dim]No suspicious URLs or IPs detected.[/dim]\n"
        )
        return

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("URL / IP")
    table.add_column("Source")
    table.add_column("Flags")

    for finding in findings:
        table.add_row(
            finding.url,
            finding.source_file,
            ", ".join(finding.flags),
        )

    _console.print(table)
    _console.print()


def _render_env_findings(report: FinalReport) -> None:
    """Render the Environment Variable Findings section."""
    findings = report.static.env_findings
    _console.print(
        Rule(f"[bold]Env Var Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print(
            "  [dim]No credential-like env vars detected.[/dim]\n"
        )
        return

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("Key")
    table.add_column("Redacted Value")
    table.add_column("Reason")

    for finding in findings:
        table.add_row(
            finding.key, finding.value_redacted, finding.reason
        )

    _console.print(table)
    _console.print()


def _render_manifest_findings(report: FinalReport) -> None:
    """Render the Manifest Findings section."""
    findings = report.static.manifest_findings
    _console.print(
        Rule(f"[bold]Manifest Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print("  [dim]No risky packages detected.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("Manifest")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Reason")

    for finding in findings:
        table.add_row(
            finding.manifest_file,
            finding.package,
            finding.version,
            finding.reason,
        )

    _console.print(table)
    _console.print()


def _render_layer_findings(report: FinalReport) -> None:
    """Render the Layer Findings section."""
    findings = report.static.layer_findings
    _console.print(
        Rule(f"[bold]Layer Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print(
            "  [dim]No suspicious layer files detected.[/dim]\n"
        )
        return

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("File Path")
    table.add_column("Layer")
    table.add_column("Type")
    table.add_column("Mode")

    for finding in findings:
        table.add_row(
            finding.file_path,
            finding.layer_id[:12],
            finding.finding_type,
            finding.mode_octal,
        )

    _console.print(table)
    _console.print()


def _render_persistence_findings(report: FinalReport) -> None:
    """Render the Persistence Findings section."""
    findings = report.static.persistence_findings
    _console.print(
        Rule(f"[bold]Persistence Findings ({len(findings)})[/bold]")
    )

    if not findings:
        _console.print(
            "  [dim]No persistence mechanisms detected.[/dim]\n"
        )
        return

    table = Table(show_header=True, header_style="bold red")
    table.add_column("File Path")
    table.add_column("Layer", width=6)
    table.add_column("Type")
    table.add_column("Evidence")

    for finding in findings:
        table.add_row(
            finding.file_path,
            str(finding.layer_index),
            finding.persistence_type,
            finding.evidence,
        )

    _console.print(table)
    _console.print()


def _render_key_findings(report: FinalReport) -> None:
    """Render the Key Findings section as a bullet list."""
    findings = report.synthesis.key_findings
    _console.print(Rule("[bold]Key Findings[/bold]"))

    if not findings:
        _console.print("  [dim]No key findings.[/dim]\n")
        return

    for finding in findings:
        _console.print(f"  [bold yellow]*[/bold yellow] {finding}")
    _console.print()


def _render_recommendations(report: FinalReport) -> None:
    """Render the Recommendations section as a colour-coded table."""
    recommendations = report.synthesis.recommendations
    _console.print(Rule("[bold]Recommendations[/bold]"))

    if not recommendations:
        _console.print("  [dim]No recommendations.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Priority", width=10)
    table.add_column("Action")
    table.add_column("Detail")

    for rec in recommendations:
        normalised = _normalise_rating(rec.priority)
        colour = _risk_colour(rec.priority)
        table.add_row(
            Text(normalised, style=colour),
            rec.action,
            rec.detail,
        )

    _console.print(table)
    _console.print()


def _render_rich(report: FinalReport) -> None:
    """Orchestrate the full Rich terminal report rendering."""
    _render_header(report)
    _render_image_profile(report)
    _render_secrets(report)
    _render_script_findings(report)
    _render_url_findings(report)
    _render_env_findings(report)
    _render_manifest_findings(report)
    _render_layer_findings(report)
    _render_persistence_findings(report)
    _render_key_findings(report)
    _render_recommendations(report)


def generate_report(
    report: FinalReport,
    output_dir: str = ".",
    json_only: bool = False,
) -> None:
    """
    Write the FinalReport to disk and render the Rich terminal report.

    Always writes a timestamped JSON file to output_dir. Renders the
    colour-coded Rich terminal report unless json_only is True.

    Args:
        report: The assembled FinalReport from the pipeline runner.
        output_dir: Directory to write the JSON report file.
        json_only: When True, skip Rich terminal output.
    """
    json_path = _write_json(report, output_dir)

    if not json_only:
        _render_rich(report)

    _console.print(f"[dim]Report saved to: {json_path}[/dim]")
