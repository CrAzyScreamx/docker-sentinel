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


def _risk_colour_for_score(score: int) -> str:
    """Return the Rich colour string for a numeric risk score (1–10)."""
    if score >= 9:
        return "bold red"
    if score >= 7:
        return "red"
    if score >= 5:
        return "yellow"
    if score >= 3:
        return "cyan"
    return "green"


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
    rating = _normalise_rating(report.final_rating)
    colour = _risk_colour(rating)

    title = Text()
    title.append("docker-sentinel  ", style="bold")
    title.append(report.image_name, style="bold cyan")

    body = Text()
    body.append("Risk Rating:  ", style="bold")
    body.append(f"{rating}\n", style=colour)
    body.append("Scanned:      ", style="bold")
    body.append(f"{report.generated_at}\n\n", style="dim")
    body.append(report.summary)

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

    _console.print(table)
    _console.print()


def _render_url_verdicts(report: FinalReport, detailed: bool) -> None:
    """
    Render the URL Verdicts section.

    Shows a Rich table with URL, Verdict, and Reason columns. Verdict
    cells are styled green for Safe and red for Not Safe. The detailed
    flag is accepted for API consistency but all columns are always
    shown. Prints a dim placeholder if no verdicts are present.
    """
    verdicts = report.url_verdicts
    _console.print(Rule("[bold]URL Verdicts[/bold]"))

    if not verdicts:
        _console.print("  [dim]No flagged URLs.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("URL")
    table.add_column("Verdict", width=10)
    table.add_column("Reason")

    for verdict in verdicts:
        verdict_style = "green" if verdict.verdict == "Safe" else "red"
        table.add_row(
            verdict.url,
            Text(verdict.verdict, style=verdict_style),
            verdict.reason,
        )

    _console.print(table)
    _console.print()


def _render_scored_findings(
    report: FinalReport,
    detailed: bool,
) -> None:
    """
    Render the Scored Findings section, sorted by score descending.

    Default mode shows Source, Score, and Description. When detailed
    is True, an additional Rationale column is appended. Score cells
    are colour-coded with _risk_colour_for_score.
    """
    findings = sorted(
        report.scored_findings, key=lambda f: f.score, reverse=True
    )
    _console.print(Rule("[bold]Scored Findings[/bold]"))

    if not findings:
        _console.print("  [dim]No findings scored.[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Source", width=20)
    table.add_column("Score", width=6)
    table.add_column("Description")
    if detailed:
        table.add_column("Rationale")

    for finding in findings:
        score_text = Text(
            str(finding.score),
            style=_risk_colour_for_score(finding.score),
        )
        row = [finding.source, score_text, finding.description]
        if detailed:
            row.append(finding.rationale)
        table.add_row(*row)

    _console.print(table)
    _console.print()


def _render_rich(report: FinalReport, detailed: bool = False) -> None:
    """Orchestrate the full Rich terminal report rendering."""
    _render_header(report)
    _render_image_profile(report)
    _render_url_verdicts(report, detailed)
    _render_scored_findings(report, detailed)


def generate_report(
    report: FinalReport,
    output_dir: str = ".",
    json_only: bool = False,
    detailed: bool = False,
) -> None:
    """
    Write the FinalReport to disk and render the Rich terminal report.

    Always writes a timestamped JSON file to output_dir. Renders the
    colour-coded Rich terminal report unless json_only is True.

    Args:
        report: The assembled FinalReport from the pipeline runner.
        output_dir: Directory to write the JSON report file.
        json_only: When True, skip Rich terminal output.
        detailed: When True, show score rationale for each finding.
    """
    json_path = _write_json(report, output_dir)

    if not json_only:
        _render_rich(report, detailed)

    _console.print(f"[dim]Report saved to: {json_path}[/dim]")
