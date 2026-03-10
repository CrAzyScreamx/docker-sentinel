"""
cli.py — Command-line entry point for docker-sentinel.

Registered as the 'docker-sentinel' script in pyproject.toml. Loads
environment variables, invokes the pipeline runner, and delegates
report rendering to report.py.
"""

import click
from dotenv import load_dotenv

from docker_sentinel.runner import run_pipeline


@click.command()
@click.argument("image_name")
@click.option(
    "-o", "--output-dir",
    "output_dir",
    default=".",
    show_default=True,
    help="Directory to write the JSON report file.",
)
@click.option(
    "-m", "--model",
    default=None,
    envvar="DOCKER_SENTINEL_MODEL",
    help="LiteLLM model string (e.g. anthropic/claude-opus-4-6).",
)
@click.option(
    "--json-only",
    "json_only",
    is_flag=True,
    default=False,
    help="Skip Rich terminal output; write the JSON report file only.",
)
def main(
    image_name: str,
    output_dir: str,
    model: str | None,
    json_only: bool,
) -> None:
    """Inspect a Docker IMAGE_NAME for security issues."""
    load_dotenv()

    report = run_pipeline(image_name, model=model)

    from docker_sentinel.report import generate_report
    generate_report(report, output_dir=output_dir, json_only=json_only)
