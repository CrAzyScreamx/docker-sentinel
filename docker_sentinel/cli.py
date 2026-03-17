"""
cli.py — Command-line entry point for docker-sentinel.

Registered as the 'docker-sentinel' script in pyproject.toml. Loads
environment variables, invokes the pipeline runner, and delegates
report rendering to report.py.
"""

import sys

import click
from dotenv import load_dotenv

from docker_sentinel.runner import run_pipeline


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
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
@click.option(
    "--detailed",
    "detailed",
    is_flag=True,
    default=False,
    help="Show score rationale for each finding.",
)
def main(
    image_name: str,
    output_dir: str,
    model: str | None,
    json_only: bool,
    detailed: bool,
) -> None:
    """Inspect a Docker IMAGE_NAME for security issues."""
    load_dotenv()

    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        click.echo(
            "Error: ANTHROPIC_API_KEY is not set.\n"
            "Set it in your environment or in a .env file next to the binary:\n"
            "  ANTHROPIC_API_KEY=sk-ant-...",
            err=True,
        )
        sys.exit(1)

    try:
        report = run_pipeline(image_name, model=model)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    from docker_sentinel.report import generate_report
    generate_report(
        report,
        output_dir=output_dir,
        json_only=json_only,
        detailed=detailed,
    )


if __name__ == "__main__":
    main()
