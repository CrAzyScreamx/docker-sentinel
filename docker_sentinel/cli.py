"""
cli.py — Command-line entry point for docker-sentinel.

Registered as the 'docker-sentinel' script in pyproject.toml. Loads
environment variables, invokes the pipeline runner, and delegates
report rendering to report.py.
"""
# pywintypes must be imported before any other pywin32 module (win32api, etc.)
# so the DLL is loaded from our bundle rather than picked up from System32.
try:
    import pywintypes  # noqa: F401
except ImportError:
    pass

import logging
import os
import sys
import traceback
from pathlib import Path


def _setup_file_logger() -> Path:
    """
    Configure a file logger that writes full debug output next to the
    executable regardless of the current working directory.

    Frozen (PyInstaller): next to docker-sentinel.exe / docker-sentinel binary.
    Dev (source):         project root (two levels above cli.py).

    Returns the log file path so it can be reported to the user.
    """
    if getattr(sys, "frozen", False):
        # sys.executable is the actual binary path — works correctly even when
        # launched via a Windows shortcut or a Linux symlink.
        log_dir = Path(sys.executable).resolve().parent
    else:
        log_dir = Path(__file__).resolve().parent.parent

    log_path = log_dir / "docker-sentinel-debug.log"

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode="w", encoding="utf-8"),
        ],
        force=True,
    )
    return log_path


_log = logging.getLogger("docker_sentinel.cli")


# ---------------------------------------------------------------------------
# Attempt the runner import here so any import-time failures are captured
# in the log before Click runs.
# ---------------------------------------------------------------------------
try:
    _log.debug("Importing docker_sentinel.runner …")
    from docker_sentinel.runner import run_pipeline
    _log.debug("docker_sentinel.runner imported successfully.")
except Exception:
    _log.critical("FATAL: failed to import docker_sentinel.runner", exc_info=True)
    raise


import click
from dotenv import load_dotenv


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
    log_path = _setup_file_logger()
    click.echo(f"[debug] Log file: {log_path}", err=True)

    _log.info("=== docker-sentinel started ===")
    _log.info("image_name=%s  model=%s  output_dir=%s", image_name, model, output_dir)
    _log.debug("sys.executable=%s  frozen=%s", sys.executable, getattr(sys, "frozen", False))
    _log.debug("sys.path=%s", sys.path)

    load_dotenv()
    _log.debug("load_dotenv() completed")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        _log.error("ANTHROPIC_API_KEY is not set")
        click.echo(
            "Error: ANTHROPIC_API_KEY is not set.\n"
            "Set it in your environment or in a .env file next to the binary:\n"
            "  ANTHROPIC_API_KEY=sk-ant-...",
            err=True,
        )
        sys.exit(1)

    _log.debug("ANTHROPIC_API_KEY present (length=%d)", len(os.environ["ANTHROPIC_API_KEY"]))

    try:
        _log.info("Calling run_pipeline …")
        report = run_pipeline(image_name, model=model)
        _log.info("run_pipeline completed successfully")
    except Exception as exc:
        _log.error("run_pipeline raised an exception: %s", exc, exc_info=True)
        click.echo(f"Error: {exc}", err=True)
        click.echo(f"Full traceback written to: {log_path}", err=True)
        sys.exit(1)

    try:
        from docker_sentinel.report import generate_report
        generate_report(
            report,
            output_dir=output_dir,
            json_only=json_only,
            detailed=detailed,
        )
        _log.info("generate_report completed")
    except Exception as exc:
        _log.error("generate_report raised an exception: %s", exc, exc_info=True)
        click.echo(f"Error during report generation: {exc}", err=True)
        click.echo(f"Full traceback written to: {log_path}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
