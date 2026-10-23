"""DriftWarden command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from driftwarden import __version__
from driftwarden.config import ConfigError, load_config

app = typer.Typer(
    name="driftwarden",
    help="Keep your codebase honest to its own architecture decisions.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)

VALID_FORMATS = ("json", "md", "sarif", "html")

# Pipeline stages from ARCHITECTURE.md, and whether they exist yet.
STAGES: list[tuple[str, bool]] = [
    ("1 Discover ADRs", False),
    ("2 Extract decisions", False),
    ("3 Structure claims", False),
    ("4 Index repository", False),
    ("5 Collect evidence", False),
    ("6 Judge", False),
    ("7 Grounding gate", False),
    ("8 Undocumented decisions", False),
    ("9 Drift timeline", False),
    ("10 Reporters", False),
]


class Mode(str, Enum):
    auto = "auto"
    offline = "offline"
    llm = "llm"


def _parse_formats(value: str | None) -> list[str]:
    if not value:
        return []
    fmts = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in fmts if f not in VALID_FORMATS]
    if bad:
        raise typer.BadParameter(
            f"unknown format(s): {', '.join(bad)}; choose from {', '.join(VALID_FORMATS)}"
        )
    return fmts


@app.command()
def version() -> None:
    """Print the DriftWarden version."""
    console.print(f"driftwarden {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repository to scan."),
    mode: Mode = typer.Option(Mode.auto, "--mode", help="auto | offline | llm"),
    format: str = typer.Option(
        "", "--format", help="Comma list of report formats: json,md,sarif,html"
    ),
    out: Path | None = typer.Option(None, "--out", help="Directory for report files."),
    config: Path | None = typer.Option(None, "--config", help="Config file to use."),
) -> None:
    """Scan a repository against its architecture decisions."""
    fmts = _parse_formats(format)
    if not path.exists():
        err.print(f"[red]error:[/red] path does not exist: {path}")
        raise typer.Exit(2)
    try:
        cfg = load_config(path, config)
    except ConfigError as exc:
        err.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(2) from exc

    console.print(f"driftwarden {__version__} - scan {path}")
    console.print(
        f"mode={mode.value} formats={','.join(fmts) or '(none)'} "
        f"out={out or '(none)'} config={cfg.source or 'defaults'}"
    )
    console.print("No analysis was performed. Pipeline stages not yet implemented:")
    for name, done in STAGES:
        if not done:
            console.print(f"  - {name}: not yet implemented")


@app.command()
def verify() -> None:
    """Re-verify a grounding ledger (not yet implemented)."""
    err.print("not yet implemented")
    raise typer.Exit(2)


if __name__ == "__main__":  # pragma: no cover
    app()
