"""DriftWarden command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from driftwarden import __version__, git
from driftwarden.config import ConfigError, load_config
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_source_quote
from driftwarden.models import WORKTREE

app = typer.Typer(
    name="driftwarden",
    help="Keep your codebase honest to its own architecture decisions.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)

VALID_FORMATS = ("json", "md", "sarif", "html")


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
    out: Path | None = typer.Option(
        None, "--out", help="Output directory (grounding ledger goes to OUT/logs/grounding)."
    ),
    config: Path | None = typer.Option(None, "--config", help="Config file to use."),
) -> None:
    """Scan a repository against its architecture decisions.

    Exit codes: 0 all decisions VERIFIED, 2 usage/config error, 3 any grounding MISMATCH.
    """
    fmts = _parse_formats(format)
    if not path.exists():
        err.print(f"[red]error:[/red] path does not exist: {path}")
        raise typer.Exit(2)
    # Config errors are reported first (D-002): a broken config is a usage error the
    # user must see even when the path is also not a git repository.
    git_error: git.GitError | None = None
    try:
        root = git.repo_root(path)
    except git.GitError as exc:
        git_error = exc
        root = path if path.is_dir() else path.parent
    try:
        cfg = load_config(root, config)
    except ConfigError as exc:
        err.print(f"[red]config error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    if git_error is not None:
        err.print(f"[red]error:[/red] {git_error}")
        raise typer.Exit(2) from git_error

    console.print(f"driftwarden {__version__} - scan {root}")
    console.print(
        f"mode={mode.value} formats={','.join(fmts) or '(none)'} config={cfg.source or 'defaults'}",
        highlight=False,
    )

    result = scan_adrs(root, cfg)
    if result.head is None:
        console.print("[yellow]note:[/yellow] repository has no commits; reading working tree")
    for rel, msg in result.errors:
        err.print(f"[yellow]warning:[/yellow] could not read {rel}: {msg}")

    ledger = Ledger(out if out is not None else Path.cwd())
    rows = []
    for dec in result.decisions:
        gr = verify_source_quote(root, dec.source, check_id="G1", subject=dec.id)
        ledger.append(gr)
        rows.append((dec, gr))

    table = Table(title=f"Decisions ({len(rows)})", show_lines=False)
    for col in ("id", "title", "status", "format", "lines", "grounding"):
        table.add_column(col, overflow="fold")
    for dec, gr in rows:
        src = dec.source
        commit = "worktree" if src.commit == WORKTREE else src.commit[:7]
        lines = f"{src.path}:{src.line_start}-{src.line_end}@{commit}"
        g = "[green]VERIFIED[/green]" if gr.status == "VERIFIED" else "[red]MISMATCH[/red]"
        table.add_row(escape(dec.id), escape(dec.title), dec.status, dec.format, escape(lines), g)
    console.print(table)

    mismatches = [gr for _, gr in rows if gr.status == "MISMATCH"]
    for gr in mismatches:
        subject = escape(gr.subject or "")
        console.print(f"[red]Could not verify[/red] {subject}: {escape(gr.reason)}")

    summary = ledger.write_summary()
    if summary["total"]:
        rate = f"{summary['pass_rate']:.1%}"
        console.print(
            f"Grounding (G1): {summary['verified']}/{summary['total']} VERIFIED, "
            f"pass rate {rate}. Ledger: {ledger.path}",
            highlight=False,
        )
    else:
        console.print("No ADRs found. Grounding (G1): nothing to verify (pass rate n/a).")

    console.print(
        "Not yet implemented: claim structuring, evidence collection, judgement, "
        "undocumented decisions, drift timeline, report formats.",
        highlight=False,
    )
    if mode is not Mode.auto or fmts:
        console.print(
            "[dim]--mode/--format are accepted but have no effect yet; "
            "no report files were written.[/dim]"
        )
    raise typer.Exit(3 if mismatches else 0)


@app.command()
def verify() -> None:
    """Re-verify a grounding ledger (not yet implemented)."""
    err.print("not yet implemented")
    raise typer.Exit(2)


if __name__ == "__main__":  # pragma: no cover
    app()
