"""DriftWarden command-line interface."""

from __future__ import annotations

import hashlib
import os
import tempfile
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


DEFAULT_OUT_DIR = ".driftwarden"


class LedgerLocationError(Exception):
    """No writable directory for the grounding ledger."""


def _writable(base: Path) -> bool:
    """Create ``base/logs/grounding`` and prove a file can be written there."""
    try:
        target = base / "logs" / "grounding"
        target.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target, prefix=".probe-"):
            pass
        return True
    except OSError:
        return False


def _fallback_dirs(root: Path) -> list[Path]:
    """Per-repo ledger dirs outside the repo: user cache dir, then the temp dir."""
    tag = f"{root.name or 'repo'}-{hashlib.sha256(str(root).encode()).hexdigest()[:10]}"
    cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    user = os.environ.get("USER") or str(os.getuid() if hasattr(os, "getuid") else "user")
    return [
        Path(cache) / "driftwarden" / tag,
        Path(tempfile.gettempdir()) / f"driftwarden-{user}" / tag,
    ]


def _default_out(root: Path) -> Path:
    """``<repo>/.driftwarden``, self-ignored so a scan never dirties the scanned repo.

    D-004: when that directory cannot be written, fall back to a per-repo dir in the
    user cache or temp dir (with a warning). A failed ``.gitignore`` write alone is
    only a warning. Raises LedgerLocationError when nothing is writable.
    """
    base = root / DEFAULT_OUT_DIR
    if _writable(base):
        ignore = base / ".gitignore"
        if not ignore.exists():
            try:
                ignore.write_text("# Written by driftwarden scan; run output, not source.\n*\n")
            except OSError as exc:
                err.print(
                    f"[yellow]warning:[/yellow] could not write {escape(str(ignore))}: "
                    f"{escape(exc.strerror or str(exc))}; the ledger may show in git status"
                )
        return base
    for alt in _fallback_dirs(root):
        if _writable(alt):
            err.print(
                f"[yellow]warning:[/yellow] cannot write {escape(str(base))}; "
                f"writing the grounding ledger to {escape(str(alt))} instead (use --out DIR)",
                highlight=False,
            )
            return alt
    raise LedgerLocationError(str(base))


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
        None,
        "--out",
        help="Output directory (grounding ledger goes to OUT/logs/grounding). "
        "Default: <repo>/.driftwarden.",
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

    if out is not None:
        if not _writable(out):
            err.print(f"[red]error:[/red] cannot write ledger to {escape(str(out))}; use --out DIR")
            raise typer.Exit(2)
        ledger_base = out
    else:
        try:
            ledger_base = _default_out(root)
        except LedgerLocationError as exc:
            err.print(f"[red]error:[/red] cannot write ledger to {escape(str(exc))}; use --out DIR")
            raise typer.Exit(2) from exc
    ledger = Ledger(ledger_base)
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
