"""DriftWarden command-line interface."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unicodedata
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from driftwarden import __version__, git
from driftwarden.config import ConfigError, load_config
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.llm import get_provider
from driftwarden.models import WORKTREE
from driftwarden.pipeline import run_scan
from driftwarden.report.model import Report, rule_text

app = typer.Typer(
    name="driftwarden",
    help="Keep your codebase honest to its own architecture decisions.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(soft_wrap=True)
err = Console(stderr=True, soft_wrap=True)

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
                    f"[yellow]warning:[/yellow] could not write {safe(str(ignore))}: "
                    f"{safe(exc.strerror or str(exc))}; the ledger may show in git status"
                )
        return base
    for alt in _fallback_dirs(root):
        if _writable(alt):
            err.print(
                f"[yellow]warning:[/yellow] cannot write {safe(str(base))}; "
                f"writing the grounding ledger to {safe(str(alt))} instead (use --out DIR)",
                highlight=False,
            )
            return alt
    raise LedgerLocationError(str(base))


@app.command()
def version() -> None:
    """Print the DriftWarden version."""
    console.print(f"driftwarden {__version__}")


def _resolve_provider(requested: str, cfg, root: Path) -> tuple[str, object | None]:
    """(mode, provider) for the scan. auto: llm when a provider key (or a local
    OpenAI-compatible base_url) is configured, else offline; a provider that fails to
    initialise falls back to offline with a warning. llm: a failure exits 2."""
    if requested == "offline":
        return "offline", None
    try:
        provider = get_provider(cfg.model_copy(update={"mode": requested}), root)
    except Exception as exc:  # noqa: BLE001 - any init failure: fallback or exit 2
        if requested == "llm":
            err.print(f"[red]error:[/red] LLM provider failed to initialise: {safe(str(exc))}")
            raise typer.Exit(2) from exc
        err.print(
            f"[yellow]warning:[/yellow] LLM provider failed to initialise "
            f"({safe(str(exc))}); falling back to offline mode",
            highlight=False,
        )
        return "offline", None
    if provider.offline:
        reason = getattr(provider, "reason", "offline mode")
        err.print(f"[dim]auto mode: {safe(reason)}[/dim]", highlight=False)
        return "offline", None
    return "llm", provider


def _loc(path: str, a: int, b: int, commit: str) -> str:
    sha = "worktree" if commit == WORKTREE else commit[:7]
    lines = f"{a}" if a == b else f"{a}-{b}"
    return f"{path}:{lines}@{sha}"


def safe(value: object) -> str:
    """THE output helper (L-028 D3): every repo-, user- or OS-derived value the CLI prints
    goes through here. ``terminal_safe`` first (ESC, OSC-8, C1, bidi and other control /
    format characters, and newlines, become visible ``\\uXXXX``, so one value is one inert
    line), then rich ``escape`` (so ``[...]`` is never markup). ``tests/test_l028_pipeline``
    checks with an AST walk that no f-string value printed by this module bypasses it."""
    return escape(terminal_safe(str(value), multiline=False))


def terminal_safe(text: str, *, multiline: bool = True) -> str:
    """``text`` with every control, format or separator character replaced by a visible
    ``\\uXXXX`` escape, so it cannot drive the terminal. ``multiline`` keeps newline and tab
    (for a whole document such as a draft); otherwise they are escaped too."""
    out = []
    keep = "\n\t" if multiline else ""
    for ch in text:
        if ch in keep:
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _detail(ev) -> str:
    """An evidence item's detail without its leading ``path:line`` (already shown)."""
    head, _, rest = ev.detail.partition(" ")
    return rest if rest and head.startswith(f"{ev.ref.path}:") else ev.detail


def _print_report(report: Report) -> None:
    by = report.summary.by_status
    judged = [c for c in report.claims if c.judged and c.verdict is not None]
    console.print(
        f"Verdicts ({len(judged)} judged of {report.summary.claims} claim(s)): "
        + ", ".join(f"{by.get(s, 0)} {s}" for s in ("VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN")),
        highlight=False,
    )
    colour = {"VIOLATED": "red", "DRIFTING": "yellow", "HOLDING": "green", "UNKNOWN": "dim"}
    for status in ("VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN"):
        group = report.verdicts(status)  # VERIFIED only; failures are listed below
        if not group:
            continue
        console.print(
            f"[{colour[status]}]{status}[/{colour[status]}] ({len(group)}), grounding VERIFIED"
        )
        for cr in group:
            c, v = cr.claim, cr.verdict
            assert v is not None
            src = c.source
            console.print(
                f"  {safe(c.id)}  {safe(rule_text(c))}  "
                f"{safe(_loc(src.path, src.line_start, src.line_end, src.commit))}",
                highlight=False,
            )
            console.print(f"    {safe(v.rationale)}", highlight=False)
            for ev in v.evidence:
                r = ev.ref
                console.print(
                    f"    evidence  {safe(_loc(r.path, r.line_start, r.line_end, r.commit))}"
                    f"  {safe(_detail(ev))}",
                    highlight=False,
                )
    skipped = [c for c in report.claims if not c.judged]
    for cr in skipped:
        console.print(
            f"[dim]not judged {safe(cr.id)}: {safe(cr.not_judged_reason or '')}[/dim]",
            highlight=False,
        )
    for item in report.could_not_verify:
        check = f" [{item.check_id}]" if item.check_id else ""
        reason = "; ".join(item.reasons)
        console.print(
            f"[red]Could not verify[/red] {safe(item.kind)} {safe(item.id)}{safe(check)}: "
            f"{safe(reason)}",
            highlight=False,
        )
    for rec in report.undocumented:
        first = rec.introducing_commits[0][:7] if rec.introducing_commits else "?"
        console.print(
            f"[yellow]Undocumented[/yellow] {safe(rec.id)}: {safe(rec.title)} "
            f"(introduced {safe(first)})",
            highlight=False,
        )
        for ev in rec.evidence:
            r = ev.ref
            console.print(
                f"    evidence  {safe(_loc(r.path, r.line_start, r.line_end, r.commit))}"
                f"  {safe(_detail(ev))}",
                highlight=False,
            )
    for d in report.drafts:
        console.print(
            f"Draft ADR for {safe(d.record_id)}: {safe(d.title)} -> suggested path "
            f"{safe(d.path or '?')} (shown only, not written)",
            highlight=False,
        )
        # The verified markdown, as inert text: never parsed as rich markup, and any
        # control / format character (ANSI escapes included) shown as a visible escape.
        console.print(
            Panel(Text(terminal_safe(d.markdown or "")), title=safe(d.path or d.record_id)),
            highlight=False,
            soft_wrap=False,
        )
    gs = report.grounding_summary
    parts = []
    for cid, cs in gs.by_check.items():
        if cs.total:
            parts.append(f"{cid} {cs.verified}/{cs.total}")
        else:
            parts.append(f"{cid} n/a")
    rate = f"{gs.pass_rate:.1%}" if gs.pass_rate is not None else "n/a"
    console.print(
        f"Grounding (all checks): {gs.verified}/{gs.total} VERIFIED, pass rate {rate} "
        f"[{', '.join(parts)}]",
        highlight=False,
    )
    s = report.summary
    drift = f"{s.drift_score:.1%}" if s.drift_score is not None else "n/a"
    console.print(
        f"Summary: drift score {drift} (decided claims not HOLDING), {s.unknown} UNKNOWN, "
        f"{s.could_not_verify} unverified item(s), {s.undocumented} undocumented decision(s), "
        f"{s.drafts} draft(s); exit code {s.exit_code}",
        highlight=False,
    )


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repository to scan."),
    mode: Mode = typer.Option(
        Mode.auto,
        "--mode",
        help="auto (llm if a provider key is configured, else offline) | offline | llm",
    ),
    format: str = typer.Option(
        "",
        "--format",
        help="Comma list of report formats: json,md,sarif,html. Not written yet "
        "(arrives in L-012/L-013); use --json-out for JSON.",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Output directory (grounding ledger goes to OUT/logs/grounding). "
        "Default: <repo>/.driftwarden.",
    ),
    config: Path | None = typer.Option(None, "--config", help="Config file to use."),
    json_out: Path | None = typer.Option(
        None, "--json-out", help="Write the full Report as JSON to this file."
    ),
    draft_adrs: bool = typer.Option(
        False,
        "--draft-adrs",
        help="Draft MADR files for undocumented decisions (shown, never written to the repo).",
    ),
) -> None:
    """Scan a repository against its architecture decisions.

    Exit codes:
    0 = no VIOLATED claim and no G1 grounding mismatch;
    1 = at least one VERIFIED VIOLATED claim;
    2 = usage or config error (including --mode llm with no usable provider);
    3 = G1 grounding mismatch (an ADR decision or claim quote not found at its
    cited lines). When both 1 and 3 apply, the exit code is 3.
    """
    fmts = _parse_formats(format)
    if not path.exists():
        err.print(f"[red]error:[/red] path does not exist: {safe(path)}")
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
        err.print(f"[red]config error:[/red] {safe(str(exc))}")
        raise typer.Exit(2) from exc
    if git_error is not None:
        err.print(f"[red]error:[/red] {safe(git_error)}")
        raise typer.Exit(2) from git_error

    requested = cfg.mode if mode is Mode.auto else mode.value
    resolved, provider = _resolve_provider(requested, cfg, root)

    console.print(f"driftwarden {__version__} - scan {safe(root)}")
    console.print(
        f"mode={resolved} formats={','.join(fmts) or '(none)'} "
        f"config={safe(cfg.source or 'defaults')}",
        highlight=False,
    )

    result = scan_adrs(root, cfg)
    if result.head is None:
        console.print("[yellow]note:[/yellow] repository has no commits; reading working tree")
    for rel, msg in result.errors:
        err.print(f"[yellow]warning:[/yellow] could not read {safe(rel)}: {safe(msg)}")
    for rel, note in result.skipped:
        console.print(f"[yellow]skipped[/yellow] {safe(rel)}: {safe(note)}", highlight=False)

    if out is not None:
        if not _writable(out):
            err.print(f"[red]error:[/red] cannot write ledger to {safe(str(out))}; use --out DIR")
            raise typer.Exit(2)
        ledger_base = out
    else:
        try:
            ledger_base = _default_out(root)
        except LedgerLocationError as exc:
            err.print(f"[red]error:[/red] cannot write ledger to {safe(str(exc))}; use --out DIR")
            raise typer.Exit(2) from exc
    ledger = Ledger(ledger_base)
    try:
        report = run_scan(
            root,
            config=cfg,
            mode=resolved,
            provider=provider,  # type: ignore[arg-type]
            ledger=ledger,
            draft_adrs=draft_adrs,
            adrs=result,
        )
    except git.GitError as exc:
        err.print(f"[red]error:[/red] {safe(str(exc))}")
        raise typer.Exit(2) from exc

    decisions = report.decisions
    table = Table(title=f"Decisions ({len(decisions)})", show_lines=False)
    for col in ("id", "title", "status", "format", "lines", "grounding"):
        table.add_column(col, overflow="fold")
    for dec in decisions:
        src = dec.source
        commit = "worktree" if src.commit == WORKTREE else src.commit[:7]
        lines = f"{src.path}:{src.line_start}-{src.line_end}@{commit}"
        g = "[green]VERIFIED[/green]" if dec.g1.status == "VERIFIED" else "[red]MISMATCH[/red]"
        table.add_row(
            safe(dec.id), safe(dec.title), safe(dec.status), safe(dec.format), safe(lines), g
        )
    console.print(table)
    for dec in decisions:
        if not dec.judged and dec.g1.status == "VERIFIED":
            console.print(
                f"[dim]not judged {safe(dec.id)}: {safe(dec.not_judged_reason or '')}[/dim]",
                highlight=False,
            )

    g1_ok = sum(1 for d in decisions if d.g1.status == "VERIFIED")
    if decisions:
        console.print(
            f"Decisions (G1): {g1_ok}/{len(decisions)} VERIFIED, "
            f"pass rate {g1_ok / len(decisions):.1%}.",
            highlight=False,
        )
    elif result.skipped:
        console.print(
            f"No decisions to verify ({len(result.skipped)} empty ADR file(s) skipped). "
            "Grounding (G1): nothing to verify (pass rate n/a).",
            highlight=False,
        )
    else:
        console.print("No ADRs found. Grounding (G1): nothing to verify (pass rate n/a).")

    _print_report(report)
    ledger.write_summary()
    console.print(f"Ledger: {safe(ledger.path)}", highlight=False, soft_wrap=True)

    if json_out is not None:
        try:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            err.print(f"[red]error:[/red] cannot write {safe(str(json_out))}: {safe(str(exc))}")
            raise typer.Exit(2) from exc
        console.print(f"Report JSON: {safe(json_out)}", highlight=False, soft_wrap=True)
    if fmts:
        console.print(
            "[dim]--format: report file formats arrive in L-012/L-013; nothing was written "
            "for --format (use --json-out FILE for the JSON report).[/dim]",
            highlight=False,
        )
    console.print(
        "[dim]Not yet implemented: drift timeline (L-011), report file formats "
        "(L-012/L-013).[/dim]",
        highlight=False,
    )
    raise typer.Exit(report.summary.exit_code)


@app.command()
def verify() -> None:
    """Re-verify a grounding ledger (not yet implemented)."""
    err.print("not yet implemented")
    raise typer.Exit(2)


if __name__ == "__main__":  # pragma: no cover
    app()
