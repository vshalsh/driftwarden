"""Deterministic verifiers for AI-produced provenance (README "Grounding & traceability").

``verify_source_quote`` implements G1 (decision quotes from ADRs) and will be
reused for G2 (code evidence). It is a plain function: no model, no network.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path, PurePosixPath

from driftwarden import git
from driftwarden.models import WORKTREE, GroundingResult, Provenance
from driftwarden.text import split_lines

_QUOTE_MAP = {
    "‘": "'",  # left single
    "’": "'",  # right single / apostrophe
    "‚": "'",  # single low-9
    "‛": "'",  # single high-reversed-9
    "′": "'",  # prime
    "“": '"',  # left double
    "”": '"',  # right double
    "„": '"',  # double low-9
    "‟": '"',  # double high-reversed-9
    "″": '"',  # double prime
    "«": '"',  # guillemets
    "»": '"',
}
_EMPHASIS = frozenset("*_~")


def _normalise_lines(lines: list[str]) -> tuple[str, list[int]]:
    """Normalise ``lines`` into one string plus, per output char, its 0-based line.

    Rules (applied identically to the quote and to the file):
    Unicode NFC; curly quotes to straight; markdown emphasis markers ``* _ ~``
    removed; every run of whitespace (including line breaks) collapsed to one
    space; leading/trailing whitespace dropped.
    """
    out: list[str] = []
    where: list[int] = []
    pending_space = False
    for idx, raw in enumerate(lines):
        for ch in unicodedata.normalize("NFC", raw):
            ch = _QUOTE_MAP.get(ch, ch)
            if ch in _EMPHASIS:
                continue
            if ch.isspace():
                pending_space = True
                continue
            if pending_space and out:
                out.append(" ")
                where.append(idx)
            pending_space = False
            out.append(ch)
            where.append(idx)
        pending_space = True  # the line break itself
    return "".join(out), where


def normalise(text: str) -> str:
    """Normalised form of ``text`` used for quote comparison."""
    return _normalise_lines(split_lines(text))[0]


def _find_elsewhere(lines: list[str], needle: str) -> list[tuple[int, int]]:
    """All 1-based (start, end) line ranges where normalised ``needle`` occurs."""
    hay, where = _normalise_lines(lines)
    hits: list[tuple[int, int]] = []
    pos = hay.find(needle)
    while pos != -1:
        hits.append((where[pos] + 1, where[pos + len(needle) - 1] + 1))
        pos = hay.find(needle, pos + 1)
    return hits


def _safe_rel(path: str) -> str | None:
    p = PurePosixPath(Path(path).as_posix())
    if p.is_absolute() or ".." in p.parts or str(p) in ("", "."):
        return None
    return str(p)


def _result(prov: Provenance, ok: bool, reason: str, check_id: str, subject: str | None):
    return GroundingResult(
        check_id=check_id,
        status="VERIFIED" if ok else "MISMATCH",
        reason=reason,
        provenance=prov,
        subject=subject,
    )


def _fmt_ranges(hits: list[tuple[int, int]]) -> str:
    shown = ", ".join(f"{a}-{b}" for a, b in hits[:5])
    return shown + (f" (+{len(hits) - 5} more)" if len(hits) > 5 else "")


def verify_source_quote(
    repo: str | Path,
    prov: Provenance,
    *,
    check_id: str = "G1",
    subject: str | None = None,
) -> GroundingResult:
    """Check that ``prov.quote`` lies within lines ``line_start..line_end`` of
    ``prov.path`` at ``prov.commit`` (or the working tree when commit is WORKTREE).

    Returns VERIFIED, or MISMATCH with a precise reason. Never raises for bad
    provenance; it raises only if ``repo`` itself is not a git repository.
    """
    root = git.repo_root(repo)
    loc = f"{prov.path}:{prov.line_start}-{prov.line_end}@{prov.commit[:12]}"

    rel = _safe_rel(prov.path)
    if rel is None:
        return _result(prov, False, f"{loc}: path is not repo-relative", check_id, subject)

    # 1. Load the file at the cited commit.
    if prov.commit == WORKTREE:
        f = root / rel
        if not f.is_file():
            return _result(prov, False, f"{loc}: file missing in working tree", check_id, subject)
        text = f.read_text(encoding="utf-8", errors="replace")
    else:
        if not prov.commit.strip() or not git.commit_exists(root, prov.commit):
            return _result(prov, False, f"{loc}: unknown commit {prov.commit!r}", check_id, subject)
        try:
            text = git.show_file(root, prov.commit, rel)
        except git.GitError:
            return _result(
                prov,
                False,
                f"{loc}: file missing at commit {prov.commit[:12]}",
                check_id,
                subject,
            )

    lines = split_lines(text)
    n = len(lines)

    # 2. Range sanity.
    if prov.line_start < 1 or prov.line_end < prov.line_start or prov.line_end > n:
        return _result(
            prov,
            False,
            f"{loc}: line range {prov.line_start}-{prov.line_end} out of bounds "
            f"(file has {n} lines)",
            check_id,
            subject,
        )

    needle = normalise(prov.quote)
    if not needle:
        return _result(prov, False, f"{loc}: quote is empty", check_id, subject)

    # 3. Quote inside the cited range?
    hay, _ = _normalise_lines(lines[prov.line_start - 1 : prov.line_end])
    if needle in hay:
        return _result(prov, True, f"{loc}: quote found in range", check_id, subject)

    hits = _find_elsewhere(lines, needle)
    if hits:
        reason = f"{loc}: quote not in cited range; found at lines {_fmt_ranges(hits)}"
    else:
        reason = f"{loc}: quote not found in cited range or anywhere in the file"
    return _result(prov, False, reason, check_id, subject)
