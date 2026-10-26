"""Deterministic verifiers for AI-produced provenance (README "Grounding & traceability").

``verify_source_quote`` implements G1 (decision quotes from ADRs) and will be
reused for G2 (code evidence). ``verify_dependency`` implements G3 (dependency
facts) by re-running the non-LLM manifest parsers on the manifest at the cited
commit. They are plain functions: no model, no network.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path, PurePosixPath

from driftwarden import git
from driftwarden.index.manifests import canonical_package, canonical_version, parse_manifest
from driftwarden.models import WORKTREE, DependencyRef, GroundingResult, Provenance
from driftwarden.text import read_text_file, split_lines

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
_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_EMPHASIS = frozenset("*_~")


def _code_span_indices(chars: list[str]) -> set[int]:
    """Indices inside backtick code spans (a run of N backticks up to the next run
    of exactly N). Unmatched backtick runs are literal and protect nothing."""
    n = len(chars)
    runs: list[tuple[int, int]] = []  # (start, length)
    i = 0
    while i < n:
        if chars[i] == "`":
            j = i
            while j < n and chars[j] == "`":
                j += 1
            runs.append((i, j - i))
            i = j
        else:
            i += 1
    inside: set[int] = set()
    k = 0
    while k < len(runs):
        start, length = runs[k]
        close = next((m for m in range(k + 1, len(runs)) if runs[m][1] == length), None)
        if close is None:
            k += 1
            continue
        c_start, c_len = runs[close]
        inside.update(range(start, c_start + c_len))
        k = close + 1
    return inside


def _emphasis_markers(chars: list[str]) -> set[int]:
    """Indices of emphasis delimiters in ``chars`` that open or close a pair.

    A delimiter run is a maximal run of one of ``* _ ~``. It can *open* when the
    next char is not whitespace and the previous char is not alphanumeric; it can
    *close* when the previous char is not whitespace and the next char is not
    alphanumeric. An opener is paired with the nearest later closer of the same
    char and run length. Only paired runs are removed, so intraword delimiters
    (``snake_case``, ``a*b``), lone markers (``_private``, ``* item``) and code
    such as ``f(*args, **kwargs)`` are kept verbatim.

    Two deliberate departures from CommonMark, because identifiers win:
    an underscore run of 2+ (``__``) does not pair around content with no
    whitespace, so ``__init__`` stays ``__init__`` (D-005); and delimiters inside
    a backtick code span are literal (D-006).
    """
    n = len(chars)
    code = _code_span_indices(chars)
    stack: list[tuple[str, int, int]] = []  # (char, run length, start index)
    drop: set[int] = set()
    i = 0
    while i < n:
        ch = chars[i]
        if ch not in _EMPHASIS or i in code:
            i += 1
            continue
        j = i
        while j < n and chars[j] == ch and j not in code:
            j += 1
        prev = chars[i - 1] if i > 0 else " "
        nxt = chars[j] if j < n else " "
        length = j - i
        can_open = not nxt.isspace() and not prev.isalnum()
        can_close = not prev.isspace() and not nxt.isalnum()
        matched = False
        if can_close:
            for k in range(len(stack) - 1, -1, -1):
                s_ch, s_len, s_start = stack[k]
                if s_ch == ch and s_len == length and s_start + s_len < i:
                    inner = chars[s_start + s_len : i]
                    if ch == "_" and length >= 2 and not any(c.isspace() for c in inner):
                        continue  # bare identifier / dunder such as __init__
                    drop.update(range(s_start, s_start + s_len))
                    drop.update(range(i, j))
                    del stack[k:]  # delimiters opened inside the pair cannot close later
                    matched = True
                    break
        if not matched and can_open:
            stack.append((ch, length, i))
        i = j
    return drop


def _normalise_lines(lines: list[str]) -> tuple[str, list[int]]:
    """Normalise ``lines`` into one string plus, per output char, its 0-based line.

    Rules (applied identically to the quote and to the file):
    Unicode NFC; curly quotes to straight; markdown emphasis markers ``* _ ~``
    removed only where they pair up around text (see ``_emphasis_markers``), so
    identifier underscores survive; every run of whitespace (including line
    breaks) collapsed to one space; leading/trailing whitespace dropped.
    """
    chars: list[str] = []
    src_line: list[int] = []
    for idx, raw in enumerate(lines):
        for ch in unicodedata.normalize("NFC", raw):
            chars.append(_QUOTE_MAP.get(ch, ch))
            src_line.append(idx)
        chars.append("\n")  # the line break itself; emphasis may span lines
        src_line.append(idx)
    drop = _emphasis_markers(chars)

    out: list[str] = []
    where: list[int] = []
    pending_space = False
    for pos, ch in enumerate(chars):
        if pos in drop:
            continue
        if ch.isspace():
            pending_space = True
            continue
        if pending_space and out:
            out.append(" ")
            where.append(src_line[pos])
        pending_space = False
        out.append(ch)
        where.append(src_line[pos])
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


def _result(
    prov: Provenance | DependencyRef, ok: bool, reason: str, check_id: str, subject: str | None
):
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
        text = read_text_file(f)
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
    if not needle.strip("".join(_EMPHASIS) + " "):  # nothing but lone markers is empty too
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


def _load_at(root: Path, rel: str, commit: str) -> tuple[str | None, str]:
    """(text, "") or (None, reason) for ``rel`` at ``commit`` / the working tree."""
    if commit == WORKTREE:
        f = root / rel
        if not f.is_file():
            return None, "file missing in working tree"
        return read_text_file(f), ""
    if not commit.strip() or not git.commit_exists(root, commit):
        return None, f"unknown commit {commit!r}"
    try:
        return git.show_file(root, commit, rel), ""
    except git.GitError:
        return None, f"file missing at commit {commit[:12]}"


def _fmt_dep(r: DependencyRef) -> str:
    spec = r.version_spec if r.version_spec is not None else "(unversioned)"
    scope = f" [{r.scope}]" if r.scope else ""
    return f"{r.package} {spec} at line {r.line}{scope}"


def verify_dependency(
    repo: str | Path,
    dep: DependencyRef,
    *,
    check_id: str = "G3",
    subject: str | None = None,
) -> GroundingResult:
    """Check a G3 dependency claim: ``dep.package`` with ``dep.version_spec`` is
    declared in ``dep.manifest_path`` at ``dep.commit`` (or the working tree when
    the commit is WORKTREE).

    The manifest is read with ``git show`` and re-parsed by the deterministic
    parser for its type. Package names are compared by each ecosystem's own
    rules (PEP 503 for PyPI, case-insensitive for NuGet, Docker Hub aliases for
    images); version specs must match exactly after whitespace normalisation,
    and ``None`` means "declared without a version". ``line``, ``ecosystem`` and
    ``scope`` are checked when the claim states them.

    Returns VERIFIED, or MISMATCH with a precise reason. Never raises for bad
    provenance or a malformed manifest; it raises only if ``repo`` itself is not
    a git repository.
    """
    root = git.repo_root(repo)
    commit = dep.commit or ""
    loc = f"{dep.manifest_path}@{commit[:12] or '?'}"

    def fail(reason: str) -> GroundingResult:
        return _result(dep, False, f"{loc}: {reason}", check_id, subject)

    if not commit.strip():
        return fail("no commit given")
    if commit != WORKTREE:
        # A moving ref (HEAD, branch, tag, short SHA) would make the claim
        # non-reproducible: only a pinned, full object name is accepted.
        if not _FULL_SHA.fullmatch(commit):
            return fail(f"commit must be a full SHA (40/64 hex) or {WORKTREE}, got {commit!r}")
        if not git.commit_exists(root, commit):
            return fail(f"unknown commit {commit!r}")
        if git.resolve_commit(root, commit) != commit.lower():
            return fail(f"commit must be a full SHA (40/64 hex) or {WORKTREE}, got {commit!r}")
    rel = _safe_rel(dep.manifest_path)
    if rel is None:
        return fail("path is not repo-relative")
    if not dep.package.strip():
        return fail("package is empty")

    text, why = _load_at(root, rel, commit)
    if text is None:
        return fail(why)

    parsed = parse_manifest(rel, text)
    if parsed.kind is None:
        return fail("not a recognised dependency manifest")
    if parsed.errors and not parsed.refs:
        return fail(f"manifest could not be parsed: {'; '.join(parsed.errors)}")

    same_name = [
        r
        for r in parsed.refs
        if canonical_package(r.ecosystem, r.package) == canonical_package(r.ecosystem, dep.package)
    ]
    cands = [r for r in same_name if dep.ecosystem is None or r.ecosystem == dep.ecosystem]
    if not cands:
        if same_name:
            ecos = ", ".join(sorted({r.ecosystem or "?" for r in same_name}))
            return fail(f"{dep.package!r} is declared as ecosystem {ecos}, not {dep.ecosystem}")
        extra = f"; parse errors: {'; '.join(parsed.errors)}" if parsed.errors else ""
        return fail(
            f"package {dep.package!r} not declared ({parsed.kind} manifest declares "
            f"{len(parsed.refs)} dependencies){extra}"
        )

    vmatch = [
        r
        for r in cands
        if canonical_version(r.ecosystem, r.version_spec)
        == canonical_version(r.ecosystem, dep.version_spec)
    ]
    if not vmatch:
        claimed = dep.version_spec if dep.version_spec is not None else "(unversioned)"
        found = "; ".join(_fmt_dep(r) for r in cands[:5])
        return fail(f"version_spec {claimed!r} does not match: manifest declares {found}")

    if dep.scope is not None:
        smatch = [r for r in vmatch if r.scope == dep.scope]
        if not smatch:
            found = "; ".join(_fmt_dep(r) for r in vmatch[:5])
            return fail(f"scope {dep.scope!r} does not match: manifest declares {found}")
        vmatch = smatch

    if dep.line is not None:
        lmatch = [r for r in vmatch if r.line == dep.line]
        if not lmatch:
            lines = ", ".join(str(r.line) for r in vmatch[:5])
            return fail(f"{dep.package} is declared at line {lines}, not line {dep.line}")
        vmatch = lmatch

    return _result(dep, True, f"{loc}: {_fmt_dep(vmatch[0])} verified", check_id, subject)
