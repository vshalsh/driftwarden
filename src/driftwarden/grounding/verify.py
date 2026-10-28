"""Deterministic verifiers for AI-produced provenance (README "Grounding & traceability").

``verify_source_quote`` implements G1 (decision quotes from ADRs) and will be
reused for G2 (code evidence). ``verify_dependency`` implements G3 (dependency
facts) by re-running the non-LLM manifest parsers on the manifest at the cited
commit. ``verify_commits_exist`` implements the commit half of G5 (introducing
commits of an undocumented decision). They are plain functions: no model, no network.

Pinned provenance (L-023). A citation is only reproducible if it names one
immutable object and one file exactly as the repository does, so both
verifiers accept only:

* ``commit``: a full object name -- 40 hex (SHA-1 repositories) or 64 hex
  (SHA-256 repositories), **lowercase** as git prints it -- that resolves to
  itself as a commit, or the ``WORKTREE`` sentinel. Moving or derived names
  (``HEAD``, branches, tags, ``HEAD~0``, ``main^{commit}``, short SHAs, a 40-hex
  prefix in a SHA-256 repository, an annotated tag's own id) are MISMATCH.
  Uppercase hex is rejected rather than normalised: git never emits it, the
  judge compares commits byte for byte, and a record must round-trip unchanged.
* ``path``: a canonical repo-relative POSIX path -- no leading ``/`` or ``./``,
  no ``.`` / ``..`` / empty segment (so no ``//`` and no trailing ``/``), no
  backslash, no control, line-separator or bidi-override character (NUL
  included), nothing inside ``.git``. The path is compared byte-exact: no
  Unicode normalisation and no whitespace trimming, so an NFD spelling of an
  NFC file name, ``A.py`` for ``a.py`` or ``a.py `` for ``a.py`` is MISMATCH.
  In WORKTREE mode every segment must appear verbatim in its directory listing,
  so case-insensitive or normalising file systems (macOS, Windows) cannot alias
  another spelling onto a real file, and the file must resolve inside the
  repository.

Both verifiers validate these before calling git and turn any unexpected error
into a MISMATCH: they never raise for bad provenance, only when ``repo`` itself
is not a git repository.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

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
_FULL_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Invisible characters that reorder how a path is displayed (Trojan Source).
_BIDI = frozenset("؜‎‏‪‫‬‭‮⁦⁧⁨⁩")
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


def path_problem(path: object) -> str | None:
    """Why ``path`` is not a canonical repo-relative POSIX path, or None if it is.

    A pure string check (no file system, no git); rules in the module docstring."""
    if not isinstance(path, str):
        return f"path must be a string, got {type(path).__name__}"
    if not path:
        return "path is empty"
    for ch in path:
        if ch == "\\":
            return "path contains a backslash (repository paths use '/')"
        if unicodedata.category(ch) in ("Cc", "Cs", "Zl", "Zp") or ch in _BIDI:
            return f"path contains control character {ch!r}"
    if path.startswith("/"):
        return "path is absolute"
    segments = path.split("/")
    if "" in segments:
        return "path has an empty segment (leading, trailing or doubled '/')"
    if any(seg in (".", "..") for seg in segments):
        return "path has a '.' or '..' segment"
    if any(seg.casefold() == ".git" for seg in segments):
        return "path points into .git"
    return None


def commit_problem(root: Path, commit: object) -> str | None:
    """Why ``commit`` is not a pinned commit of the repository at ``root``, or None
    when it is WORKTREE or a full lowercase SHA that git resolves, as a commit, to
    itself."""
    if commit == WORKTREE:
        return None
    if not isinstance(commit, str) or not _FULL_SHA.fullmatch(commit):
        return (
            f"unknown commit {commit!r}: not a pinned commit id "
            f"(need a full 40/64-hex lowercase SHA or {WORKTREE})"
        )
    try:
        resolved = git.resolve_commit(root, commit)
    except git.NotAGitRepoError:
        raise
    except git.GitError:
        return f"unknown commit {commit!r}"
    if resolved != commit:
        return (
            f"unknown commit {commit!r}: not the full id of a commit (git resolves it to "
            f"{resolved[:12]}...; an abbreviation or a tag object)"
        )
    return None


def _show(text: object) -> str:
    """``text`` for a reason string: as is when printable, else its repr."""
    s = text if isinstance(text, str) else repr(text)
    return s if s.isprintable() else repr(s)


def _worktree_file(root: Path, rel: str) -> Path | None:
    """The working-tree file ``rel`` names, every segment matched verbatim against
    its directory listing, resolving inside ``root``; else None."""
    cur = root
    for seg in rel.split("/"):
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        if seg not in names:
            return None
        cur = cur / seg
    try:
        cur.resolve().relative_to(root.resolve())
    except (OSError, ValueError, RuntimeError):
        return None
    return cur if cur.is_file() else None


def _result(
    prov: Provenance | DependencyRef | None,
    ok: bool,
    reason: str,
    check_id: str,
    subject: str | None,
):
    return GroundingResult(
        check_id=check_id,
        status="VERIFIED" if ok else "MISMATCH",
        reason=reason,
        provenance=prov,
        subject=subject,
    )


def _crashed(
    prov: Provenance | DependencyRef,
    path: object,
    exc: Exception,
    check_id: str,
    subject: str | None,
) -> GroundingResult:
    """MISMATCH for an unexpected error while verifying ``prov``."""
    loc = f"{_show(path)}@{_show(getattr(prov, 'commit', '?'))[:12]}"
    return _result(
        prov, False, f"{loc}: could not verify ({type(exc).__name__}: {exc})", check_id, subject
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

    Only a pinned commit (full lowercase SHA, or WORKTREE) and a canonical
    repo-relative path can verify; see the module docstring.

    Returns VERIFIED, or MISMATCH with a precise reason. Never raises for bad
    provenance (any unexpected error is a MISMATCH); it raises only if ``repo``
    itself is not a git repository.
    """
    root = git.repo_root(repo)
    try:
        return _verify_source_quote(root, prov, check_id, subject)
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # the contract: bad provenance is a MISMATCH, never a crash
        return _crashed(prov, getattr(prov, "path", "?"), exc, check_id, subject)


def _verify_source_quote(
    root: Path, prov: Provenance, check_id: str, subject: str | None
) -> GroundingResult:
    loc = f"{_show(prov.path)}:{prov.line_start}-{prov.line_end}@{_show(prov.commit)[:12]}"

    # 1. Canonical path and pinned commit, checked before anything reaches git;
    #    then load the file at the cited commit.
    bad = path_problem(prov.path)
    if bad is not None:
        reason = f"{loc}: path is not repo-relative and canonical: {bad}"
        return _result(prov, False, reason, check_id, subject)
    bad = commit_problem(root, prov.commit)
    if bad is not None:
        return _result(prov, False, f"{loc}: {bad}", check_id, subject)
    text, why = _load_at(root, prov.path, prov.commit)
    if text is None:
        return _result(prov, False, f"{loc}: {why}", check_id, subject)

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
    """(text, "") or (None, reason) for ``rel`` at ``commit`` / the working tree.

    ``rel`` and ``commit`` must already have passed ``path_problem`` and
    ``commit_problem``."""
    if commit == WORKTREE:
        f = _worktree_file(root, rel)
        if f is None:
            return None, "file missing in working tree"
        return read_text_file(f), ""
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

    Only a pinned commit (full lowercase SHA, or WORKTREE) and a canonical
    repo-relative manifest path can verify; see the module docstring.

    Returns VERIFIED, or MISMATCH with a precise reason. Never raises for bad
    provenance or a malformed manifest (any unexpected error is a MISMATCH); it
    raises only if ``repo`` itself is not a git repository.
    """
    root = git.repo_root(repo)
    try:
        return _verify_dependency(root, dep, check_id, subject)
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # the contract: bad provenance is a MISMATCH, never a crash
        return _crashed(dep, getattr(dep, "manifest_path", "?"), exc, check_id, subject)


def _verify_dependency(
    root: Path, dep: DependencyRef, check_id: str, subject: str | None
) -> GroundingResult:
    commit = dep.commit or ""
    loc = f"{_show(dep.manifest_path)}@{_show(commit)[:12] or '?'}"

    def fail(reason: str) -> GroundingResult:
        return _result(dep, False, f"{loc}: {reason}", check_id, subject)

    if not commit.strip():
        return fail("no commit given")
    # A moving ref (HEAD, branch, tag, short SHA) would make the claim
    # non-reproducible: only a pinned, full object name is accepted.
    bad = commit_problem(root, commit)
    if bad is not None:
        return fail(bad)
    rel = dep.manifest_path
    bad = path_problem(rel)
    if bad is not None:
        return fail(f"path is not repo-relative and canonical: {bad}")
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


def verify_commits_exist(
    repo: str | Path,
    commits: list[str],
    *,
    ancestor_of: str | None = None,
    check_id: str = "G5",
    subject: str | None = None,
) -> list[GroundingResult]:
    """G5: every id in ``commits`` is a pinned commit of ``repo`` (full lowercase
    40/64-hex SHA that resolves to itself; WORKTREE is *not* accepted, an
    introducing commit must be a real commit) and, when ``ancestor_of`` is given,
    is that commit or one of its ancestors. One result per commit; an empty list
    gives one MISMATCH ("no commits given"). Never raises for bad ids; raises only
    if ``repo`` is not a git repository.
    """
    root = git.repo_root(repo)
    if not commits:
        return [_result(None, False, "no commits given", check_id, subject)]
    out: list[GroundingResult] = []
    for c in commits:
        shown = _show(c)[:12]
        try:
            bad = (
                f"unknown commit {c!r}: the working tree is not a commit"
                if c == WORKTREE
                else commit_problem(root, c)
            )
            if (
                bad is None
                and ancestor_of is not None
                and not git.is_ancestor(root, c, ancestor_of)
            ):
                bad = f"commit {c[:12]} is not an ancestor of {str(ancestor_of)[:12]}"
        except git.NotAGitRepoError:
            raise
        except Exception as exc:  # bad provenance is a MISMATCH, never a crash
            bad = f"could not verify ({type(exc).__name__}: {exc})"
        ok = bad is None
        reason = f"{shown}: commit exists" if ok else f"{shown}: {bad}"
        if ok and ancestor_of is not None:
            reason += f" and is in the history of {str(ancestor_of)[:12]}"
        out.append(_result(None, ok, reason, check_id, subject))
    return out


# --------------------------------------------------------------------------- G4


def _first_parent_set(root: Path, head: str) -> set[str]:
    return set(git._run(["rev-list", "--first-parent", f"{head}^{{commit}}"], root).split())


def _g4_violated(root: Path, claim, commit: str, config, adr_check: bool):
    """(violated, verdict, why) for ``claim`` at ``commit``, judged from scratch:
    offline judge, own snapshot, no cache. Violated = VIOLATED with VERIFIED
    grounding, and (when ``adr_check``) the claim's ADR file exists at ``commit``."""
    from driftwarden.judge.judge import Judge

    if adr_check and git.blob_at(root, commit, claim.source.path) is None:
        return False, None, f"ADR {claim.source.path} not present"
    try:
        verdict = Judge(root, commit=commit, mode="offline", config=config).judge(claim)
    except git.NotAGitRepoError:
        raise
    except git.GitError as exc:
        return False, None, f"tree not readable ({exc})"
    ok = verdict.status == "VIOLATED" and verdict.grounding == "VERIFIED"
    return ok, verdict, f"{verdict.status}/{verdict.grounding}"


def verify_first_violation(repo: str | Path, entry, claim, config=None) -> list[GroundingResult]:
    """G4: re-check a drift-timeline entry (``timeline.TimelineEntry``) from scratch.

    For a FOUND entry with commit C:

    (a) C and ``entry.head`` are pinned commits, C is on the first-parent history of
        head, and ``parent`` is C's first parent (``None`` only for a true root
        commit, not a shallow-clone boundary);
    (b) at C the claim is VERIFIED VIOLATED (offline judge, fresh snapshot), the entry
        cites evidence, every item is cited by that verdict and passes G2/G3
        (``judge.verify_evidence`` at C);
    (c) at the parent the claim is not VERIFIED VIOLATED;
    (d) ``subject`` and ``author_date`` match ``git log -1`` of C (subject sanitised
        as in ``undocumented.draft.sanitise_subject``).

    TRUNCATED entries: ``oldest_available`` is on head's first-parent history, the
    claim is VERIFIED VIOLATED there, and the stated truncation is real (a
    ``.git/shallow`` boundary, or a commit with parents for ``max_commits``).
    NOT_VIOLATED_AT_HEAD entries: the claim is not VERIFIED VIOLATED at head. UNKNOWN
    entries state nothing and get one MISMATCH. The ADR-presence rule follows the
    search: applied iff the claim's ADR file is committed at head.

    Every result has check_id ``G4``; any MISMATCH reason is precise. Plain and
    deterministic, no model. Never raises for a bad entry; raises only if ``repo``
    is not a git repository."""
    root = git.repo_root(repo)
    subj = f"{getattr(claim, 'id', '?')}/timeline"
    try:
        return _verify_first_violation(root, entry, claim, config, subj)
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # a bad entry is a MISMATCH, never a crash
        return [_result(None, False, f"could not verify ({type(exc).__name__}: {exc})", "G4", subj)]


def _verify_first_violation(root: Path, entry, claim, config, subj: str) -> list[GroundingResult]:
    from driftwarden.judge.judge import verify_evidence

    out: list[GroundingResult] = []

    def res(ok: bool, reason: str, prov=None) -> None:
        out.append(_result(prov, ok, reason, "G4", subj))

    if entry.claim_id != claim.id:
        res(False, f"entry is for claim {entry.claim_id!r}, not {claim.id!r}")
        return out
    if entry.status == "UNKNOWN":
        why = "; ".join(entry.reasons)[:300] or "no reason given"
        res(False, f"no first-violation result to verify: {why}")
        return out
    head = entry.head
    bad = commit_problem(root, head) if head is not None else "no head commit"
    if bad is not None:
        res(False, f"head: {bad}")
        return out
    try:
        adr_check = git.blob_at(root, head, claim.source.path) is not None
    except git.GitError:
        adr_check = False

    if entry.status == "NOT_VIOLATED_AT_HEAD":
        if entry.first_violating_commit is not None:
            res(False, "a NOT_VIOLATED_AT_HEAD entry must not name a first violating commit")
        violated, _v, why = _g4_violated(root, claim, head, config, adr_check)
        res(
            not violated,
            f"head {head[:12]}: claim is {why}"
            + (", not VERIFIED VIOLATED" if not violated else ", but entry says not violated"),
        )
        return out

    chain = _first_parent_set(root, head)
    if entry.status == "TRUNCATED":
        old = entry.oldest_available
        if entry.first_violating_commit is not None:
            res(False, "a TRUNCATED entry must not name a first violating commit (no guessing)")
        bad = commit_problem(root, old) if old is not None else "no oldest_available commit"
        if bad is not None:
            res(False, f"oldest_available: {bad}")
            return out
        if old not in chain:
            res(False, f"{old[:12]} is not on the first-parent history of {head[:12]}")
            return out
        if entry.truncated_by == "shallow":
            ok = old in git.shallow_boundary(root)
            what = "shallow-clone boundary" if ok else "not a shallow boundary"
            res(ok, f"{old[:12]}: {what}")
        elif entry.truncated_by == "max_commits":
            ok = bool(git.parents(root, old))
            res(ok, f"{old[:12]}: " + ("has parents beyond the cap" if ok else "is a root commit"))
        else:
            res(False, f"unknown truncation {entry.truncated_by!r}")
        violated, verdict, why = _g4_violated(root, claim, old, config, adr_check)
        res(violated, f"{old[:12]}: claim is {why}" + ("" if violated else ", not VIOLATED"))
        if violated:
            out.extend(_g4_evidence(root, entry.evidence, verdict, old, subj, verify_evidence))
        return out

    if entry.status != "FOUND":
        res(False, f"unknown entry status {entry.status!r}")
        return out

    # (a) commit and parent
    c = entry.first_violating_commit
    bad = commit_problem(root, c) if c is not None else "no first_violating_commit"
    if bad is not None:
        res(False, f"(a) commit: {bad}")
        return out
    if c not in chain:
        res(False, f"(a) {c[:12]} is not on the first-parent history of {head[:12]}")
        return out
    parents = git.parents(root, c)
    if entry.parent is None:
        if parents:
            res(False, f"(a) parent is None but {c[:12]} has first parent {parents[0][:12]}")
            return out
        if c in git.shallow_boundary(root):
            res(False, f"(a) {c[:12]} is a shallow-clone boundary, not a root commit")
            return out
        res(True, f"(a) {c[:12]} is the root commit")
    else:
        bad = commit_problem(root, entry.parent)
        if bad is not None:
            res(False, f"(a) parent: {bad}")
            return out
        if not parents or parents[0] != entry.parent:
            first = parents[0][:12] if parents else "none"
            res(False, f"(a) {entry.parent[:12]} is not the first parent of {c[:12]} ({first})")
            return out
        res(True, f"(a) {entry.parent[:12]} is the first parent of {c[:12]}")

    # (b) violated at C, evidence verifies and is the verdict's
    violated, verdict, why = _g4_violated(root, claim, c, config, adr_check)
    if not violated:
        res(False, f"(b) at {c[:12]} the claim is {why}, not VERIFIED VIOLATED")
    else:
        res(True, f"(b) at {c[:12]} the claim is VERIFIED VIOLATED")
        if not entry.evidence:
            res(False, f"(b) entry cites no evidence at {c[:12]}")
        out.extend(_g4_evidence(root, entry.evidence, verdict, c, subj, verify_evidence))

    # (c) not violated at the parent
    if entry.parent is not None:
        pv, _v, pwhy = _g4_violated(root, claim, entry.parent, config, adr_check)
        res(
            not pv,
            f"(c) at parent {entry.parent[:12]} the claim is {pwhy}"
            + (" (not violated)" if not pv else ": already violated, so not the first commit"),
        )

    # (d) subject and date
    from driftwarden.undocumented.draft import sanitise_subject

    logs = git.log(root, max_count=1, rev=c)
    if not logs or logs[0].sha != c:
        res(False, f"(d) no git log entry for {c[:12]}")
        return out
    want_subject = sanitise_subject(logs[0].subject)
    problems = []
    if entry.subject != want_subject:
        problems.append(f"subject {entry.subject!r} != git log {want_subject!r}")
    if entry.author_date != logs[0].date:
        problems.append(f"author_date {entry.author_date!r} != git log {logs[0].date!r}")
    res(not problems, f"(d) {c[:12]}: " + ("; ".join(problems) or "subject and date match"))
    return out


def _g4_evidence(root, evidence, verdict, commit, subj, verify_evidence) -> list[GroundingResult]:
    """One G4 result per evidence item: cited by ``verdict`` at ``commit`` and G2/G3-verified."""
    cited = [e.model_dump() for e in verdict.evidence] if verdict is not None else []
    out = []
    for ev in evidence:
        problems = []
        if ev.model_dump() not in cited:
            problems.append(f"not among the evidence the verdict at {commit[:12]} cites")
        for r in verify_evidence(root, ev, commit=commit, subject=subj):
            if r.status != "VERIFIED":
                problems.append(f"{r.check_id}: {r.reason}")
        ok = not problems
        reason = f"(b) evidence {ev.id}: " + ("; ".join(problems) if problems else "G2/G3 verified")
        out.append(_result(ev.ref, ok, reason, "G4", subj))
    return out
