"""ADR drafter for undocumented decisions (pipeline step 8, grounding G5).

:func:`draft_adr` turns a VERIFIED :class:`UndocumentedDecision` into a MADR
draft built only from what the repository shows; :func:`verify_draft` is the G5
gate every draft passes before it is returned (and that anyone can re-run on a
draft later). Offline and deterministic by default; no network.

**The draft.** MADR with YAML front-matter (``status: proposed (draft)``, ``date``
= author date of the oldest introducing commit, the record id and the scanned
commit), the title ``Use <technology> for <category>``, a context paragraph of
verified facts, *Considered Options*, *Decision Outcome* and *Consequences* left
as explicit ``TODO: confirm`` items (the reasons for a choice are not in the
repository, so none are written), and a *More Information* section of
citations:

* ``- Commit `<sha>`, <YYYY-MM-DD>: <subject>`` for each introducing commit
  (author date and subject line only; no author names). The subject is
  sanitised: control / format / separator characters become spaces, and runs of
  7+ hex digits and ``path:line``-like tokens become ``[ref removed]``, so a
  commit message cannot put a foreign SHA or source reference into the draft;
* ``- [<evidence id>] <path> lines <a>-<b> at `<sha>`<detail>:`` (the path as a
  backtick code span long enough for any backticks in it) followed by a fenced
  block holding the verbatim quote, once for each introducing line (at its
  introducing commit; detail ``, introduced``) and once for each evidence item
  (at the scanned commit; detail = kind, and for a manifest item the package,
  version spec, ecosystem and scope that G3 re-checks).

**The gate** (:func:`verify_draft`, fail closed). The record is re-verified from
scratch (``verify_undocumented``: G2/G3 on the evidence, G5 on the introductions).
The draft text is then **pinned to the record**: it must be byte-for-byte the
rendering of the record (commit dates and subjects read from git again). For an
``origin="llm"`` draft only the context paragraph may differ, and that paragraph
must pass the polish checks below. So no heading, front-matter, status line,
list item, rationale, SHA, reference or number can be added, removed or changed
anywhere else. Then every cited quote passes ``verify_source_quote`` (G2) at its
commit, every manifest item ``verify_dependency`` (G3), every cited commit
``verify_commits_exist`` with the scanned commit as ``ancestor_of`` (G5), and the
draft must parse back through ``discover.adr.parse_adr`` with the expected title
and status ``proposed``. Any failure makes the draft ``status=UNKNOWN,
grounding=MISMATCH`` with the reasons: it is shown as *Could not verify*, never
as a draft. A record that is itself *Could not verify* yields no draft at all.

**LLM path (opt-in).** The default is the deterministic template
(``provider=None``; an offline provider is never called). Only when the caller
passes a non-offline ``provider`` may the model rewrite the context paragraph
(one JSON string). Its text is never trusted for facts. It is rejected, and the
template draft returned with a note, when it is not a single plain ASCII
paragraph; when it contains markdown structure (headings, lists, ordered lists,
quotes, tables, fences), HTML or ``<``/``>``, links or URLs, a ``status:``; when
it has any run of 7+ hex digits that is not a backticked abbreviation of one of
the record's commits (a bare all-digit run is a number, never a commit
reference), or any ``path:line``-like token; when it has any number that is not
one of the template paragraph's own count / date tokens (digits inside SHAs never
count); when the provider raises anything; or when the assembled draft fails the
gate. **Known limit:** the gate checks structure, references and numbers, not
meaning; a model sentence that invents a reason, a benefit, a person or an
alternative in plain words ("chosen because it is fast") cannot be detected by a
deterministic check. That is why the LLM path is opt-in and its prompt forbids
it; such text is confined to the context paragraph.

**Files.** ``path`` is a suggestion, ``<adr dir>/NNNN-use-<tech>-for-<category>.md``
with NNNN the next free number among the ADRs discovered at the scanned commit and
in the working tree (date-prefixed names such as ``2026-01-11-x.md`` are not
numbers); the ADR directory is where the existing ADRs live, else ``docs/adr``
(paths that are not canonical repo-relative paths are ignored). Nothing is
written unless ``write=True`` and the draft verified. A write never overwrites a
file, never follows a symlinked directory or file, never leaves the repository,
and is idempotent: if an ADR whose front-matter names the same
``driftwarden-record`` already exists *and verifies against the record*, its path
is returned instead (a file that only names the record is reported in a note and
ignored). The file is published atomically (temporary file in the same
directory, fsync, hard link that fails if the name exists), so a failed write
never leaves a partial draft behind. A write that cannot happen leaves the
draft as is with a note.

**Untrusted values.** Manifest-derived fields (package, version spec, ecosystem,
scope), paths, evidence ids and the record id are rendered as single-line code
spans: newlines, control, format and separator characters become visible
escapes (``\\n``, ``\\uXXXX``) and long values are capped, so a value such as a
``package.json`` version containing ``"\\n\\n## Security"`` cannot add markdown
structure. When the detector listed only some occurrences (it always keeps the
oldest introduction), the context says the cited occurrences were introduced by
those commits and that further occurrences are not cited.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import secrets
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from driftwarden import git
from driftwarden.config import Config
from driftwarden.discover.adr import discover_adr_files, parse_adr, scan_adrs_at
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import (
    commit_problem,
    path_problem,
    verify_commits_exist,
    verify_dependency,
    verify_source_quote,
)
from driftwarden.judge import catalog
from driftwarden.llm.base import Provider
from driftwarden.models import (
    Claim,
    Decision,
    Evidence,
    GroundingResult,
    Provenance,
    UndocumentedDecision,
    VerdictGrounding,
)
from driftwarden.text import split_lines
from driftwarden.undocumented.detect import CATEGORY_LABELS, verify_undocumented

DRAFT_STATUS = "proposed (draft)"
DEFAULT_ADR_DIR = "docs/adr"
TODO = "TODO: confirm"
REF_REMOVED = "[ref removed]"

DraftStatus = Literal["DRAFT", "UNKNOWN"]
DraftOrigin = Literal["template", "llm"]


class DraftADR(BaseModel):
    """A drafted ADR for one undocumented decision, with its G5 gate result.

    Invariant (enforced): a draft that is not VERIFIED has status UNKNOWN and
    reasons, and is shown as *Could not verify*; a DRAFT has markdown.
    """

    record_id: str
    technology: str
    category: str
    title: str = ""
    status: DraftStatus = "DRAFT"
    markdown: str | None = Field(default=None, description="The MADR text; None if not drafted.")
    number: int | None = Field(default=None, description="Suggested ADR number.")
    path: str | None = Field(default=None, description="Suggested repo-relative file path.")
    origin: DraftOrigin = "template"
    record: UndocumentedDecision
    cited_commits: list[str] = Field(default_factory=list, description="Full SHAs cited.")
    evidence_refs: list[Provenance] = Field(default_factory=list, description="Refs cited.")
    grounding: VerdictGrounding = "VERIFIED"
    reasons: list[str] = Field(default_factory=list, description="Why not verified.")
    checks: list[GroundingResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    written_path: str | None = Field(
        default=None, description="The file holding this draft after write=True."
    )

    @property
    def could_not_verify(self) -> bool:
        return self.grounding != "VERIFIED"

    @property
    def display_status(self) -> str:
        return "Could not verify" if self.could_not_verify else "Draft"

    @model_validator(mode="after")
    def _invariants(self) -> DraftADR:
        if self.grounding != "VERIFIED" and self.status != "UNKNOWN":
            raise ValueError("a draft that is not VERIFIED must have status UNKNOWN")
        if self.grounding != "VERIFIED" and not self.reasons:
            raise ValueError("a draft that is not VERIFIED needs reasons")
        if self.status == "DRAFT" and not self.markdown:
            raise ValueError("a DRAFT must carry markdown")
        return self


# --------------------------------------------------------------------------- naming


def technology_name(technology: str) -> str:
    """Display name: the catalog's first alias (or the id), first letter capitalised."""
    t = catalog.technology(technology)
    name = t.aliases[0] if t is not None and t.aliases else technology
    name = name[:1].upper() + name[1:] if name.islower() else name
    return _escape(name, 80)


def draft_title(technology: str, category: str) -> str:
    label = CATEGORY_LABELS.get(category, category)
    return f"Use {_escape(technology_name(technology), 80)} for {_escape(label, 80)}"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def draft_filename(number: int, technology: str, category: str) -> str:
    return f"{number:04d}-use-{_slug(technology)}-for-{_slug(category)}.md"


_NUM = re.compile(r"^(?:adr[-_]?)?(\d+)(?=[-_.]|$)", re.IGNORECASE)
_ISO_DATE = re.compile(r"^(?:adr[-_]?)?\d{4}-\d{2}-\d{2}(?!\d)", re.IGNORECASE)


def _is_date(digits: str) -> bool:
    if len(digits) != 8:
        return False
    try:
        _dt.date(int(digits[:4]), int(digits[4:6]), int(digits[6:]))
    except ValueError:
        return False
    return True


def next_adr_number(paths: Iterable[str]) -> int:
    """One more than the highest number leading an ADR file name (1 when none).

    Date-prefixed names (``2026-01-11-x.md``, ``20260111-x.md``) carry no number."""
    nums: list[int] = []
    for p in paths:
        name = Path(p).name
        if _ISO_DATE.match(name):
            continue
        m = _NUM.match(name)
        if m and not _is_date(m.group(1)):
            nums.append(int(m.group(1)))
    return max(nums, default=0) + 1


def _adr_dir(paths: list[str]) -> str:
    dirs = Counter(Path(p).parent.as_posix() for p in paths)
    dirs.pop(".", None)
    if not dirs:
        return DEFAULT_ADR_DIR
    best = max(dirs.values())
    return sorted(d for d, n in dirs.items() if n == best)[0]


def _existing_adrs(root: Path, commit: str, config: Config | None) -> list[str]:
    paths: set[str] = set()
    try:
        paths.update(d.source.path for d in scan_adrs_at(root, commit, config).decisions)
    except git.NotAGitRepoError:
        raise
    except git.GitError:
        pass
    paths.update(discover_adr_files(root, config))
    return sorted(paths)


# --------------------------------------------------------------------------- rendering


@dataclass(frozen=True)
class _CommitInfo:
    date: str  # YYYY-MM-DD, author date
    subject: str  # sanitised


_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{7,}(?![0-9A-Za-z])")
# Matches start only at the beginning of a run (linear time on long tokens).
_REF = re.compile(r"(?<![^\s`:])(?P<path>[^\s`:]+):(?P<a>\d+)(?:-(?P<b>\d+))?")


def sanitise_subject(subject: str) -> str:
    """A commit subject safe to quote in a draft: no control / format / separator
    characters, no SHA-like hex runs, no ``path:line`` references."""
    chars = [" " if (ch != " " and unicodedata.category(ch)[0] in "CZ") else ch for ch in subject]
    text = "".join(chars)
    text = _HEX_RUN.sub(REF_REMOVED, text)
    return _REF.sub(lambda m: m.group(0) if m["path"].isdigit() else REF_REMOVED, text)


def _commit_info(root: Path, sha: str) -> _CommitInfo:
    entries = git.log(root, max_count=1, rev=sha)
    if not entries or entries[0].sha != sha:
        raise git.GitError(f"no log entry for {sha[:12]}")
    return _CommitInfo(date=entries[0].date[:10], subject=sanitise_subject(entries[0].subject))


def _short(sha: str) -> str:
    return sha[:12]


def _code(text: str) -> str:
    """``text`` as a markdown code span, whatever backticks it holds."""
    runs = [len(m.group(0)) for m in re.finditer(r"`+", text)]
    if not runs:
        return f"`{text}`"
    ticks = "`" * (max(runs) + 1)
    return f"{ticks} {text} {ticks}"


INLINE_CAP = 160


def _escape(text: str, cap: int = INLINE_CAP) -> str:
    """One visible line for an untrusted value (manifest fields, paths, ids): control,
    format and separator characters become ``\\n`` / ``\\uXXXX`` escapes, and the
    result is capped at ``cap`` characters."""
    out: list[str] = []
    for ch in text:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch != " " and unicodedata.category(ch)[0] in "CZ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= cap else s[:cap] + "..."


def _inline(text: str) -> str:
    """An untrusted value as a single-line, backtick-safe code span."""
    return _code(_escape(text))


def _fence(quote: str) -> str:
    runs = [len(m.group(0)) for m in re.finditer(r"`+", quote)]
    return "`" * max(3, max(runs, default=0) + 1)


def _evidence_detail(ev: Evidence) -> str:
    """Every manifest-derived value is untrusted: each is an escaped code span."""
    d = ev.dependency
    kind = _inline(ev.kind)
    if d is None:
        return f", {kind}"
    spec = _inline(d.version_spec) if d.version_spec is not None else "unversioned"
    eco = _inline(d.ecosystem) if d.ecosystem else "?"
    scope = f", scope {_inline(d.scope)}" if d.scope else ""
    return f", {kind} {_inline(d.package)} {spec} ({eco}{scope})"


INTRO_DETAIL = ", introduced"


def _cite_line(eid: str, ref: Provenance, detail: str) -> str:
    span = f"lines {ref.line_start}-{ref.line_end}"
    return f"- [{_escape(eid, 40)}] {_inline(ref.path)} {span} at `{ref.commit}`{detail}:"


def _cite_block(eid: str, ref: Provenance, detail: str) -> list[str]:
    fence = _fence(ref.quote)
    return [_cite_line(eid, ref, detail), "", f"{fence}text", *split_lines(ref.quote), fence, ""]


def _commit_line(sha: str, info: _CommitInfo) -> str:
    return f"- Commit `{sha}`, {info.date}: {info.subject}"


def template_context(rec: UndocumentedDecision, infos: dict[str, _CommitInfo]) -> str:
    """The deterministic context paragraph: verified facts only."""
    name = technology_name(rec.technology)
    label = CATEGORY_LABELS.get(rec.category, rec.category)
    files = sorted({e.ref.path for e in rec.evidence})
    n_ev, n_files = len(rec.evidence), len(files)
    intros = rec.introducing_commits
    first = intros[0]
    when = f"commit `{_short(first)}` ({infos[first].date})"
    if len(intros) > 1:
        last = intros[-1]
        when = (
            f"{len(intros)} commits, from `{_short(first)}` ({infos[first].date}) "
            f"to `{_short(last)}` ({infos[last].date})"
        )
    intro = f"{name} was introduced by {when}."
    if _sampled(rec):
        intro = (
            f"The cited occurrences were introduced by {when}. Further occurrences exist "
            "in the code and are not cited."
        )
    return (
        f"The code at commit `{_short(rec.commit)}` uses {name} as {label}: "
        f"{n_ev} production occurrence{'s' if n_ev != 1 else ''} in {n_files} "
        f"file{'s' if n_files != 1 else ''}, cited below. No ADR in this repository "
        f"records that decision. {intro}"
    )


def _sampled(rec: UndocumentedDecision) -> bool:
    """True when the detector listed only some of the occurrences (its note says so)."""
    return any(re.match(r"\d+ further occurrence", n) for n in rec.notes)


_NOTICE = (
    "This draft was generated by DriftWarden from the repository history. Every commit "
    "and source line it cites was checked against the repository; the repository does "
    "not record why the choice was made, so the reasons are left as TODO items for the "
    "team to fill in before accepting it."
)


def render_markdown(
    rec: UndocumentedDecision, infos: dict[str, _CommitInfo], context: str | None = None
) -> str:
    """The MADR text for ``rec``; ``context`` replaces the template paragraph."""
    name = technology_name(rec.technology)
    first = rec.introducing_commits[0]
    lines = [
        "---",
        f"status: {DRAFT_STATUS}",
        f"date: {infos[first].date}",
        f"driftwarden-record: {_escape(rec.id, 120)}",
        f"driftwarden-commit: {rec.commit}",
        "---",
        "",
        f"# {draft_title(rec.technology, rec.category)}",
        "",
        "## Context and Problem Statement",
        "",
        context if context is not None else template_context(rec, infos),
        "",
        _NOTICE,
        "",
        "## Considered Options",
        "",
        f"* {name} (in use)",
        f"* {TODO} which alternatives were considered.",
        "",
        "## Decision Outcome",
        "",
        f'Chosen option: "{name}", because {TODO}. The repository does not record the reasons.',
        "",
        "### Consequences",
        "",
        f"* {TODO} the good and bad consequences of this choice.",
        "",
        "## More Information",
        "",
        "### Introducing commits",
        "",
        *(_commit_line(c, infos[c]) for c in rec.introducing_commits),
        "",
        "### Where it was introduced",
        "",
    ]
    for intro in rec.introductions:
        lines += _cite_block(intro.evidence_id, intro.ref, INTRO_DETAIL)
    lines += [f"### Where it is used at `{_short(rec.commit)}`", ""]
    for ev in rec.evidence:
        lines += _cite_block(ev.id, ev.ref, _evidence_detail(ev))
    return "\n".join(lines).rstrip("\n") + "\n"


# --------------------------------------------------------------------------- polish checks

_SHA_TOKEN = re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{7,64}(?![0-9a-z])")
_ORDERED = re.compile(r"(?:^|\s)\d+[.)](?:\s|$)")
_STATUS = re.compile(r"(?i)\bstatus\s*:")
_REFLIKE = re.compile(r"(?<![\w./-])[\w./-]+:\d")
_STRUCT_START = ("#", "-", "*", "+", ">", "=")


def _record_commits(rec: UndocumentedDecision) -> list[str]:
    return list(dict.fromkeys([*rec.introducing_commits, rec.commit]))


_TICKED = re.compile(r"`([^`\s]+)`")


def _strip_record_shas(text: str, commits: list[str]) -> tuple[str, list[str]]:
    """``text`` with every commit reference removed, and the hex runs that are not one.

    A commit reference is a backtick code span holding a lowercase abbreviation (7+
    hex) of a record commit, the way the template writes them. Any other hex run is
    not a reference: inside backticks it is foreign; bare in the prose, a run of
    decimal digits only is a *number* (left for the number check: it is allowed only
    if it is one of the template's own count / date tokens) and any other run is
    foreign, even when it happens to abbreviate a record commit."""
    foreign: list[str] = []

    def ticked(m: re.Match[str]) -> str:
        tok = m.group(1)
        if _SHA_TOKEN.fullmatch(tok):
            if tok == tok.lower() and any(c.startswith(tok) for c in commits):
                return " "
            foreign.append(tok)
            return " "
        return m.group(0)

    def bare(m: re.Match[str]) -> str:
        tok = m.group(0)
        if tok.isdigit():
            return tok
        foreign.append(tok)
        return " "

    return _SHA_TOKEN.sub(bare, _TICKED.sub(ticked, text)), foreign


def polish_problems(text: str, template: str, rec: UndocumentedDecision) -> list[str]:
    """Why ``text`` may not replace the template context paragraph ([] when it may)."""
    problems: list[str] = []
    if not text.strip():
        return ["model text is empty"]
    if text != text.strip() or "\n" in text or "\r" in text:
        problems.append("model text is not a single trimmed paragraph")
    if any(not (32 <= ord(ch) < 127) for ch in text):
        problems.append("model text has non-ASCII or control characters")
    s = text.strip()
    if s.startswith(_STRUCT_START) or any(t in s for t in ("```", "~~~", "|")):
        problems.append("model text contains markdown structure")
    if _ORDERED.search(s):
        problems.append("model text contains an ordered list")
    if any(t in s for t in ("<", ">", "](", "://", "www.")):
        problems.append("model text contains HTML, a link or a URL")
    if _STATUS.search(s):
        problems.append("model text contains a status")
    commits = _record_commits(rec)
    bare, foreign = _strip_record_shas(s, commits)
    if foreign:
        problems.append(f"model text has hex runs that are not record commits: {foreign[:3]}")
    if _REFLIKE.search(bare):
        problems.append("model text contains a path:line-like reference")
    t_bare, _ = _strip_record_shas(template, commits)
    allowed = set(re.findall(r"[0-9]+", t_bare))
    extra = sorted(set(re.findall(r"[0-9]+", bare)) - allowed)
    if extra:
        problems.append(f"model text has numbers that are not facts of the record: {extra[:5]}")
    return problems


# --------------------------------------------------------------------------- the G5 gate

_SENTINEL = "\x00DRIFTWARDEN-CONTEXT\x00"


def _first_difference(got: str, want: str) -> str:
    g, w = got.split("\n"), want.split("\n")
    for i in range(max(len(g), len(w))):
        a = g[i] if i < len(g) else "<end of text>"
        b = w[i] if i < len(w) else "<end of text>"
        if a != b:
            return f"line {i + 1}: {a[:80]!r}, expected {b[:80]!r}"
    return "trailing text differs"


def verify_draft(
    repo: str | Path,
    draft: DraftADR,
    *,
    decisions: Iterable[Decision] | None = None,
    claims: Iterable[Claim] = (),
    config: Config | None = None,
    ledger: Ledger | None = None,
) -> DraftADR:
    """G5 gate: re-verify ``draft`` (see the module docstring). Returns the draft with
    ``checks`` replaced and ``status/grounding/reasons`` set: DRAFT / VERIFIED, or
    UNKNOWN / MISMATCH with every reason. Never raises for a bad draft; raises only
    if ``repo`` is not a git repository. ``decisions`` (optional) re-runs the
    "no ADR mentions it" check of the record; ``config`` must be the one the record
    was detected with (its exclusions decide how imports resolve)."""
    root = git.repo_root(repo)
    decisions = list(decisions) if decisions is not None else None
    claims = tuple(claims)
    checks: list[GroundingResult] = []
    reasons: list[str] = []
    subj = f"draft:{draft.record_id}"
    cited_commits: list[str] = []
    cited_refs: list[Provenance] = []

    def result(ok: bool, reason: str, prov=None, cid: str = "G5") -> None:
        checks.append(
            GroundingResult(
                check_id=cid,
                status="VERIFIED" if ok else "MISMATCH",
                reason=reason,
                provenance=prov,
                subject=subj,
            )
        )
        if not ok:
            reasons.append(reason)

    def fail(reason: str, prov=None, cid: str = "G5") -> None:
        result(False, reason, prov, cid)

    rec = draft.record
    try:
        want_title = draft_title(rec.technology, rec.category)
        if (draft.record_id, draft.technology, draft.category, draft.title) != (
            rec.id, rec.technology, rec.category, want_title,
        ):  # fmt: skip
            fail("draft header (record id, technology, category, title) does not match its record")
        vrec = verify_undocumented(root, rec, decisions=decisions, claims=claims, config=config)
        checks.extend(vrec.checks)
        reasons.extend(f"record: {r}" for r in vrec.reasons)
        md = draft.markdown
        if not md:
            fail("no draft text")
        elif not rec.introducing_commits or any(
            commit_problem(root, c) is not None for c in rec.introducing_commits
        ):
            fail("the record's introducing commits cannot be read; nothing to compare with")
        else:
            infos = {c: _commit_info(root, c) for c in rec.introducing_commits}
            _check_text(rec, md, draft.origin, infos, fail, result)
            _check_citations(root, rec, result, cited_refs)
            commits = _record_commits(rec)
            for r in verify_commits_exist(root, commits, ancestor_of=rec.commit, subject=subj):
                checks.append(r)
                if r.status != "VERIFIED":
                    reasons.append(r.reason)
            cited_commits.extend(commits)
            dec = parse_adr(md, "docs/adr/draft.md", rec.commit)
            ok = dec.title == want_title and dec.status == "proposed"
            result(
                ok,
                f"draft parses back with title {dec.title!r} and status {dec.status!r}"
                + ("" if ok else f" (expected {want_title!r}, 'proposed')"),
            )
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # a bad draft is a MISMATCH, never a crash
        fail(f"could not verify ({type(exc).__name__}: {exc})")

    if ledger is not None:
        ledger.extend(checks)
    data = draft.model_dump()
    data.update(checks=checks, cited_commits=cited_commits, evidence_refs=cited_refs)
    if reasons:
        data.update(status="UNKNOWN", grounding="MISMATCH", reasons=reasons)
    else:
        data.update(status="DRAFT", grounding="VERIFIED", reasons=[])
    try:
        return DraftADR.model_validate(data)
    except ValueError as exc:  # a forged, unvalidated draft (model_copy/model_construct)
        reason = f"draft is not a valid DraftADR ({type(exc).__name__})"
        data.update(status="UNKNOWN", grounding="MISMATCH", reasons=[*reasons, reason])
        return DraftADR.model_construct(**data)


def _check_text(rec, md: str, origin: str, infos, fail, result) -> None:
    """The draft text must be the record's rendering (``origin='llm'``: except for a
    context paragraph that passes the polish checks)."""
    template = render_markdown(rec, infos)
    if origin == "llm":
        pre, post = render_markdown(rec, infos, _SENTINEL).split(_SENTINEL)
        if len(md) < len(pre) + len(post) or not (md.startswith(pre) and md.endswith(post)):
            fail(
                f"draft text outside the context paragraph differs from the rendering of "
                f"{rec.id} ({_first_difference(md, template)})"
            )
            return
        ctx = md[len(pre) : len(md) - len(post)]
        problems = polish_problems(ctx, template_context(rec, infos), rec)
        for p in problems:
            fail(f"context paragraph: {p}")
        if not problems:
            result(True, f"draft text is the rendering of {rec.id} with a checked context")
        return
    if md != template:
        fail(
            f"draft text differs from the rendering of {rec.id} ({_first_difference(md, template)})"
        )
    else:
        result(True, f"draft text is exactly the rendering of {rec.id}")


def _check_citations(root: Path, rec, result, cited_refs: list[Provenance]) -> None:
    by_id = {e.id: e for e in rec.evidence}
    items = [(i.evidence_id, i.ref, None) for i in rec.introductions]
    items += [(e.id, e.ref, e) for e in rec.evidence]
    for eid, ref, ev in items:
        g2 = verify_source_quote(root, ref, check_id="G2", subject=f"draft:{rec.id}/{eid}")
        result(g2.status == "VERIFIED", f"[{eid}] {g2.reason}", ref, "G2")
        if g2.status == "VERIFIED":
            cited_refs.append(ref)
        if eid not in by_id:
            result(False, f"[{eid}] cites no evidence item of {rec.id}")
        if ev is not None and ev.dependency is not None:
            g3 = verify_dependency(root, ev.dependency, subject=f"draft:{rec.id}/{eid}")
            result(g3.status == "VERIFIED", f"[{eid}] {g3.reason}", ev.dependency, "G3")


# --------------------------------------------------------------------------- LLM polish

POLISH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["context"],
    "additionalProperties": False,
    "properties": {"context": {"type": "string", "minLength": 1, "maxLength": 2000}},
}
POLISH_SYSTEM = (
    "You edit the context paragraph of a draft Architecture Decision Record. Improve "
    "only its wording. Keep every fact exactly as given and add none: no reasons for "
    "the choice, no benefits, no alternatives, no names of people, no new numbers, "
    "dates, versions, commit ids, links or file references. Keep commit ids in "
    "backticks as given. One plain ASCII paragraph, no markdown structure."
)


def _polish(provider: Provider, rec: UndocumentedDecision, template: str) -> tuple[str | None, str]:
    prompt = (
        f"Technology: {technology_name(rec.technology)}\n"
        f"Category: {CATEGORY_LABELS.get(rec.category, rec.category)}\n\n"
        f"Context paragraph to edit:\n{template}\n"
    )
    try:
        res = provider.complete_json(
            prompt, POLISH_SCHEMA, system=POLISH_SYSTEM, purpose=f"adr-draft:{rec.id}"
        )
        value = res.value.get("context") if isinstance(res.value, dict) else None
    except Exception as exc:  # third-party code: any failure means "keep the template"
        return None, f"LLM polish failed ({type(exc).__name__}): template text kept"
    if not isinstance(value, str):
        return None, "LLM polish returned no context string: template text kept"
    problems = polish_problems(value, template, rec)
    if problems:
        return None, f"LLM polish rejected ({'; '.join(problems)}): template text kept"
    return value, ""


# --------------------------------------------------------------------------- drafting


def draft_adr(
    repo: str | Path,
    record: UndocumentedDecision,
    *,
    provider: Provider | None = None,
    existing_adrs: Iterable[str] | None = None,
    decisions: Iterable[Decision] | None = None,
    claims: Iterable[Claim] = (),
    config: Config | None = None,
    write: bool = False,
    ledger: Ledger | None = None,
) -> DraftADR:
    """A MADR draft for ``record``, passed through :func:`verify_draft`.

    A record that is *Could not verify* (or fails re-verification) yields no draft:
    the result has ``status=UNKNOWN``, no markdown, and the reasons. The default is
    the deterministic template; a non-offline ``provider`` opts in to an LLM polish
    of the context paragraph (see the module docstring). ``existing_adrs``
    (repo-relative ADR paths) fixes the numbering; by default the ADRs at the
    record's commit and in the working tree are discovered. Nothing is written
    unless ``write=True``; see the module docstring for the write rules. ``config``
    must be the one the record was detected with; it reaches every gate call.
    ``decisions`` and ``claims`` are read once (a generator is fine)."""
    root = git.repo_root(repo)
    decisions = list(decisions) if decisions is not None else None
    claims = tuple(claims)
    title = draft_title(record.technology, record.category)
    raw_paths = (
        list(existing_adrs)
        if existing_adrs is not None
        else _existing_adrs(root, record.commit, config)
    )
    paths = sorted(p for p in raw_paths if isinstance(p, str) and path_problem(p) is None)
    number = next_adr_number(paths)
    rel = f"{_adr_dir(paths)}/{draft_filename(number, record.technology, record.category)}"
    base: dict[str, Any] = dict(
        record_id=record.id,
        technology=record.technology,
        category=record.category,
        title=title,
        number=number,
        path=rel,
        record=record,
    )

    def refused(reasons: list[str], checks: list[GroundingResult] | None = None) -> DraftADR:
        data = {**base, "number": None, "path": None}
        return DraftADR(
            **data, status="UNKNOWN", grounding="MISMATCH", reasons=reasons or ["not verified"],
            checks=checks or [], markdown=None,
        )  # fmt: skip

    if record.could_not_verify:
        return refused([f"record is Could not verify: {r}" for r in record.reasons])
    try:
        if not record.introducing_commits or any(
            commit_problem(root, c) is not None for c in record.introducing_commits
        ):
            return refused(["record's introducing commits are not pinned commits of this repo"])
        infos = {c: _commit_info(root, c) for c in record.introducing_commits}
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # unreadable or unparsable commit metadata: refuse, never raise
        return refused([f"introducing commit unreadable ({type(exc).__name__}: {exc})"])

    notes: list[str] = []
    template = template_context(record, infos)
    drafts: list[tuple[DraftOrigin, str]] = []
    if provider is not None and not getattr(provider, "offline", True):
        text, note = _polish(provider, record, template)
        if text is not None:
            drafts.append(("llm", render_markdown(record, infos, text)))
        else:
            notes.append(note)
    drafts.append(("template", render_markdown(record, infos)))

    result: DraftADR | None = None
    for origin, md in drafts:
        cand = DraftADR(**base, markdown=md, origin=origin, notes=list(notes))
        result = verify_draft(root, cand, decisions=decisions, claims=claims, config=config)
        if not result.could_not_verify:
            break
        if origin == "llm":
            notes.append(f"LLM draft failed the gate ({'; '.join(result.reasons[:3])}): "
                         "template text kept")  # fmt: skip
    assert result is not None
    if ledger is not None:
        ledger.extend(result.checks)
    if result.could_not_verify:
        return refused(result.reasons, result.checks)
    result = result.model_copy(update={"notes": notes})
    if write:
        result = _write(root, result, config)
    return result


# --------------------------------------------------------------------------- writing

_FM_RECORD = re.compile(r"^driftwarden-record:\s*(\S+)\s*$")


def _drafted_record(path: Path) -> str | None:
    """The ``driftwarden-record`` named in the front-matter of ``path``, or None."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = [fh.readline() for _ in range(12)]
    except OSError:
        return None
    if not head or head[0].rstrip("\r\n") != "---":
        return None
    for line in head[1:]:
        line = line.rstrip("\r\n")
        if line == "---":
            return None
        m = _FM_RECORD.match(line)
        if m:
            return m.group(1)
    return None


def _existing_draft(
    root: Path, draft: DraftADR, config: Config | None
) -> tuple[str | None, DraftADR | None, list[str]]:
    """An ADR file that already holds a draft of this record *and verifies* against it
    (exactly the template rendering, or an LLM-polished rendering that passes the
    gate), the verified draft *of that file's text*, and notes about files that only
    claim to (truncated, edited, stale)."""
    cands: set[str] = set(discover_adr_files(root, config))
    if draft.path is not None:
        d = root / Path(draft.path).parent
        if d.is_dir() and not d.is_symlink():
            cands.update(
                p.relative_to(root).as_posix() for p in d.iterdir() if p.suffix.lower() == ".md"
            )
    notes: list[str] = []
    for rel in sorted(cands):
        if _drafted_record(root / rel) != draft.record_id:
            continue
        try:
            text = (root / rel).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            text = None
        if text is not None:
            if text == draft.markdown:
                return rel, draft, notes
            for origin in ("template", "llm"):
                cand = draft.model_copy(update={"markdown": text, "origin": origin})
                res = verify_draft(root, cand, config=config)
                if not res.could_not_verify:
                    return rel, res, notes
        notes.append(f"{rel} names {draft.record_id} but does not verify; not treated as a draft")
    return None, None, notes


def _publish(target: Path, data: bytes) -> None:
    """Create ``target`` holding ``data`` atomically: write a temporary file in the same
    directory, fsync it, then hard-link it into place (fails if ``target`` exists, so
    nothing is ever overwritten). The temporary file is always removed; on failure
    ``target`` does not exist (unless it existed before)."""
    tmp = target.with_name(f".{target.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(tmp, flags, 0o644)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(tmp, target)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _unsafe_dir(root: Path, rel_dir: str) -> str | None:
    """Why the directory ``rel_dir`` cannot safely receive a file, or None."""
    cur = root
    for seg in Path(rel_dir).parts:
        cur = cur / seg
        if cur.is_symlink():
            return f"{cur.relative_to(root).as_posix()} is a symlink"
        if os.path.lexists(cur) and not cur.is_dir():
            return f"{cur.relative_to(root).as_posix()} is not a directory"
    try:
        cur.resolve().relative_to(root.resolve())
    except (OSError, ValueError, RuntimeError):
        return f"{rel_dir} resolves outside the repository"
    return None


def _write(root: Path, draft: DraftADR, config: Config | None) -> DraftADR:
    assert draft.path is not None and draft.markdown is not None

    try:
        existing, on_disk, found_notes = _existing_draft(root, draft, config)
    except OSError as exc:
        existing, on_disk = None, None
        found_notes = [f"existing drafts not checked ({type(exc).__name__})"]
    draft = draft.model_copy(update={"notes": [*draft.notes, *found_notes]})

    def note(text: str) -> DraftADR:
        return draft.model_copy(update={"notes": [*draft.notes, text]})

    try:
        if existing is not None and on_disk is not None:
            # Report the file as it is on disk (its text, origin and checks), not the
            # draft generated this time: markdown == the bytes at written_path.
            m = _NUM.match(Path(existing).name)
            return on_disk.model_copy(
                update={
                    "path": existing,
                    "written_path": existing,
                    "number": int(m.group(1)) if m else None,
                    "notes": [*draft.notes, f"{existing} already drafts {draft.record_id} "
                              f"({on_disk.origin}); not written again"],
                }
            )  # fmt: skip
        bad = path_problem(draft.path)
        if bad is not None:
            return note(f"not written: {draft.path!r} is not a repo-relative path ({bad})")
        rel_dir = Path(draft.path).parent.as_posix()
        why = _unsafe_dir(root, rel_dir)
        if why is not None:
            return note(f"not written: {why}")
        (root / rel_dir).mkdir(parents=True, exist_ok=True)
        why = _unsafe_dir(root, rel_dir)  # re-check after creating it
        if why is not None:
            return note(f"not written: {why}")
        target = root / draft.path
        if os.path.lexists(target):
            return note(f"not written: {draft.path} exists; not overwritten")
        _publish(target, draft.markdown.encode("utf-8"))
    except FileExistsError:
        return note(f"not written: {draft.path} exists; not overwritten")
    except OSError as exc:
        return note(f"not written: {type(exc).__name__}: {exc}")
    return draft.model_copy(update={"written_path": draft.path})


__all__ = [
    "DRAFT_STATUS",
    "DraftADR",
    "draft_adr",
    "draft_filename",
    "draft_title",
    "next_adr_number",
    "polish_problems",
    "render_markdown",
    "sanitise_subject",
    "technology_name",
    "verify_draft",
]
