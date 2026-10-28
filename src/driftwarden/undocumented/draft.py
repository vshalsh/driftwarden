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
  (author date and subject line only; no author names);
* ``- [<evidence id>] `<path>` lines <a>-<b> at `<sha>`<detail>:`` followed by a
  fenced block holding the verbatim quote, once for each introducing line (at
  its introducing commit; detail ``, introduced``) and once for each evidence
  item (at the scanned commit; detail = kind, and for a manifest item the
  package, version spec, ecosystem and scope that G3 re-checks).

**The gate** (:func:`verify_draft`, fail closed). The record is re-verified from
scratch (``verify_undocumented``: G2/G3 on the evidence, G5 on the introductions);
then the *markdown itself* is parsed and every citation in it is checked against
the repository and against the record:

* every SHA in the text -- full ids in citations and front-matter, and any run of
  7-64 hex digits anywhere in the prose -- must name (or abbreviate) one of the
  record's commits (its introducing commits or the scanned commit), and each one
  is checked with ``verify_commits_exist`` (it exists and is an ancestor of the
  scanned commit, G5);
* each commit line's date and subject must be git's for that SHA;
* each source citation must be one of the record's evidence / introduction refs,
  rendered exactly as the record says (path, line range, commit, detail, quote),
  and its quote must pass ``verify_source_quote`` (G2) at that commit; a
  dependency item's manifest fact passes ``verify_dependency`` (G3);
* every ``path:line`` reference in the prose must be a cited range;
* every introducing commit, evidence item and introduction must be cited, and
  no code block may stand outside a citation;
* the draft parses back through the repository's own ADR parser
  (``discover.adr.parse_adr``) with the expected title and status ``proposed``.

Any failure makes the draft ``status=UNKNOWN, grounding=MISMATCH`` with the
reasons: it is shown as *Could not verify*, never as a draft. A record that is
itself *Could not verify* yields no draft at all.

**LLM path.** With a non-offline ``provider``, the model may rewrite the context
paragraph only (one JSON string). Its text is never trusted for facts: it may not
add headings, lists, code blocks or numbers that the template paragraph does not
contain, and the assembled draft must pass the same gate; otherwise the template
draft is returned with a note. Known limit: the gate checks references, not
meaning, so a model sentence that invents a reason in plain words is not caught
by it (the prompt forbids it and the number rule narrows it).

**Files.** ``path`` is a suggestion, ``<adr dir>/NNNN-use-<tech>-for-<category>.md``
with NNNN the next free number among the ADRs discovered at the scanned commit and
in the working tree; the ADR directory is where the existing ADRs live, else
``docs/adr``. Nothing is written unless ``write=True`` (and the draft verified);
an existing file is never overwritten.
"""

from __future__ import annotations

import re
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
    verify_commits_exist,
    verify_dependency,
    verify_source_quote,
)
from driftwarden.judge import catalog
from driftwarden.llm.base import LLMError, Provider
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
MIN_SHA_PREFIX = 7

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
    written_path: str | None = Field(default=None, description="Set when write=True wrote it.")

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
    return name[:1].upper() + name[1:] if name.islower() else name


def draft_title(technology: str, category: str) -> str:
    return f"Use {technology_name(technology)} for {CATEGORY_LABELS.get(category, category)}"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def draft_filename(number: int, technology: str, category: str) -> str:
    return f"{number:04d}-use-{_slug(technology)}-for-{_slug(category)}.md"


_NUM = re.compile(r"^(?:adr[-_]?)?(\d+)", re.IGNORECASE)


def next_adr_number(paths: Iterable[str]) -> int:
    """One more than the highest number leading an ADR file name (1 when none)."""
    nums = [int(m.group(1)) for p in paths if (m := _NUM.match(Path(p).name))]
    return max(nums, default=0) + 1


def _adr_dir(paths: list[str]) -> str:
    dirs = Counter(str(Path(p).parent.as_posix()) for p in paths)
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
    subject: str


def _commit_info(root: Path, sha: str) -> _CommitInfo:
    entries = git.log(root, max_count=1, rev=sha)
    if not entries or entries[0].sha != sha:
        raise git.GitError(f"no log entry for {sha[:12]}")
    return _CommitInfo(date=entries[0].date[:10], subject=entries[0].subject)


def _short(sha: str) -> str:
    return sha[:12]


def _fence(quote: str) -> str:
    runs = [len(m.group(0)) for m in re.finditer(r"`+", quote)]
    return "`" * max(3, max(runs, default=0) + 1)


def _evidence_detail(ev: Evidence) -> str:
    d = ev.dependency
    if d is None:
        return f", {ev.kind}"
    spec = d.version_spec if d.version_spec is not None else "unversioned"
    eco = d.ecosystem or "?"
    scope = f", scope {d.scope}" if d.scope else ""
    return f", {ev.kind} `{d.package}` {spec} ({eco}{scope})"


INTRO_DETAIL = ", introduced"


def _cite_line(eid: str, ref: Provenance, detail: str) -> str:
    span = f"lines {ref.line_start}-{ref.line_end}"
    return f"- [{eid}] `{ref.path}` {span} at `{ref.commit}`{detail}:"


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
    return (
        f"The code at commit `{_short(rec.commit)}` uses {name} as {label}: "
        f"{n_ev} production occurrence{'s' if n_ev != 1 else ''} in {n_files} "
        f"file{'s' if n_files != 1 else ''}, cited below. No ADR in this repository "
        f"records that decision. {name} was introduced by {when}."
    )


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
        f"driftwarden-record: {rec.id}",
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


# --------------------------------------------------------------------------- the G5 gate

_COMMIT_LINE = re.compile(r"^- Commit `(?P<sha>[^`]*)`, (?P<date>[^:]*): (?P<subject>.*)$")
_CITE_LINE = re.compile(
    r"^- \[(?P<eid>[^\]]*)\] `(?P<path>[^`]+)` lines (?P<a>\d+)-(?P<b>\d+) "
    r"at `(?P<sha>[^`]*)`(?P<detail>.*):$"
)
_FENCE_OPEN = re.compile(r"^(?P<fence>`{3,}|~{3,})text$")
_ANY_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,64}(?![0-9A-Za-z])")
_REF = re.compile(r"(?P<path>[\w./-]*[\w-][./][\w./-]*):(?P<a>\d+)(?:-(?P<b>\d+))?(?!\d)")
_FRONT = re.compile(r"^(?P<key>[A-Za-z][\w-]*)\s*:\s*(?P<value>.*)$")


def _sha_like(token: str) -> bool:
    return any(ch.isdigit() for ch in token) or len(token) >= 12


@dataclass
class _Cite:
    eid: str
    path: str
    a: int
    b: int
    sha: str
    line: str
    quote: str | None  # None when no fenced block followed


@dataclass
class _Parsed:
    commits: list[tuple[str, str, str, str]]  # (sha, date, subject, line)
    cites: list[_Cite]
    prose: list[str]
    front: dict[str, str]
    problems: list[str]


def _parse_draft(md: str) -> _Parsed:
    lines = split_lines(md)
    out = _Parsed([], [], [], {}, [])
    i = 0
    if lines and lines[0] == "---":
        end = next((k for k in range(1, len(lines)) if lines[k] == "---"), None)
        if end is None:
            out.problems.append("front-matter is not closed")
        else:
            for raw in lines[1:end]:
                m = _FRONT.match(raw)
                if m:
                    out.front[m.group("key").lower()] = m.group("value").strip()
                out.prose.append(raw)
            i = end + 1
    while i < len(lines):
        line = lines[i]
        if line.startswith("- Commit "):
            m = _COMMIT_LINE.match(line)
            if m is None:
                out.problems.append(f"malformed commit citation: {line!r}")
                out.prose.append(line)
            else:
                out.commits.append((m["sha"], m["date"], m["subject"], line))
            i += 1
            continue
        if line.startswith("- ["):
            m = _CITE_LINE.match(line)
            if m is None:
                out.problems.append(f"malformed source citation: {line!r}")
                out.prose.append(line)
                i += 1
                continue
            cite = _Cite(m["eid"], m["path"], int(m["a"]), int(m["b"]), m["sha"], line, None)
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            fm = _FENCE_OPEN.match(lines[j]) if j < len(lines) else None
            if fm is None:
                out.problems.append(f"source citation without a quote block: {line!r}")
                out.cites.append(cite)
                i += 1
                continue
            fence = fm["fence"]
            close = next((k for k in range(j + 1, len(lines)) if lines[k] == fence), None)
            if close is None:
                out.problems.append(f"unclosed quote block after: {line!r}")
                out.cites.append(cite)
                i = len(lines)
                continue
            cite.quote = "\n".join(lines[j + 1 : close])
            out.cites.append(cite)
            i = close + 1
            continue
        if _ANY_FENCE.match(line):
            out.problems.append(f"code block outside a citation at line {i + 1}")
        out.prose.append(line)
        i += 1
    return out


@dataclass(frozen=True)
class _Expected:
    ref: Provenance
    evidence: Evidence
    intro: bool


def _expected_cites(rec: UndocumentedDecision) -> dict[str, _Expected]:
    """Citation line -> what it cites, for every introduction and evidence item."""
    by_id = {e.id: e for e in rec.evidence}
    out: dict[str, _Expected] = {}
    for intro in rec.introductions:
        ev = by_id.get(intro.evidence_id)
        if ev is not None:
            out[_cite_line(ev.id, intro.ref, INTRO_DETAIL)] = _Expected(intro.ref, ev, True)
    for ev in rec.evidence:
        out[_cite_line(ev.id, ev.ref, _evidence_detail(ev))] = _Expected(ev.ref, ev, False)
    return out


def verify_draft(
    repo: str | Path,
    draft: DraftADR,
    *,
    decisions: Iterable[Decision] | None = None,
    claims: Iterable[Claim] = (),
    ledger: Ledger | None = None,
) -> DraftADR:
    """G5 gate: re-verify ``draft`` (see the module docstring). Returns the draft with
    ``checks`` replaced and ``status/grounding/reasons`` set: DRAFT / VERIFIED, or
    UNKNOWN / MISMATCH with every reason. Never raises for a bad draft; raises only
    if ``repo`` is not a git repository. ``decisions`` (optional) re-runs the
    "no ADR mentions it" check of the record."""
    root = git.repo_root(repo)
    checks: list[GroundingResult] = []
    reasons: list[str] = []
    subj = f"draft:{draft.record_id}"
    cited_commits: list[str] = []
    cited_refs: list[Provenance] = []

    def fail(reason: str, prov=None, cid: str = "G5") -> None:
        checks.append(
            GroundingResult(
                check_id=cid, status="MISMATCH", reason=reason, provenance=prov, subject=subj
            )
        )
        reasons.append(reason)

    def ok(reason: str, prov=None, cid: str = "G5") -> None:
        checks.append(
            GroundingResult(
                check_id=cid, status="VERIFIED", reason=reason, provenance=prov, subject=subj
            )
        )

    rec = draft.record
    try:
        # 1. The record itself, from scratch.
        if (draft.record_id, draft.technology, draft.category) != (
            rec.id, rec.technology, rec.category,
        ):  # fmt: skip
            fail("draft header does not match its record")
        vrec = verify_undocumented(root, rec, decisions=decisions, claims=claims)
        checks.extend(vrec.checks)
        reasons.extend(f"record: {r}" for r in vrec.reasons)
        md = draft.markdown
        if not md:
            fail("no draft text")
        else:
            _verify_text(root, rec, md, draft.title, fail, ok, checks, cited_commits, cited_refs)
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
    return DraftADR.model_validate(data)


def _verify_text(
    root: Path,
    rec: UndocumentedDecision,
    md: str,
    title: str,
    fail,
    ok,
    checks: list[GroundingResult],
    cited_commits: list[str],
    cited_refs: list[Provenance],
) -> None:
    parsed = _parse_draft(md)
    for p in parsed.problems:
        fail(p)
    record_commits = list(dict.fromkeys([*rec.introducing_commits, rec.commit]))
    mentioned: list[str] = []

    def mention(sha: str) -> None:
        if sha not in mentioned:
            mentioned.append(sha)

    # Front-matter: pinned to this record.
    fm = parsed.front
    fm_rec, fm_commit = fm.get("driftwarden-record"), fm.get("driftwarden-commit")
    if fm_rec != rec.id:
        fail(f"front-matter driftwarden-record is {fm_rec!r}, not {rec.id}")
    if fm_commit != rec.commit:
        fail(f"front-matter driftwarden-commit {fm_commit!r} is not the record's commit")
    else:
        mention(rec.commit)

    # Commit lines: introducing commits only, with git's own date and subject.
    seen_commits: list[str] = []
    for sha, date, subject, _line in parsed.commits:
        if sha not in rec.introducing_commits:
            fail(f"commit {sha[:12]!r} is cited but is not an introducing commit of {rec.id}")
            continue
        if sha in seen_commits:
            fail(f"commit {sha[:12]} is cited twice")
        seen_commits.append(sha)
        mention(sha)
        if commit_problem(root, sha) is not None:
            continue  # reported by verify_commits_exist
        info = _commit_info(root, sha)
        if (date, subject) != (info.date, info.subject):
            fail(
                f"commit {sha[:12]}: draft says {date} {subject!r}, git says "
                f"{info.date} {info.subject!r}"
            )
        else:
            ok(f"commit {sha[:12]}: date and subject match git")
    for c in rec.introducing_commits:
        if c not in seen_commits:
            fail(f"introducing commit {c[:12]} is not cited")

    # Source citations: exactly the record's refs, quotes re-verified (G2), deps (G3).
    expected = _expected_cites(rec)
    refs_of = {(x.evidence.id, x.ref.path, x.ref.line_start, x.ref.line_end, x.ref.commit)
               for x in expected.values()}  # fmt: skip
    seen_lines: set[str] = set()
    for cite in parsed.cites:
        loc = f"[{cite.eid}] {cite.path}:{cite.a}-{cite.b}@{cite.sha[:12]}"
        if cite.sha in record_commits:
            mention(cite.sha)
        x = expected.get(cite.line)
        if x is None:
            if (cite.eid, cite.path, cite.a, cite.b, cite.sha) in refs_of:
                fail(f"{loc}: citation text differs from the record ({cite.line!r})")
            else:
                fail(f"{loc}: not a ref of record {rec.id}")
            continue
        if cite.line in seen_lines:
            fail(f"{loc}: cited twice")
        seen_lines.add(cite.line)
        ref, ev = x.ref, x.evidence
        if cite.quote is None:
            continue  # reported by the parser
        if cite.quote != ref.quote:
            fail(f"{loc}: quote differs from the record's", ref, "G2")
        prov = Provenance(path=cite.path, line_start=cite.a, line_end=cite.b, commit=cite.sha,
                          quote=cite.quote)  # fmt: skip
        g2 = verify_source_quote(root, prov, check_id="G2", subject=f"draft:{rec.id}/{cite.eid}")
        checks.append(g2)
        if g2.status != "VERIFIED":
            fail(f"{loc}: {g2.reason}", prov, "G2")
        else:
            cited_refs.append(prov)
        if ev.dependency is not None and not x.intro:
            g3 = verify_dependency(root, ev.dependency, subject=f"draft:{rec.id}/{cite.eid}")
            checks.append(g3)
            if g3.status != "VERIFIED":
                fail(f"{loc}: {g3.reason}", ev.dependency, "G3")
    for line, x in expected.items():
        if line not in seen_lines:
            r = x.ref
            fail(f"[{x.evidence.id}] {r.path}:{r.line_start}-{r.line_end}@{r.commit[:12]} "
                 "is not cited")  # fmt: skip

    # Prose: every hex run abbreviates a record commit; every path:line is a cited range.
    ranges = {(r[1], r[2], r[3]) for r in refs_of}
    for text in parsed.prose:
        for m in _HEX.finditer(text):
            tok = m.group(0)
            if not _sha_like(tok):
                continue
            hits = [c for c in record_commits if c.startswith(tok)]
            if not hits:
                fail(f"{tok!r} in the text is not a commit of record {rec.id}")
            for c in hits:
                mention(c)
        for m in _REF.finditer(text):
            path, a = m["path"], int(m["a"])
            b = int(m["b"]) if m["b"] else a
            if (path, a, b) not in ranges:
                fail(f"reference {m.group(0)!r} in the text is not a cited source range")

    # Prose numbers (counts, dates): only those of the template rendering of this record.
    infos: dict[str, _CommitInfo] = {}
    if rec.introducing_commits and all(
        commit_problem(root, c) is None for c in rec.introducing_commits
    ):
        infos = {c: _commit_info(root, c) for c in rec.introducing_commits}
        first_date = infos[rec.introducing_commits[0]].date
        if fm.get("date") != first_date:
            fail(f"front-matter date {fm.get('date')!r} is not {first_date}")
        allowed = set(
            re.findall(r"\d+", "\n".join(_parse_draft(render_markdown(rec, infos)).prose))
        )
        for text in parsed.prose:
            bare = _REF.sub(" ", _HEX.sub(" ", text))
            extra = sorted(set(re.findall(r"\d+", bare)) - allowed)
            if extra:
                fail(f"number(s) {extra[:5]} in the text are not facts of record {rec.id}")
                break

    # G5: every commit the text names exists and is in the scanned commit's history.
    if mentioned:
        for r in verify_commits_exist(
            root, mentioned, ancestor_of=rec.commit, subject=f"draft:{rec.id}"
        ):
            checks.append(r)
            if r.status != "VERIFIED":
                fail(r.reason)
    else:
        fail("the draft cites no commit")
    cited_commits.extend(mentioned)

    # Round trip through the repository's own ADR parser.
    dec = parse_adr(md, "docs/adr/draft.md", rec.commit)
    want = draft_title(rec.technology, rec.category)
    if title != want:
        fail(f"draft title {title!r} is not {want!r}")
    if dec.title != want:
        fail(f"draft parses with title {dec.title!r}, not {want!r}")
    if dec.status != "proposed":
        fail(f"draft parses with status {dec.status!r}, not 'proposed'")
    if dec.title == want and dec.status == "proposed":
        ok("draft parses back as a proposed ADR with the expected title")


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
    "dates, versions, commit ids or file references. Keep commit ids in backticks as "
    "given. One plain paragraph, no headings, lists or code blocks."
)


def _polish_problems(text: str, template: str) -> list[str]:
    problems: list[str] = []
    for raw in split_lines(text):
        s = raw.strip()
        if s.startswith(("#", "- ", "* ", "+ ", "---", ">")) or "```" in s or "~~~" in s:
            problems.append("model text contains markdown structure")
            break
    allowed = set(re.findall(r"\d+", template))
    extra = sorted(set(re.findall(r"\d+", text)) - allowed)
    if extra:
        problems.append(f"model text adds numbers not in the facts: {extra[:5]}")
    return problems


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
    except LLMError as exc:
        return None, f"LLM polish failed ({type(exc).__name__}): template text kept"
    raw = str(res.value.get("context", ""))
    problems = _polish_problems(raw, template)
    text = " ".join(raw.split())
    if problems:
        return None, f"LLM polish rejected ({'; '.join(problems)}): template text kept"
    return text, ""


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
    the result has ``status=UNKNOWN``, no markdown, and the reasons. ``provider``
    (non-offline) may polish the context paragraph; see the module docstring.
    ``existing_adrs`` (repo-relative ADR paths) fixes the numbering; by default the
    ADRs at the record's commit and in the working tree are discovered. Nothing is
    written unless ``write=True``; the file is then created at ``path`` (never
    overwritten) and ``written_path`` set."""
    root = git.repo_root(repo)
    title = draft_title(record.technology, record.category)
    paths = (
        sorted(existing_adrs)
        if existing_adrs is not None
        else _existing_adrs(root, record.commit, config)
    )
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
        infos = {c: _commit_info(root, c) for c in record.introducing_commits}
    except git.NotAGitRepoError:
        raise
    except git.GitError as exc:
        return refused([f"introducing commit unreadable: {exc}"])

    notes: list[str] = []
    template = template_context(record, infos)
    drafts: list[tuple[DraftOrigin, str]] = []
    if provider is not None and not provider.offline:
        text, note = _polish(provider, record, template)
        if text is not None:
            drafts.append(("llm", render_markdown(record, infos, text)))
        else:
            notes.append(note)
    drafts.append(("template", render_markdown(record, infos)))

    result: DraftADR | None = None
    for origin, md in drafts:
        cand = DraftADR(**base, markdown=md, origin=origin, notes=list(notes))
        result = verify_draft(root, cand, decisions=decisions, claims=claims)
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
        result = _write(root, result)
    return result


def _write(root: Path, draft: DraftADR) -> DraftADR:
    assert draft.path is not None and draft.markdown is not None
    target = root / draft.path
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(target, "x", encoding="utf-8", newline="\n") as fh:
            fh.write(draft.markdown)
    except FileExistsError:
        return draft.model_copy(
            update={"notes": [*draft.notes, f"{draft.path} exists; not overwritten"]}
        )
    return draft.model_copy(update={"written_path": draft.path})


__all__ = [
    "DRAFT_STATUS",
    "DraftADR",
    "draft_adr",
    "draft_filename",
    "draft_title",
    "next_adr_number",
    "render_markdown",
    "technology_name",
    "verify_draft",
]
