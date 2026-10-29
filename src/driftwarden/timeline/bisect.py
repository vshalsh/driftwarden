"""Drift timeline (pipeline step 9): the commit where a VIOLATED claim first stopped holding.

``first_violation(repo, claim)`` walks the first-parent history of ``head``
(``git rev-list --first-parent``, newest ``max_commits`` commits: the *window*)
and finds the **most recent** commit C such that the claim is *violated at C*
and *not violated at C's first parent*: the start of the current violation.
``build_timeline`` does that for every VERIFIED VIOLATED verdict of a scan,
sharing one snapshot cache.

What "violated at C" means
    The claim (always the one read from HEAD's ADR; old ADRs are never re-read)
    is judged against the tree of C by the deterministic judge in **offline**
    mode (``Judge(mode="offline")``: rules + grounding gate, never an LLM, since
    the search makes many judgements). C is violated when the gated verdict is
    ``VIOLATED`` with ``VERIFIED`` grounding. Everything else counts as *not
    violated*: HOLDING, DRIFTING, UNKNOWN, a MISMATCH gate, a tree that cannot
    be read, and a commit where the claim's ADR file (``claim.source.path``)
    does not exist yet (the decision had not been taken; only the tree entry is
    looked up, the old ADR is not parsed). Each such commit gets a note, so the
    gap is never silent. If the ADR file is not committed at ``head`` at all
    (a WORKTREE claim) the presence check is skipped, with a note. A commit
    whose tree equals its first parent's (an empty or merge-only change) is
    judged exactly like its parent and so can never be a boundary.

Search (``search`` field) and its trade-off
    * ``exhaustive`` (the default for windows of at most
      ``EXHAUSTIVE_MAX_COMMITS`` = 300 commits; ``exhaustive=True`` forces it):
      every commit of the window is judged. The boundary is exactly the most
      recent held -> violated transition; ``non_monotonic`` is a checked bool and
      ``earlier_transitions`` lists every older transition in the window.
    * ``sampled`` (windows over 300 commits; ``exhaustive=False`` forces it):
      about ``sqrt(n)`` evenly spaced commits are judged (oldest and head
      included). Monotonic samples are bisected between the newest held sample
      and the next one; bisection keeps "lo held, hi violated", so the boundary
      and its parent are always judged exactly and C is a *real* transition.
      But a held stretch shorter than the sample spacing can be missed, so C may
      be an older transition than the latest one. Therefore a sampled entry never
      claims monotonicity: ``non_monotonic`` is ``None`` ("not checked") and
      ``earlier_transitions`` is empty. If the samples themselves show violated,
      held, violated again, the search falls back to judging the whole window and
      the entry is ``exhaustive``. If every sample is violated, the search walks
      back from head commit by commit until it meets a held commit (that boundary
      is exact), or confirms the whole window is violated (then it is exhaustive).
      ``non_monotonic`` is ``Optional[bool]`` rather than a bool plus a
      "checked" flag so that no reader can mistake an unchecked value for False.

    Cost: exhaustive judges n commits (each snapshot loaded once, cached by
    SHA); sampled about ``sqrt(n) + log2(n)`` (≈ 32 for 500 commits).

History edges
    * Root commit already violated: C = root, ``parent=None``, note "violated
      since the first commit" (always after the whole window was judged).
    * Merge commits: only the first-parent chain is walked, so a violation that
      arrived on a side branch is reported at the **merge commit** that brought
      it into the mainline (a note names the other parents). This is the commit
      at which the mainline stopped holding, which is what a reader of
      ``main`` saw; the side-branch commit itself is not reported.
    * Truncated history: ``truncated_by`` is ``shallow`` when the oldest commit
      of the window is a shallow-clone boundary (``.git/shallow``) and
      ``max_commits`` when the cap cut the walk. When the claim is violated at
      **every** commit of a truncated window (always checked commit by commit,
      never inferred from samples), the entry is ``TRUNCATED``: nothing is
      guessed about older history. A transition found *inside* a truncated window
      is still FOUND, with a note that older history was not checked.

Grounding (G4)
    Every entry is re-checked from scratch by
    ``grounding.verify.verify_first_violation`` before it is returned (results go
    to ``ledger`` with check_id ``G4``). Every field of the entry is either
    re-derived or re-checked there; see that function for the exact list. An
    entry that fails becomes ``status=UNKNOWN, grounding=MISMATCH`` with the
    reasons: shown as "first seen: unknown", never as a fact.

Known limits: a renamed or moved ADR file counts as "missing" before the rename,
so the boundary can be the rename commit (its note says so). Only first-parent
history is searched. Exhaustive search on a large repository costs one snapshot
per commit of the window.
"""

from __future__ import annotations

import math
import re
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from driftwarden import git
from driftwarden.config import Config
from driftwarden.grounding.ledger import Ledger
from driftwarden.judge.evidence import Snapshot, load_snapshot
from driftwarden.judge.judge import Judge
from driftwarden.models import (
    WORKTREE,
    Claim,
    Evidence,
    GroundingResult,
    GroundingStatus,
    Verdict,
)

TimelineStatus = Literal["FOUND", "NOT_VIOLATED_AT_HEAD", "TRUNCATED", "UNKNOWN"]
TruncatedBy = Literal["shallow", "max_commits"]
SearchMode = Literal["exhaustive", "sampled"]

DEFAULT_MAX_COMMITS = 500
EXHAUSTIVE_MAX_COMMITS = 300
SNAPSHOT_CACHE_SIZE = 64
MIN_SAMPLES = 9
MAX_NOTES = 20
GAP_NOTE = re.compile(r"^(?P<sha>[0-9a-f]{12}): ")
MORE_NOTE = re.compile(r"^\(\+(?P<n>[1-9][0-9]*) more commits not judged as violated\)$")


class TimelineEntry(BaseModel):
    """Where one VIOLATED claim first stopped holding (G4 provenance: ``commit``,
    ``parent``, ``evidence``).

    Invariants (enforced): an entry whose grounding is not VERIFIED has status
    UNKNOWN and reasons (shown as "first seen: unknown"); a VERIFIED entry has no
    reasons and no proposed status; a FOUND entry names its commit, date, subject
    and the verified evidence that makes it violated; a TRUNCATED entry names the
    oldest commit it could see and why history stopped. Which combinations of
    the remaining fields are true is checked by G4 (``verify_first_violation``).
    """

    claim_id: str
    status: TimelineStatus
    head: str | None = Field(default=None, description="Full SHA the walk started from.")
    search: SearchMode | None = Field(
        default=None, description="How the window was searched; None when nothing was searched."
    )
    first_violating_commit: str | None = None
    parent: str | None = Field(
        default=None, description="First parent of first_violating_commit; None for the root."
    )
    author_date: str | None = Field(default=None, description="ISO-8601 author date of C.")
    subject: str | None = Field(default=None, description="C's subject, sanitised.")
    evidence: list[Evidence] = Field(
        default_factory=list, description="The verified evidence at C that makes it violated."
    )
    non_monotonic: bool | None = Field(
        default=None,
        description="True: violated before C too (then held again). False: checked, never "
        "violated before C in the window. None: not checked (sampled search, or no search).",
    )
    earlier_transitions: list[str] = Field(
        default_factory=list,
        description="Older held -> violated commits in the window (oldest first); exhaustive only.",
    )
    oldest_available: str | None = Field(
        default=None, description="Oldest commit of the searched window (FOUND / TRUNCATED)."
    )
    truncated_by: TruncatedBy | None = Field(
        default=None, description="Why the window does not reach the root commit, if it does not."
    )
    notes: list[str] = Field(default_factory=list)
    commits_judged: int = Field(default=0, description="Distinct commits judged by the search.")
    commits_in_window: int = Field(default=0, description="First-parent commits searched.")
    grounding: GroundingStatus = "VERIFIED"
    reasons: list[str] = Field(default_factory=list, description="G4 reasons on MISMATCH.")
    proposed_status: TimelineStatus | None = Field(
        default=None, description="What the search proposed before the G4 gate."
    )
    checks: list[GroundingResult] = Field(default_factory=list, description="G4 results.")

    @property
    def could_not_verify(self) -> bool:
        return self.grounding != "VERIFIED"

    @property
    def first_seen(self) -> str:
        """One line for a report: the boundary, or "first seen: unknown (reason)"."""
        if self.could_not_verify or self.status == "UNKNOWN":
            why = "; ".join(self.reasons)[:300] or "no result"
            return f"first seen: unknown ({why})"
        if self.status == "FOUND":
            assert self.first_violating_commit is not None
            day = (self.author_date or "")[:10]
            return f"first seen: {self.first_violating_commit[:12]} ({day})"
        if self.status == "TRUNCATED":
            old = (self.oldest_available or "?")[:12]
            return f"first seen: before {old} (history truncated: {self.truncated_by})"
        return "first seen: not violated at head"

    @model_validator(mode="after")
    def _invariants(self) -> TimelineEntry:
        if self.grounding != "VERIFIED" and self.status != "UNKNOWN":
            raise ValueError("a timeline entry that is not VERIFIED must have status UNKNOWN")
        if self.grounding != "VERIFIED" and not self.reasons:
            raise ValueError("a timeline entry that is not VERIFIED needs reasons")
        if self.grounding == "VERIFIED" and (self.reasons or self.proposed_status is not None):
            raise ValueError("a VERIFIED timeline entry has no reasons and no proposed status")
        if self.status == "UNKNOWN" and self.grounding == "VERIFIED":
            raise ValueError("an UNKNOWN timeline entry cannot be VERIFIED")
        if self.status == "FOUND" and not (
            self.first_violating_commit
            and self.author_date is not None
            and self.subject is not None
            and self.evidence
        ):
            raise ValueError("a FOUND entry needs commit, author_date, subject and evidence")
        if self.status == "TRUNCATED" and not (self.oldest_available and self.truncated_by):
            raise ValueError("a TRUNCATED entry needs oldest_available and truncated_by")
        return self


# --------------------------------------------------------------------------- cache


class SnapshotCache:
    """Snapshots by commit SHA for one timeline run (LRU, ``max_size`` entries).

    A snapshot is the expensive part of a judgement (tree read, import graph,
    manifests); ``build_timeline`` shares one cache across claims, so the commits
    every claim judges are loaded once."""

    def __init__(self, repo: str | Path, config: Config | None = None, max_size: int = 0) -> None:
        self.root = git.repo_root(repo)
        self.config = config
        self.max_size = max_size or SNAPSHOT_CACHE_SIZE
        self._snaps: OrderedDict[str, Snapshot] = OrderedDict()
        self.loads = 0
        self.hits = 0

    def get(self, sha: str) -> Snapshot:
        snap = self._snaps.get(sha)
        if snap is not None:
            self._snaps.move_to_end(sha)
            self.hits += 1
            return snap
        snap = load_snapshot(self.root, sha, self.config)
        self.loads += 1
        self._snaps[sha] = snap
        while len(self._snaps) > self.max_size:
            self._snaps.popitem(last=False)
        return snap


# --------------------------------------------------------------------------- judging


@dataclass
class Judged:
    """The outcome of judging one claim at one commit."""

    violated: bool
    verdict: Verdict | None
    note: str | None = None  # why a non-HOLDING commit was not counted as violated


def judge_at(
    root: Path,
    claim: Claim,
    sha: str,
    cache: SnapshotCache,
    *,
    adr_check: bool = True,
) -> Judged:
    """Judge ``claim`` against the tree of ``sha`` (offline, deterministic). The note
    (for commits that could not be judged) is part of the entry and re-derived by G4."""
    short = sha[:12]
    if adr_check:
        try:
            present = git.blob_at(root, sha, claim.source.path) is not None
        except git.NotAGitRepoError:
            raise
        except git.GitError as exc:
            why = f"{short}: tree not readable ({exc}); counted as not violated"
            return Judged(False, None, why)
        if not present:
            return Judged(
                False,
                None,
                f"{short}: ADR {claim.source.path} not present (decision not taken yet); "
                "counted as not violated",
            )
    try:
        snap = cache.get(sha)
        verdict = Judge(root, mode="offline", snapshot=snap).judge(claim)
    except git.NotAGitRepoError:
        raise
    except git.GitError as exc:
        return Judged(False, None, f"{short}: tree not readable ({exc}); counted as not violated")
    if verdict.status == "VIOLATED" and verdict.grounding == "VERIFIED":
        return Judged(True, verdict)
    note = None
    if verdict.status == "UNKNOWN" or verdict.grounding != "VERIFIED":
        why = "; ".join(verdict.reasons)[:200] or verdict.rationale[:200]
        note = (
            f"{short}: claim could not be judged ({verdict.status}/{verdict.grounding}: {why}); "
            "counted as not violated"
        )
    return Judged(False, verdict, note)


def first_parent_chain(root: Path, head: str, max_commits: int | None = None) -> list[str]:
    """First-parent history of ``head``, newest first, at most ``max_commits`` commits."""
    args = ["rev-list", "--first-parent"]
    if max_commits is not None:
        args.append(f"--max-count={max_commits}")
    return git._run([*args, f"{head}^{{commit}}"], root).split()


def sample_indices(n: int) -> list[int]:
    """About sqrt(n) (at least MIN_SAMPLES) evenly spaced indices of 0..n-1, both
    ends included."""
    if n <= 0:
        return []
    k = min(n, max(MIN_SAMPLES, math.isqrt(n) + 1))
    if k == 1:
        return [0]
    return sorted({round(i * (n - 1) / (k - 1)) for i in range(k)})


def gap_notes(judged: Iterable[tuple[int, Judged]]) -> list[str]:
    """Notes for the judged commits that were not counted as violated for a reason other
    than HOLDING / DRIFTING, oldest first, at most MAX_NOTES plus a count of the rest."""
    raw = [j.note for _, j in sorted(judged, key=lambda x: x[0]) if j.note]
    shown = [n for n in raw if n][:MAX_NOTES]
    if len(raw) > MAX_NOTES:
        shown.append(f"(+{len(raw) - MAX_NOTES} more commits not judged as violated)")
    return shown


def entry_notes(
    *,
    status: str,
    head: str,
    window: int,
    adr_path: str,
    adr_check: bool,
    search: str | None = None,
    truncated_by: str | None = None,
    oldest: str | None = None,
    head_status: str | None = None,
    root_boundary: bool = False,
    non_monotonic: bool | None = None,
    earlier: list[str] | None = None,
    merge_parents: list[str] | None = None,
    commit: str | None = None,
) -> list[str]:
    """The fixed (non-gap) notes of an entry, in order; a pure function of the entry's
    other facts, so G4 re-derives them."""
    notes = [f"window: {window} first-parent commit(s) of {head[:12]}"]
    if not adr_check:
        notes.append(f"ADR {adr_path} is not committed at {head[:12]}; ADR-presence check skipped")
    if status == "NOT_VIOLATED_AT_HEAD":
        notes.append(f"at head the claim is {head_status}, not VERIFIED VIOLATED")
        return notes
    if search == "exhaustive":
        notes.append(f"exhaustive search: all {window} commit(s) of the window judged")
    else:
        notes.append(
            f"sampled search: {len(sample_indices(window))} evenly spaced commit(s) plus "
            "bisection; a held stretch shorter than the sample spacing can be missed, so "
            "non_monotonic is not checked (None)"
        )
    if status == "TRUNCATED":
        why = (
            "shallow clone: the parents of the oldest commit are not available"
            if truncated_by == "shallow"
            else f"max_commits={window} reached before a commit where the claim held"
        )
        notes.append(f"violated at every commit of the window; {why}")
        return notes
    if root_boundary:
        notes.append("violated since the first commit")
    if truncated_by is not None and oldest is not None:
        notes.append(
            f"history truncated ({truncated_by}); transitions before {oldest[:12]} not checked"
        )
    if non_monotonic:
        shown = ", ".join(x[:12] for x in earlier or []) or "before the window"
        notes.append(
            "non-monotonic: the claim was violated, then held, then violated again; earlier "
            f"held -> violated transition(s): {shown}"
        )
    if merge_parents and len(merge_parents) > 1 and commit is not None:
        notes.append(
            f"{commit[:12]} is a merge commit: first-parent boundary; the change came in from "
            f"{', '.join(p[:12] for p in merge_parents[1:])}"
        )
    return notes


@dataclass
class _Search:
    root: Path
    claim: Claim
    commits: list[str]  # oldest first
    cache: SnapshotCache
    adr_check: bool
    memo: dict[int, Judged] = field(default_factory=dict)

    def judged(self, i: int) -> Judged:
        if i not in self.memo:
            self.memo[i] = judge_at(
                self.root, self.claim, self.commits[i], self.cache, adr_check=self.adr_check
            )
        return self.memo[i]

    def v(self, i: int) -> bool:
        return self.judged(i).violated


def _bisect(s: _Search, lo: int, hi: int) -> int:
    """Smallest index in (lo, hi] with V True, given V(lo) False and V(hi) True; the
    returned boundary and its parent are both judged."""
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if s.v(mid):
            hi = mid
        else:
            lo = mid
    return hi


def first_violation(
    repo: str | Path,
    claim: Claim,
    *,
    head: str = "HEAD",
    config: Config | None = None,
    max_commits: int = DEFAULT_MAX_COMMITS,
    ledger: Ledger | None = None,
    cache: SnapshotCache | None = None,
    exhaustive: bool | None = None,
) -> TimelineEntry:
    """The commit where the current violation of ``claim`` started, on the
    first-parent history of ``head`` (see the module docstring). ``exhaustive``:
    None = exhaustive iff the window has at most EXHAUSTIVE_MAX_COMMITS commits;
    True / False force exhaustive / sampled. The entry is G4-verified before it is
    returned; its G4 results go to ``ledger``. Never calls an LLM."""
    root = git.repo_root(repo)
    cache = cache if cache is not None else SnapshotCache(root, config)
    try:
        head_sha = git.resolve_commit(root, head)
    except git.NotAGitRepoError:
        raise
    except git.GitError as exc:
        return _unknown(claim, None, f"head {head!r} is not a commit: {exc}", ledger)
    if max_commits < 1:
        return _unknown(claim, head_sha, f"max_commits must be >= 1, got {max_commits}", ledger)
    try:
        commits = list(reversed(first_parent_chain(root, head_sha, max_commits)))
        shallow = git.shallow_boundary(root)
    except git.NotAGitRepoError:
        raise
    except git.GitError as exc:
        return _unknown(claim, head_sha, f"history not readable: {exc}", ledger)

    n = len(commits)
    oldest = commits[0]
    truncated_by: TruncatedBy | None = None
    if oldest in shallow:
        truncated_by = "shallow"
    elif n == max_commits and git.parents(root, oldest):
        truncated_by = "max_commits"
    try:
        adr_check = git.blob_at(root, head_sha, claim.source.path) is not None
    except git.GitError:
        adr_check = False

    s = _Search(root, claim, commits, cache, adr_check)
    common = {
        "head": head_sha,
        "window": n,
        "adr_path": claim.source.path,
        "adr_check": adr_check,
    }

    if not s.v(n - 1):
        j = s.judged(n - 1)
        what = j.verdict.status if j.verdict else "not judged"
        entry = TimelineEntry(
            claim_id=claim.id,
            status="NOT_VIOLATED_AT_HEAD",
            head=head_sha,
            commits_in_window=n,
            commits_judged=1,
            notes=[
                *entry_notes(status="NOT_VIOLATED_AT_HEAD", head_status=what, **common),
                *gap_notes(s.memo.items()),
            ],
        )
        return _ground(repo, entry, claim, config, ledger, head_sha)

    linear = exhaustive if exhaustive is not None else n <= EXHAUSTIVE_MAX_COMMITS
    boundary: int | None = None
    if not linear:
        vals = [(i, s.v(i)) for i in sample_indices(n)]
        held = [i for i, ok in vals if not ok]
        if not held:
            # Every sample is violated: never infer "violated throughout" from samples.
            # Walk back from head to the newest held commit (exact boundary), or confirm
            # that the whole window is violated.
            newest_held = next((i for i in range(n - 1, -1, -1) if not s.v(i)), None)
            boundary = 0 if newest_held is None else newest_held + 1
        elif any(ok for i, ok in vals if i < held[-1]):
            linear = True  # violated, held, violated again among the samples
        else:
            nxt = next(i for i, _ in vals if i > held[-1])
            boundary = _bisect(s, held[-1], nxt)
    if linear:
        for i in range(n):
            s.v(i)

    full = len(s.memo) == n  # every commit of the window judged
    earlier: list[str] = []
    non_monotonic: bool | None = None
    if full:
        trans = [i for i in range(1, n) if s.v(i) and not s.v(i - 1)]
        if s.v(0) and truncated_by is None:
            trans.insert(0, 0)  # violated at the root commit itself
        boundary = trans[-1] if trans else 0
        earlier = [commits[i] for i in trans[:-1]]
        non_monotonic = any(s.v(i) for i in range(boundary))
    assert boundary is not None
    search: SearchMode = "exhaustive" if full else "sampled"

    if boundary == 0 and truncated_by is not None:
        assert full  # TRUNCATED only after every commit of the window was judged violated
        j0 = s.judged(0)
        entry = TimelineEntry(
            claim_id=claim.id,
            status="TRUNCATED",
            head=head_sha,
            search=search,
            oldest_available=oldest,
            truncated_by=truncated_by,
            non_monotonic=False,
            evidence=list(j0.verdict.evidence) if j0.verdict else [],
            notes=[
                *entry_notes(
                    status="TRUNCATED", search=search, truncated_by=truncated_by, **common
                ),
                *gap_notes(s.memo.items()),
            ],
            commits_judged=len(s.memo),
            commits_in_window=n,
        )
        return _ground(repo, entry, claim, config, ledger, head_sha)

    c = commits[boundary]
    parent = commits[boundary - 1] if boundary > 0 else None
    try:
        all_parents = git.parents(root, c)
    except git.GitError:
        all_parents = []
    info = _log1(root, c)
    j = s.judged(boundary)
    assert j.verdict is not None
    entry = TimelineEntry(
        claim_id=claim.id,
        status="FOUND",
        head=head_sha,
        search=search,
        first_violating_commit=c,
        parent=parent,
        author_date=info[0] if info else "",
        subject=info[1] if info else "",
        evidence=list(j.verdict.evidence),
        non_monotonic=non_monotonic,
        earlier_transitions=earlier,
        oldest_available=oldest,
        truncated_by=truncated_by,
        notes=[
            *entry_notes(
                status="FOUND",
                search=search,
                truncated_by=truncated_by,
                oldest=oldest,
                root_boundary=parent is None,
                non_monotonic=non_monotonic,
                earlier=earlier,
                merge_parents=all_parents,
                commit=c,
                **common,
            ),
            *gap_notes(s.memo.items()),
        ],
        commits_judged=len(s.memo),
        commits_in_window=n,
    )
    return _ground(repo, entry, claim, config, ledger, head_sha)


def _log1(root: Path, sha: str) -> tuple[str, str] | None:
    """(ISO author date, sanitised subject) of ``sha``."""
    from driftwarden.undocumented.draft import sanitise_subject

    try:
        entries = git.log(root, max_count=1, rev=sha)
    except git.GitError:
        return None
    if not entries or entries[0].sha != sha:
        return None
    return entries[0].date, sanitise_subject(entries[0].subject)


def _unknown(claim: Claim, head: str | None, reason: str, ledger: Ledger | None) -> TimelineEntry:
    result = GroundingResult(
        check_id="G4", status="MISMATCH", reason=reason, provenance=None, subject=claim.id
    )
    if ledger is not None:
        ledger.append(result)
    return TimelineEntry(
        claim_id=claim.id,
        status="UNKNOWN",
        head=head,
        grounding="MISMATCH",
        reasons=[reason],
        checks=[result],
    )


def apply_grounding(entry: TimelineEntry, results: list[GroundingResult]) -> TimelineEntry:
    """``entry`` with the G4 ``results`` attached; any MISMATCH turns it into
    UNKNOWN / MISMATCH with the reasons (shown as "first seen: unknown")."""
    reasons = [r.reason for r in results if r.status != "VERIFIED"]
    data = entry.model_dump()
    data["checks"] = [*entry.checks, *results]
    if not reasons:
        data["grounding"] = "VERIFIED"
        return TimelineEntry.model_validate(data)
    data.update(
        status="UNKNOWN",
        grounding="MISMATCH",
        reasons=[*entry.reasons, *reasons],
        proposed_status=entry.proposed_status or entry.status,
    )
    return TimelineEntry.model_validate(data)


def _ground(
    repo: str | Path,
    entry: TimelineEntry,
    claim: Claim,
    config: Config | None,
    ledger: Ledger | None,
    head: str,
) -> TimelineEntry:
    from driftwarden.grounding.verify import verify_first_violation

    results = verify_first_violation(repo, entry, claim, config, head=head)
    if ledger is not None:
        ledger.extend(results)
    return apply_grounding(entry, results)


def build_timeline(
    repo: str | Path,
    claims: Iterable[Claim],
    verdicts: Iterable[Verdict],
    *,
    head: str = "HEAD",
    config: Config | None = None,
    max_commits: int = DEFAULT_MAX_COMMITS,
    ledger: Ledger | None = None,
    exhaustive: bool | None = None,
) -> list[TimelineEntry]:
    """``first_violation`` for every VERIFIED VIOLATED verdict, in verdict order.

    The walk starts at the commit the verdict was judged at (``verdict.commit``)
    when that is a commit, else at ``head`` (a WORKTREE verdict). One snapshot
    cache is shared by all claims. A verdict whose claim is not in ``claims``
    gives an UNKNOWN entry with the reason, never a silent gap."""
    by_id = {c.id: c for c in claims}
    cache = SnapshotCache(repo, config)
    out: list[TimelineEntry] = []
    for v in verdicts:
        if v.status != "VIOLATED" or v.grounding != "VERIFIED":
            continue
        claim = by_id.get(v.claim_id)
        if claim is None:
            stub = Claim.model_construct(id=v.claim_id)
            out.append(_unknown(stub, None, f"claim {v.claim_id!r} not among the claims", ledger))
            continue
        start = v.commit if v.commit and v.commit != WORKTREE else head
        out.append(
            first_violation(
                repo,
                claim,
                head=start,
                config=config,
                max_commits=max_commits,
                ledger=ledger,
                cache=cache,
                exhaustive=exhaustive,
            )
        )
    return out
