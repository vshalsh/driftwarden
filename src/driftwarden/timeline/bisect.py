"""Drift timeline (pipeline step 9): the commit where a VIOLATED claim first stopped holding.

``first_violation(repo, claim)`` walks the first-parent history of ``head``
(``git rev-list --first-parent``, newest ``max_commits`` commits) and finds the
most recent commit C such that the claim is *violated at C* and *not violated
at C's first parent*. ``build_timeline`` does that for every VERIFIED VIOLATED
verdict of a scan, sharing one snapshot cache.

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

Search, and its trade-off
    The search assumes drift is monotonic (held ... held, violated ... violated)
    and bisects, but checks that assumption cheaply first:

    1. *Sample.* About ``sqrt(n)`` evenly spaced commits of the n-commit window
       are judged, always including the oldest commit and ``head``.
    2. *Monotonic samples* (no violated sample before a held one): bisect
       between the newest held sample and the next sample. Bisection keeps "lo
       held, hi violated" as an invariant, so the reported boundary C and its
       parent are always both judged exactly: the boundary is a real
       held -> violated transition, never an interpolation.
    3. *Non-monotonic samples* (violated, then held, then violated again):
       fall back to a linear scan of the whole window, report the **most
       recent** held -> violated transition, set ``non_monotonic=True`` and
       list the earlier transitions in ``earlier_transitions`` and ``notes``.

    Cost: about ``sqrt(n) + log2(n)`` judgements in the monotonic case (≈ 26
    for 300 commits) instead of n; n in the fallback. What sampling can miss: a
    held interval shorter than the sample spacing. Then the samples look
    monotonic and bisection still returns a *genuine* transition, but possibly
    an older one than the most recent, and ``non_monotonic`` stays False. The
    G4 verifier still passes in that case (C violated, parent not), because G4
    proves that C is a transition, not that it is the last one. Callers that
    need the exhaustive answer pass ``exhaustive=True`` (linear scan always).

History edges
    * Root commit already violated: C = root, ``parent=None``, note "violated
      since the first commit".
    * Merge commits: only the first-parent chain is walked, so a violation that
      arrived on a side branch is reported at the **merge commit** that brought
      it into the mainline (a note names the other parents). This is the commit
      at which the mainline stopped holding, which is what a reader of
      ``main`` saw; the side-branch commit itself is not reported.
    * Truncated history: when the oldest commit of the window is a shallow-clone
      boundary (``.git/shallow``) or the ``max_commits`` cap cut the walk, and
      the claim is violated over the whole window, the entry is ``TRUNCATED``
      with ``oldest_available`` and ``truncated_by``. Nothing is guessed. A
      transition found *inside* a truncated window is still FOUND (C and its
      parent were both judged), with a note that older history was not checked.

Grounding (G4)
    Every entry is re-checked from scratch by
    ``grounding.verify.verify_first_violation`` before it is returned (results go
    to ``ledger`` with check_id ``G4``). A FOUND entry that fails becomes
    ``status=UNKNOWN, grounding=MISMATCH`` with the reasons: shown as "first
    seen: unknown", never as a fact.

Known limits: a renamed or moved ADR file counts as "missing" before the rename,
so the boundary can be the rename commit (its note says so). Only first-parent
history is searched.
"""

from __future__ import annotations

import math
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

DEFAULT_MAX_COMMITS = 500
SNAPSHOT_CACHE_SIZE = 64
MIN_SAMPLES = 9
MAX_NOTES = 20


class TimelineEntry(BaseModel):
    """Where one VIOLATED claim first stopped holding (G4 provenance: ``commit``,
    ``parent``, ``evidence``).

    Invariants (enforced): an entry whose grounding is not VERIFIED has status
    UNKNOWN and reasons (shown as "first seen: unknown"); a FOUND entry names its
    commit, date, subject and the verified evidence that makes it violated; a
    TRUNCATED entry names the oldest commit it could see and why history stopped.
    """

    claim_id: str
    status: TimelineStatus
    head: str | None = Field(default=None, description="Full SHA the walk started from.")
    first_violating_commit: str | None = None
    parent: str | None = Field(
        default=None, description="First parent of first_violating_commit; None for the root."
    )
    author_date: str | None = Field(default=None, description="ISO-8601 author date of C.")
    subject: str | None = Field(default=None, description="C's subject, sanitised.")
    evidence: list[Evidence] = Field(
        default_factory=list, description="The verified evidence at C that makes it violated."
    )
    non_monotonic: bool = False
    earlier_transitions: list[str] = Field(
        default_factory=list,
        description="Older held -> violated commits (oldest first) when non_monotonic.",
    )
    oldest_available: str | None = Field(
        default=None, description="TRUNCATED: the oldest commit of the searched window."
    )
    truncated_by: TruncatedBy | None = None
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
    manifests); ``build_timeline`` shares one cache across claims, so the sample
    commits every claim judges are loaded once."""

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
    """Judge ``claim`` against the tree of ``sha`` (offline, deterministic)."""
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


def first_parent_chain(root: Path, head: str, max_commits: int) -> list[str]:
    """First-parent history of ``head``, newest first, at most ``max_commits`` commits."""
    out = git._run(
        ["rev-list", "--first-parent", f"--max-count={max_commits}", f"{head}^{{commit}}"], root
    )
    return out.split()


def sample_indices(n: int) -> list[int]:
    """About sqrt(n) (at least MIN_SAMPLES) evenly spaced indices of 0..n-1, both
    ends included."""
    if n <= 0:
        return []
    k = min(n, max(MIN_SAMPLES, math.isqrt(n) + 1))
    if k == 1:
        return [0]
    return sorted({round(i * (n - 1) / (k - 1)) for i in range(k)})


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

    def notes(self) -> list[str]:
        raw = [self.memo[i].note for i in sorted(self.memo) if self.memo[i].note]
        shown = [n for n in raw if n][:MAX_NOTES]
        if len(raw) > MAX_NOTES:
            shown.append(f"(+{len(raw) - MAX_NOTES} more commits not judged as violated)")
        return shown


def _bisect(s: _Search, lo: int, hi: int) -> int:
    """Smallest index in (lo, hi] with V True, given V(lo) False (or lo = -1) and
    V(hi) True; returns the boundary index (always adjacent to a judged held commit
    or the window start)."""
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
    exhaustive: bool = False,
) -> TimelineEntry:
    """The commit where ``claim`` first stopped holding on the first-parent history of
    ``head`` (see the module docstring). The entry is G4-verified before it is
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
    notes: list[str] = [f"searched {n} first-parent commit(s) of {head_sha[:12]}"]
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
    if not adr_check:
        notes.append(
            f"ADR {claim.source.path} is not committed at {head_sha[:12]}; "
            "ADR-presence check skipped"
        )

    s = _Search(root, claim, commits, cache, adr_check)
    base = {"claim_id": claim.id, "head": head_sha, "commits_in_window": n}

    if not s.v(n - 1):
        j = s.judged(n - 1)
        what = j.verdict.status if j.verdict else "not judged"
        notes.append(f"at head the claim is {what}, not VERIFIED VIOLATED")
        entry = TimelineEntry(
            **base,
            status="NOT_VIOLATED_AT_HEAD",
            notes=[*notes, *s.notes()],
            commits_judged=len(s.memo),
        )
        return _ground(repo, entry, claim, config, ledger)

    if exhaustive:
        boundary = None
        linear = True
    else:
        idx = sample_indices(n)
        vals = [(i, s.v(i)) for i in idx]
        held = [i for i, ok in vals if not ok]
        last_held = held[-1] if held else -1
        linear = any(ok for i, ok in vals if i < last_held)
        boundary = None
        if not linear:
            notes.append(f"sampled {len(idx)} commit(s): monotonic, bisected")
            nxt = next(i for i, _ in vals if i > last_held)
            boundary = _bisect(s, last_held, nxt)
        else:
            notes.append(
                f"sampled {len(idx)} commit(s): violated, then held, then violated again; "
                "linear scan of the window"
            )

    if linear:
        for i in range(n):
            s.v(i)
        transitions = [i for i in range(1, n) if s.v(i) and not s.v(i - 1)]
        if s.v(0) and truncated_by is None:
            transitions.insert(0, 0)
        boundary = transitions[-1] if transitions else 0

    assert boundary is not None
    earlier: list[str] = []
    non_monotonic = False
    if linear:  # every commit is judged; the sampled path only knows its samples
        earlier = [
            commits[i]
            for i in range(boundary)
            if s.v(i) and ((i == 0 and truncated_by is None) or (i > 0 and not s.v(i - 1)))
        ]
        non_monotonic = any(s.v(i) for i in range(boundary))

    if boundary == 0 and truncated_by is not None:
        why = (
            "shallow clone: the parents of the oldest commit are not available"
            if truncated_by == "shallow"
            else f"max_commits={max_commits} reached before a commit where the claim held"
        )
        j0 = s.judged(0)
        entry = TimelineEntry(
            **{**base, "truncated_by": truncated_by},
            status="TRUNCATED",
            oldest_available=oldest,
            evidence=list(j0.verdict.evidence) if j0.verdict else [],
            notes=[*notes, f"violated over the whole window; {why}", *s.notes()],
            commits_judged=len(s.memo),
        )
        return _ground(repo, entry, claim, config, ledger)

    c = commits[boundary]
    parent = commits[boundary - 1] if boundary > 0 else None
    if parent is None:
        notes.append("violated since the first commit")
    if truncated_by is not None:
        notes.append(
            f"history truncated ({truncated_by}); transitions before {oldest[:12]} not checked"
        )
    if non_monotonic:
        shown = ", ".join(x[:12] for x in earlier) or "before the window"
        notes.append(
            "non-monotonic: the claim was violated, then held, then violated again; earlier "
            f"held -> violated transition(s): {shown}"
        )
    try:
        all_parents = git.parents(root, c)
    except git.GitError:
        all_parents = []
    if len(all_parents) > 1:
        notes.append(
            f"{c[:12]} is a merge commit: first-parent boundary; the change came in from "
            f"{', '.join(p[:12] for p in all_parents[1:])}"
        )
    info = _log1(root, c)
    j = s.judged(boundary)
    assert j.verdict is not None
    entry = TimelineEntry(
        **base,
        status="FOUND",
        first_violating_commit=c,
        parent=parent,
        author_date=info[0] if info else "",
        subject=info[1] if info else "",
        evidence=list(j.verdict.evidence),
        non_monotonic=non_monotonic,
        earlier_transitions=earlier,
        notes=[*notes, *s.notes()],
        commits_judged=len(s.memo),
    )
    return _ground(repo, entry, claim, config, ledger)


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
) -> TimelineEntry:
    from driftwarden.grounding.verify import verify_first_violation

    results = verify_first_violation(repo, entry, claim, config)
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
    exhaustive: bool = False,
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
