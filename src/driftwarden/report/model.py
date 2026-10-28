"""The Report: one typed, serialisable result of a whole scan (L-028).

``driftwarden.pipeline.run_scan`` builds it; it is the single input for every
reporter (JSON, Markdown, SARIF, HTML, PR comment) and for the benchmark.

Grounding rules the model carries (see README "Grounding & traceability"):

* ``claims[*].verdict`` is shown as a fact only when its ``grounding`` is VERIFIED.
* ``could_not_verify`` lists every decision, claim, verdict, evidence item,
  undocumented record, draft and any other verifier row of this run that failed
  grounding, each with its reasons. Nothing is dropped silently.
* ``grounding_summary`` is computed from the ledger rows this run wrote, not
  from counters kept on the side.

Ordering is stable (decision id, claim id, record id, then path/line), so two
offline runs on the same commit give byte-identical JSON apart from
``metadata.scanned_at``.

``drift_score`` (``Summary``): the share of judged claims of accepted decisions
with a decided, VERIFIED verdict (HOLDING, DRIFTING or VIOLATED) that are not
HOLDING, i.e. ``(DRIFTING + VIOLATED) / (HOLDING + DRIFTING + VIOLATED)``.
UNKNOWN verdicts (including *Could not verify*) are left out of both sides and
counted separately in ``Summary.unknown``. ``None`` when nothing was decided.

``exit_code`` (``Summary``), the CLI's recommendation:

* 3: something in ``could_not_verify`` came from G1 (an ADR decision or claim
  whose quote is not at its cited lines). Wins over 1.
* 1: at least one claim is VIOLATED (a VIOLATED verdict is always VERIFIED).
* 0: otherwise.
"""

from __future__ import annotations

import re
from datetime import date as Date
from typing import Literal

from pydantic import BaseModel, Field

from driftwarden.models import (
    AdrFormat,
    Claim,
    DependencyRef,
    GroundingResult,
    GroundingStatus,
    Provenance,
    Status,
    UndocumentedDecision,
    UnverifiedClaim,
    Verdict,
    VerdictStatus,
)
from driftwarden.undocumented.draft import DraftADR

REPORT_SCHEMA_VERSION = 1
CHECK_IDS: tuple[str, ...] = ("G1", "G2", "G3", "G4", "G5", "G6")
VERDICT_STATUSES: tuple[VerdictStatus, ...] = ("HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN")

RunMode = Literal["offline", "llm"]
UnverifiedKind = Literal[
    "decision", "claim", "verdict", "evidence", "undocumented", "draft", "check"
]


def natural_key(value: str) -> tuple:
    """Sort key that orders embedded numbers numerically ("c2" before "c10")."""
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in re.split(r"(\d+)", value)
        if part
    )


class Metadata(BaseModel):
    tool: str = "driftwarden"
    tool_version: str
    schema_version: int = REPORT_SCHEMA_VERSION
    repo: str = Field(description="Name of the repository root directory.")
    commit: str = Field(description="Full SHA judged, or WORKTREE (repository without commits).")
    scanned_at: str = Field(description="UTC ISO-8601 time of the scan.")
    mode: RunMode
    requested_mode: str = Field(description="What was asked for: auto, offline or llm.")
    provider: str | None = Field(default=None, description="LLM provider name (llm mode only).")
    model: str | None = Field(default=None, description="LLM model (llm mode only).")
    changed_paths: list[str] | None = Field(
        default=None, description="PR mode: the paths the judged claims were filtered by."
    )
    draft_adrs: bool = False


class DecisionResult(BaseModel):
    """One ADR decision: what it says about itself, its G1 check, and whether it was judged."""

    id: str
    title: str
    status: Status
    format: AdrFormat
    date: Date | None = None
    superseded_by: str | None = None
    source: Provenance
    g1: GroundingResult
    judged: bool
    not_judged_reason: str | None = None
    claim_ids: list[str] = Field(default_factory=list)


class ClaimResult(BaseModel):
    """One verified claim and, when it was judged, its verdict."""

    claim: Claim
    judged: bool
    not_judged_reason: str | None = None
    verdict: Verdict | None = None

    @property
    def id(self) -> str:
        return self.claim.id

    @property
    def status(self) -> VerdictStatus | None:
        return self.verdict.status if self.verdict is not None else None

    @property
    def could_not_verify(self) -> bool:
        return self.verdict is not None and self.verdict.could_not_verify


class UnverifiedItem(BaseModel):
    """Anything that failed grounding: shown as *Could not verify* with its reasons."""

    kind: UnverifiedKind
    id: str = Field(description="Decision / claim / record id, or the ledger row's subject.")
    check_id: str | None = Field(
        default=None, description="The failed check (G1..G6) when one verifier row says so."
    )
    reasons: list[str]
    decision_id: str | None = None
    claim_id: str | None = None
    provenance: Provenance | DependencyRef | None = None
    proposed_status: VerdictStatus | None = None


class TimelineEntry(BaseModel):
    """Reserved for L-011 (drift timeline, G4). Not produced yet."""

    claim_id: str
    first_violating_commit: str | None = None
    parent: str | None = None
    date: str | None = None
    subject: str | None = None
    grounding: GroundingStatus | None = None


class CheckSummary(BaseModel):
    total: int = 0
    verified: int = 0
    mismatch: int = 0
    pass_rate: float | None = Field(default=None, description="None when nothing was checked.")


class GroundingSummary(BaseModel):
    total: int = 0
    verified: int = 0
    mismatch: int = 0
    pass_rate: float | None = None
    by_check: dict[str, CheckSummary] = Field(default_factory=dict)


class Summary(BaseModel):
    decisions: int = 0
    decisions_judged: int = 0
    claims: int = Field(default=0, description="Verified claims (judged or not).")
    claims_judged: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    unknown: int = Field(default=0, description="Judged claims with status UNKNOWN.")
    could_not_verify: int = 0
    undocumented: int = 0
    drafts: int = 0
    drift_score: float | None = None
    exit_code: int = 0


class Report(BaseModel):
    metadata: Metadata
    decisions: list[DecisionResult] = Field(default_factory=list)
    claims: list[ClaimResult] = Field(default_factory=list)
    unverified_claims: list[UnverifiedClaim] = Field(
        default_factory=list, description="Claims that failed G1 or were malformed (not judged)."
    )
    could_not_verify: list[UnverifiedItem] = Field(default_factory=list)
    undocumented: list[UndocumentedDecision] = Field(
        default_factory=list, description="VERIFIED undocumented decisions."
    )
    drafts: list[DraftADR] = Field(
        default_factory=list, description="VERIFIED ADR drafts (never written to the repo)."
    )
    timeline: list[TimelineEntry] = Field(
        default_factory=list, description="Reserved for L-011; empty until then."
    )
    grounding_summary: GroundingSummary = Field(default_factory=GroundingSummary)
    summary: Summary = Field(default_factory=Summary)
    notes: list[str] = Field(default_factory=list)

    def verdicts(self, status: VerdictStatus) -> list[ClaimResult]:
        """Judged claims with a VERIFIED verdict of ``status``."""
        return [
            c
            for c in self.claims
            if c.verdict is not None
            and c.verdict.status == status
            and not c.verdict.could_not_verify
        ]


def rule_text(claim: Claim) -> str:
    """A short, human form of a claim's rule, e.g. ``only(datastore) = [postgresql]``."""
    r = claim.rule

    def lst(key: str) -> str:
        v = r.get(key)
        return "[" + ", ".join(str(x) for x in v) + "]" if isinstance(v, list) else str(v)

    if claim.kind == "only":
        cat = r.get("category") or claim.subject
        return f"only({cat}) = {lst('only')}"
    if claim.kind == "forbid":
        return f"forbid {lst('forbid')}"
    if claim.kind == "require":
        return f"require {lst('require')}"
    if claim.kind == "boundary":
        side = "allowed_in" if "allowed_in" in r else "via"
        return f"boundary {lst('target')} {side} {lst(side)}"
    return f'free "{r.get("text", "")}"'


__all__ = [
    "CHECK_IDS",
    "REPORT_SCHEMA_VERSION",
    "CheckSummary",
    "ClaimResult",
    "DecisionResult",
    "GroundingSummary",
    "Metadata",
    "Report",
    "Summary",
    "TimelineEntry",
    "UnverifiedItem",
    "natural_key",
    "rule_text",
]
