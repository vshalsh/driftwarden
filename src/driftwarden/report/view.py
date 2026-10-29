"""What a reporter may show as fact (L-012): one grounding cross-check for every format.

Every reporter (Markdown, PR comment, SARIF, and the HTML report of L-013) renders a
:class:`ReportView` built by :func:`build_view`, never the raw Report lists. The view
re-checks, with plain Python and no git access, that each finding's evidence carries
its own VERIFIED verifier record *in this report*:

* an evidence item is shown (and may become a SARIF location) only when the verdict's
  ``checks`` hold a VERIFIED G2 row for ``<claim id>/<evidence id>`` whose provenance
  equals the item's ``ref`` exactly, a VERIFIED G3 row whose provenance equals its
  ``dependency`` (dependency items), no failed row for that subject, the item's
  commit is the judged commit, its path is canonical and its lines are >= 1;
* undocumented decisions are held to the same rule (subject ``<record id>/<evidence id>``);
* a finding with any evidence item that fails this check is **not** shown under its
  status: it moves to *Could not verify* with the reason, anchored on the ADR line.

The pipeline already guarantees all of this for a fresh scan, so on a fresh scan the
check changes nothing. It matters for ``driftwarden report REPORT.json``, which
re-renders a saved file that anyone could have edited: a tampered evidence item
never reaches a report as a fact.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field, replace

from driftwarden.models import (
    WORKTREE,
    Claim,
    DependencyRef,
    Evidence,
    GroundingResult,
    Provenance,
    UndocumentedDecision,
    Verdict,
)
from driftwarden.report.model import (
    VERDICT_STATUSES,
    ClaimResult,
    DecisionResult,
    Report,
    UnverifiedItem,
    natural_key,
)
from driftwarden.undocumented.draft import DraftADR

AGAINST_RELATIONS = ("forbidden", "alternative", "outside_boundary")
_KIND_ORDER = {
    k: i
    for i, k in enumerate(
        ["decision", "claim", "verdict", "evidence", "undocumented", "draft", "check"]
    )
}


def canonical_path(path: str) -> bool:
    """A repo-relative POSIX path as the repository names it (no ``./``, ``..``, ``\\``)."""
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    if posixpath.normpath(path) != path:
        return False
    return not (path == ".." or path.startswith("../"))


def location_ok(ref: Provenance) -> bool:
    return canonical_path(ref.path) and 1 <= ref.line_start <= ref.line_end


def evidence_verified(
    ev: Evidence, checks: list[GroundingResult], subject: str, commit: str | None
) -> str | None:
    """None when ``ev`` is backed by its own VERIFIED rows in ``checks``; else why not."""
    ref = ev.ref
    where = f"{ref.path}:{ref.line_start}"
    if not location_ok(ref):
        return f"{ev.id}: {where} is not a canonical repo-relative path with lines >= 1"
    if commit and ref.commit != commit:
        return f"{ev.id}: {where} is from commit {ref.commit[:12]}, not the judged {commit[:12]}"
    mine = [c for c in checks if c.subject == subject]
    if not mine:
        return f"{ev.id}: {where} has no verifier record in this report"
    bad = [c for c in mine if c.status != "VERIFIED"]
    if bad:
        return f"{ev.id}: {bad[0].reason}"
    if not any(c.check_id == "G2" and c.provenance == ref for c in mine):
        return f"{ev.id}: {where} does not match its VERIFIED G2 record (edited after the scan?)"
    if ev.dependency is not None and not any(
        c.check_id == "G3" and c.provenance == ev.dependency for c in mine
    ):
        return f"{ev.id}: dependency {ev.dependency.package} does not match its VERIFIED G3 record"
    return None


@dataclass(frozen=True)
class Finding:
    """A judged claim shown under its status: every evidence item passed the cross-check."""

    result: ClaimResult
    claim: Claim
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    decision: DecisionResult | None

    @property
    def id(self) -> str:
        return self.claim.id

    @property
    def status(self) -> str:
        return self.verdict.status

    @property
    def in_change(self) -> bool | None:
        """PR mode: does the change touch this claim? None outside PR mode."""
        return self.result.in_change

    def primary(self) -> Evidence | None:
        """The evidence item a finding is located at: the first one against the claim."""
        for ev in self.evidence:
            if ev.relation in AGAINST_RELATIONS:
                return ev
        return self.evidence[0] if self.evidence else None


@dataclass(frozen=True)
class Undocumented:
    record: UndocumentedDecision
    evidence: tuple[Evidence, ...]
    draft: DraftADR | None


@dataclass(frozen=True)
class Unverified:
    """One *Could not verify* entry. ``anchor`` is the ADR line to locate it at (never
    the unverified code line); ``provenance`` is what the failed item cited, as data."""

    kind: str
    id: str
    check_id: str | None
    reasons: tuple[str, ...]
    decision_id: str | None = None
    claim_id: str | None = None
    provenance: Provenance | DependencyRef | None = None
    anchor: Provenance | None = None
    proposed_status: str | None = None
    report_check: bool = False  # True: failed the report-time cross-check, not the scan
    in_change: bool | None = None  # PR mode: the claim's ClaimResult.in_change


@dataclass
class ReportView:
    report: Report
    violated: list[Finding] = field(default_factory=list)
    drifting: list[Finding] = field(default_factory=list)
    holding: list[Finding] = field(default_factory=list)
    unknown: list[Finding] = field(default_factory=list)
    could_not_verify: list[Unverified] = field(default_factory=list)
    undocumented: list[Undocumented] = field(default_factory=list)
    not_judged: list[ClaimResult] = field(default_factory=list)
    decisions: dict[str, DecisionResult] = field(default_factory=dict)

    @property
    def pr_mode(self) -> bool:
        return self.report.metadata.changed_paths is not None or any(
            c.in_change is not None for c in self.report.claims
        )

    @property
    def demoted(self) -> int:
        return sum(1 for u in self.could_not_verify if u.report_check)

    def bucket(self, status: str) -> list[Finding]:
        return {
            "VIOLATED": self.violated,
            "DRIFTING": self.drifting,
            "HOLDING": self.holding,
            "UNKNOWN": self.unknown,
        }[status]


def _anchor(
    item: UnverifiedItem,
    claims: dict[str, Claim],
    decisions: dict[str, DecisionResult],
    adr_paths: set[str],
) -> Provenance | None:
    if item.claim_id and item.claim_id in claims:
        return claims[item.claim_id].source
    if item.kind in ("decision", "claim") and isinstance(item.provenance, Provenance):
        return item.provenance  # the ADR line itself (it is what failed G1)
    if item.decision_id and item.decision_id in decisions:
        return decisions[item.decision_id].source
    p = item.provenance
    if isinstance(p, Provenance) and p.path in adr_paths:
        return p
    return None


def _sort(items: list[Unverified]) -> list[Unverified]:
    return sorted(
        items,
        key=lambda i: (
            _KIND_ORDER.get(i.kind, 99),
            natural_key(i.id),
            i.check_id or "",
            list(i.reasons),
        ),
    )


def build_view(report: Report) -> ReportView:
    """Partition ``report`` into what may be shown as fact and what could not be verified."""
    decisions = {d.id: d for d in report.decisions}
    claims = {c.claim.id: c.claim for c in report.claims}
    adr_paths = {d.source.path for d in report.decisions}
    view = ReportView(report=report, decisions=decisions)
    cnv: list[Unverified] = []
    for item in report.could_not_verify:
        cnv.append(
            Unverified(
                kind=item.kind,
                id=item.id,
                check_id=item.check_id,
                reasons=tuple(item.reasons) or ("no reason recorded",),
                decision_id=item.decision_id,
                claim_id=item.claim_id,
                provenance=item.provenance,
                anchor=_anchor(item, claims, decisions, adr_paths),
                proposed_status=item.proposed_status,
            )
        )
    listed_verdicts = {u.claim_id for u in cnv if u.kind == "verdict"}

    for cr in report.claims:
        v = cr.verdict
        if not cr.judged or v is None:
            view.not_judged.append(cr)
            continue
        claim = cr.claim
        if v.could_not_verify:
            if claim.id not in listed_verdicts:  # a saved report missing its item
                cnv.append(
                    Unverified(
                        kind="verdict",
                        id=claim.id,
                        check_id=None,
                        reasons=tuple(v.reasons),
                        decision_id=claim.decision_id,
                        claim_id=claim.id,
                        provenance=claim.source,
                        anchor=claim.source,
                        proposed_status=v.proposed_status,
                    )
                )
            continue
        commit = v.commit or report.metadata.commit
        problems = [
            p
            for ev in v.evidence
            if (p := evidence_verified(ev, v.checks, f"{claim.id}/{ev.id}", commit)) is not None
        ]
        if problems or (v.status in ("VIOLATED", "DRIFTING") and not v.evidence):
            cnv.append(
                Unverified(
                    kind="verdict",
                    id=claim.id,
                    check_id="G2",
                    reasons=tuple(problems or [f"a {v.status} verdict without evidence"]),
                    decision_id=claim.decision_id,
                    claim_id=claim.id,
                    provenance=claim.source,
                    anchor=claim.source,
                    proposed_status=v.status,
                    report_check=True,
                )
            )
            continue
        view.bucket(v.status).append(
            Finding(
                result=cr,
                claim=claim,
                verdict=v,
                evidence=tuple(v.evidence),
                decision=decisions.get(claim.decision_id),
            )
        )

    drafts = {d.record_id: d for d in report.drafts if not d.could_not_verify and d.markdown}
    for rec in report.undocumented:
        problems = [
            p
            for ev in rec.evidence
            if (p := evidence_verified(ev, rec.checks, f"{rec.id}/{ev.id}", rec.commit)) is not None
        ]
        if rec.could_not_verify:
            problems = list(rec.reasons) or ["record is not VERIFIED"]
        elif not rec.evidence:
            problems.append("an undocumented decision without evidence")
        if problems:
            cnv.append(
                Unverified(
                    kind="undocumented",
                    id=rec.id,
                    check_id="G2",
                    reasons=tuple(problems),
                    report_check=True,
                )
            )
            continue
        view.undocumented.append(
            Undocumented(record=rec, evidence=tuple(rec.evidence), draft=drafts.get(rec.id))
        )

    in_change = {c.claim.id: c.in_change for c in report.claims}
    cnv = [
        replace(u, in_change=in_change.get(u.claim_id)) if u.claim_id in in_change else u
        for u in cnv
    ]
    view.could_not_verify = _sort(cnv)
    return view


REGATE_REASON = "re-render: no matching VERIFIED ledger record"


def regate(report: Report) -> Report:
    """``report`` with the :func:`build_view` checks applied to the data itself (L-012 D1).

    ``driftwarden report`` calls this once on a loaded Report before rendering any format,
    so JSON, Markdown, SARIF and HTML agree. A finding that fails the cross-check becomes
    ``UNKNOWN`` / ``MISMATCH`` (its ``proposed_status`` kept), an undocumented record that
    fails is removed with its draft, each one gets a *Could not verify* item whose first
    reason is ``REGATE_REASON``, and the summary, drift score and exit code are recomputed.
    A report that passes is returned unchanged (same object), so a fresh scan's JSON
    round-trips byte for byte. Known limit: a file whose ledger rows were forged too cannot
    be caught without re-scanning (``report`` re-renders; ``scan`` verifies).
    """
    view = build_view(report)
    listed = {(i.kind, i.id) for i in report.could_not_verify}
    new = [u for u in view.could_not_verify if u.report_check or (u.kind, u.id) not in listed]
    if not new:
        return report
    demoted_claims = {u.claim_id for u in new if u.kind == "verdict" and u.claim_id}
    demoted_records = {u.id for u in new if u.kind == "undocumented"}

    claims: list[ClaimResult] = []
    for cr in report.claims:
        v = cr.verdict
        if cr.claim.id in demoted_claims and v is not None and not v.could_not_verify:
            why = next(u for u in new if u.claim_id == cr.claim.id)
            data = v.model_dump()
            data.update(
                status="UNKNOWN",
                grounding="MISMATCH",
                proposed_status=v.status,
                reasons=[REGATE_REASON, *why.reasons],
                rationale=f"{REGATE_REASON} (was {v.status})",
            )
            cr = cr.model_copy(update={"verdict": Verdict.model_validate(data)})
        claims.append(cr)

    items = list(report.could_not_verify)
    for u in new:
        reasons = (
            list(u.reasons)
            if u.reasons and u.reasons[0] == REGATE_REASON
            else [
                REGATE_REASON,
                *u.reasons,
            ]
        )
        items.append(
            UnverifiedItem(
                kind=u.kind,  # type: ignore[arg-type]
                id=u.id,
                check_id=u.check_id,
                reasons=reasons,
                decision_id=u.decision_id,
                claim_id=u.claim_id,
                provenance=u.provenance,
                proposed_status=u.proposed_status,  # type: ignore[arg-type]
            )
        )
    items.sort(
        key=lambda i: (_KIND_ORDER.get(i.kind, 99), natural_key(i.id), i.check_id or "", i.reasons)
    )
    undocumented = [r for r in report.undocumented if r.id not in demoted_records]
    drafts = [d for d in report.drafts if d.record_id not in demoted_records]

    judged = [c for c in claims if c.judged and c.verdict is not None]
    by_status = {st: sum(1 for c in judged if c.status == st) for st in VERDICT_STATUSES}
    decided = by_status["HOLDING"] + by_status["DRIFTING"] + by_status["VIOLATED"]
    drift = (by_status["DRIFTING"] + by_status["VIOLATED"]) / decided if decided else None
    if any(i.check_id == "G1" for i in items):
        exit_code = 3
    elif by_status["VIOLATED"]:
        exit_code = 1
    else:
        exit_code = 0
    summary = report.summary.model_copy(
        update={
            "claims_judged": len(judged),
            "by_status": by_status,
            "unknown": by_status["UNKNOWN"],
            "could_not_verify": len(items),
            "undocumented": len(undocumented),
            "drafts": len(drafts),
            "drift_score": drift,
            "exit_code": exit_code,
        }
    )
    return report.model_copy(
        update={
            "claims": claims,
            "could_not_verify": items,
            "undocumented": undocumented,
            "drafts": drafts,
            "summary": summary,
        }
    )


_SHA = re.compile(r"[0-9a-f]{7,64}")


def valid_sha(commit: str | None) -> bool:
    """A lowercase hex SHA (or WORKTREE): anything else comes from an edited report."""
    return commit == WORKTREE or (commit is not None and bool(_SHA.fullmatch(commit)))


def full_sha(commit: str | None) -> str:
    """``commit`` for display, or ``invalid`` when it is not a hex SHA (L-012 D4)."""
    if not valid_sha(commit):
        return "invalid"
    return "worktree" if commit == WORKTREE else str(commit)


def short_sha(commit: str | None) -> str:
    """Seven hex digits, ``worktree``, or ``invalid`` for anything that is not a SHA."""
    if not valid_sha(commit):
        return "invalid"
    return "worktree" if commit == WORKTREE else str(commit)[:7]


__all__ = [
    "AGAINST_RELATIONS",
    "Finding",
    "ReportView",
    "Undocumented",
    "Unverified",
    "REGATE_REASON",
    "build_view",
    "canonical_path",
    "evidence_verified",
    "full_sha",
    "location_ok",
    "regate",
    "short_sha",
    "valid_sha",
]
