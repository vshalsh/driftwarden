"""End-to-end scan pipeline (L-028): one function, one typed result.

``run_scan`` runs every stage in ARCHITECTURE.md order and returns a
:class:`~driftwarden.report.model.Report`:

1. Discover and parse ADRs (``discover.adr.scan_adrs`` for ``commit="HEAD"``,
   which reads tracked, clean ADRs at HEAD and the rest from the working tree,
   as ``driftwarden scan`` always has; ``scan_adrs_at`` for any other commit).
2. G1 on every decision's own source quote.
3. Structure claims (``claims.structure.structure_scan``) for the decisions that
   are judged: status ``accepted`` *and* a VERIFIED decision quote. Proposed,
   superseded, deprecated, rejected and unknown-status decisions are listed with
   the reason and never judged (``structure_scan`` itself structures every
   decision and leaves this choice to the caller, so the pipeline makes it here).
4. Judge each claim at the commit (``judge.judge.Judge`` over one ``Snapshot``;
   in llm mode through ``judge.consistency.ConsistencyRunner``, 3 runs + vote,
   G6). Offline mode judges once: the rules are deterministic.
5. Detect undocumented decisions (``undocumented.detect.detect_undocumented``,
   same Snapshot). Needs a commit: a repository with no commits skips it (noted).
6. Optionally draft ADRs for the verified records (``undocumented.draft.draft_adr``
   with ``write=False``: drafts are returned, never written into the repository;
   always the deterministic template, the LLM polish is not used here).
7. Assemble the Report.

The repository is indexed once: the same Snapshot serves the judge and the
detector. Every verifier result of every stage goes to ``ledger``, and the
Report's ``grounding_summary`` is computed from the rows this call appended.

**PR mode (``changed_paths``).** Every accepted claim is judged exactly as in a
full scan: ``changed_paths`` never decides *what* is judged, so PR mode can never
hide a violation, and the exit code counts every verified violation. It only
tags each judged claim with ``ClaimResult.in_change`` (``None`` outside PR mode)
so reporters can lead with the findings the change touches. ``in_change`` is
true when (see :func:`claim_touches`):

* the claim's ADR file is in ``changed_paths``; or
* a changed path is, or lies under, a path or term the rule names (any string
  value of the rule: ``target``, ``allowed_in``, ``via``, ``scope``, ``actor``,
  the forbid / require / only terms ...); or
* a changed path is the file or manifest of any of the claim's evidence items,
  collected **without** the per-group cap the judge uses (a 51st file importing
  a forbidden package still counts) and **with** every keyword (``code``)
  candidate (a free-form claim has no other evidence), or of anything the verdict
  or one of its consistency runs cited; or
* conservatively, for ``require`` and ``only`` claims (whose verdict can change
  when something disappears): a changed path is not in the scanned tree (it was
  deleted, or is the old name of a rename), or is a dependency manifest.

Paths are compared as canonical repo-relative POSIX strings (``./`` and trailing
``/`` removed), case-sensitively. Undocumented-decision detection and drafting
are not filtered.

**Draft numbering.** Drafts of one scan reserve their suggested paths in turn
(passed to ``draft_adr`` as ``existing_adrs``), so three drafts get three
consecutive ADR numbers, never the same one.
"""

from __future__ import annotations

import json
import posixpath
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from driftwarden import __version__, git
from driftwarden.claims.structure import resolve_mode, structure_scan
from driftwarden.config import Config
from driftwarden.discover.adr import AdrScan, scan_adrs, scan_adrs_at
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_source_quote
from driftwarden.index.manifests import detect as detect_manifest
from driftwarden.judge.consistency import DEFAULT_RUNS, ConsistencyRunner
from driftwarden.judge.evidence import EvidenceSet, collect_evidence, load_snapshot
from driftwarden.judge.judge import Judge
from driftwarden.llm.base import Provider
from driftwarden.models import (
    WORKTREE,
    Claim,
    Decision,
    GroundingResult,
    UnverifiedClaim,
    Verdict,
)
from driftwarden.report.model import (
    CHECK_IDS,
    VERDICT_STATUSES,
    CheckSummary,
    ClaimResult,
    DecisionResult,
    GroundingSummary,
    Metadata,
    Report,
    Summary,
    UnverifiedItem,
    natural_key,
)
from driftwarden.undocumented.detect import detect_undocumented
from driftwarden.undocumented.draft import DraftADR, draft_adr
from driftwarden.undocumented.draft import _existing_adrs as existing_adr_paths

RULE_PATH_KEYS = ("target", "allowed_in", "via", "scope", "actor")
UNCAPPED = 10**9
"""``max_per_relation`` for PR-mode relevance: every evidence item, no cap."""

_KIND_ORDER = {
    k: i
    for i, k in enumerate(
        ["decision", "claim", "verdict", "evidence", "undocumented", "draft", "check"]
    )
}


# --------------------------------------------------------------------------- helpers


def _canon(path: str) -> str:
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.strip("/")
    return posixpath.normpath(p) if p else ""


def _under(path: str, base: str) -> bool:
    return bool(base) and (path == base or path.startswith(base + "/"))


def _rule_strings(rule: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for value in rule.values():
        for v in value if isinstance(value, list) else [value]:
            if isinstance(v, str):
                out.append(v)
    return out


def claim_touches(
    claim: Claim,
    es: EvidenceSet | None,
    changed: set[str],
    *,
    absent: set[str] | None = None,
    manifests: set[str] | None = None,
) -> bool:
    """The PR-mode ``in_change`` rule (module docstring). ``es`` should be the claim's
    UNCAPPED evidence; ``absent`` are the changed paths missing from the scanned tree
    (deleted or renamed away); ``manifests`` the changed paths that are manifests."""
    if _canon(claim.source.path) in changed:
        return True
    for v in _rule_strings(claim.rule):
        base = _canon(v)
        if base and any(_under(p, base) for p in changed):
            return True
    if es is not None:
        for ev in es.candidates:
            if _canon(ev.ref.path) in changed:
                return True
            if ev.dependency is not None and _canon(ev.dependency.manifest_path) in changed:
                return True
    if claim.kind in ("require", "only") and (absent or manifests):
        return True
    return False


def _not_judged_reason(dec: Decision, g1: GroundingResult) -> str | None:
    if dec.status != "accepted":
        why = f"status is {dec.status}; only accepted decisions are judged"
        if dec.superseded_by:
            why += f" (superseded by {dec.superseded_by})"
        return why
    if g1.status != "VERIFIED":
        return "the decision's own quote failed G1, so its claims are not structured or judged"
    return None


def _ledger_lines(ledger: Ledger) -> list[str]:
    """The ledger's JSONL records. Split on "\\n" ONLY (D2): the ledger is written with
    ``ensure_ascii=False``, so NEL, U+2028 and U+2029 can sit unescaped inside a record,
    and ``str.splitlines()`` would cut the record there. The empty string after the
    trailing newline is dropped."""
    try:
        text = ledger.path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


_ROW_KEYS = {"run_id": str, "check_id": str, "status": str, "reason": str}


def _ledger_rows(ledger: Ledger, start: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Rows this run appended to ``ledger`` (after record ``start``), and a reason for
    every record that is not a valid row. Bad records are reported, never a crash."""
    rows: list[dict[str, Any]] = []
    bad: list[str] = []
    for n, line in enumerate(_ledger_lines(ledger)[start:], start + 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            bad.append(f"{ledger.path.name} record {n} is not valid JSON ({exc})")
            continue
        if not isinstance(row, dict) or any(
            not isinstance(row.get(k), t) for k, t in _ROW_KEYS.items()
        ):
            bad.append(f"{ledger.path.name} record {n} is not a grounding result row")
            continue
        if row["status"] not in ("VERIFIED", "MISMATCH"):
            bad.append(f"{ledger.path.name} record {n} has unknown status {row['status']!r}")
            continue
        if row["run_id"] == ledger.run_id:
            rows.append(row)
    return rows, bad


def _line_count(ledger: Ledger) -> int:
    return len(_ledger_lines(ledger))


def grounding_summary(rows: list[dict[str, Any]]) -> GroundingSummary:
    """Totals and pass rates per check id (G1-G6 always present), from ledger rows."""
    counts: Counter[tuple[str, str]] = Counter((r["check_id"], r["status"]) for r in rows)
    ids = sorted({*CHECK_IDS, *(c for c, _ in counts)}, key=natural_key)
    by_check: dict[str, CheckSummary] = {}
    for cid in ids:
        ok, bad = counts[(cid, "VERIFIED")], counts[(cid, "MISMATCH")]
        total = ok + bad
        by_check[cid] = CheckSummary(
            total=total, verified=ok, mismatch=bad, pass_rate=(ok / total) if total else None
        )
    ok = sum(v for (_, s), v in counts.items() if s == "VERIFIED")
    total = sum(counts.values())
    return GroundingSummary(
        total=total,
        verified=ok,
        mismatch=total - ok,
        pass_rate=(ok / total) if total else None,
        by_check=by_check,
    )


def _unverified_claim_item(uc: UnverifiedClaim) -> UnverifiedItem:
    g = uc.grounding
    return UnverifiedItem(
        kind="claim",
        id=uc.id,
        check_id=g.check_id if g is not None and g.status != "VERIFIED" else None,
        reasons=[uc.reason],
        decision_id=uc.decision_id,
        claim_id=uc.id,
        provenance=uc.source,
    )


def _verdict_items(claim: Claim, v: Verdict) -> list[UnverifiedItem]:
    if not v.could_not_verify:
        return []
    items = [
        UnverifiedItem(
            kind="verdict",
            id=claim.id,
            reasons=list(v.reasons),
            decision_id=claim.decision_id,
            claim_id=claim.id,
            provenance=claim.source,
            proposed_status=v.proposed_status,
        )
    ]
    seen: set[tuple] = set()
    for c in v.checks:
        if c.status == "VERIFIED":
            continue
        key = (c.check_id, c.subject, c.reason)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            UnverifiedItem(
                kind="evidence",
                id=c.subject or claim.id,
                check_id=c.check_id,
                reasons=[c.reason],
                decision_id=claim.decision_id,
                claim_id=claim.id,
                provenance=c.provenance,
            )
        )
    return items


def _sort_items(items: list[UnverifiedItem]) -> list[UnverifiedItem]:
    return sorted(
        items,
        key=lambda i: (
            _KIND_ORDER[i.kind],
            natural_key(i.id),
            i.check_id or "",
            i.reasons,
        ),
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- run_scan


def run_scan(
    repo: str | Path,
    *,
    config: Config,
    mode: str,
    provider: Provider | None = None,
    commit: str = "HEAD",
    ledger: Ledger,
    draft_adrs: bool = False,
    changed_paths: list[str] | None = None,
    adrs: AdrScan | None = None,
    runs: int = DEFAULT_RUNS,
) -> Report:
    """Run the whole pipeline on ``repo`` at ``commit`` and return the Report.

    ``mode``: ``offline``, ``llm`` or ``auto`` (llm iff ``provider`` is a
    non-offline provider; see ``claims.structure.resolve_mode``). ``llm`` needs a
    ``provider``. ``adrs`` is an ADR scan the caller already made (the CLI prints
    its warnings first); by default the ADRs are discovered here. ``runs`` is the
    number of consistency runs per claim in llm mode.

    Raises git.GitError when ``repo`` is not a git repository or ``commit`` does
    not name a commit; ValueError for ``mode="llm"`` without a provider.
    """
    resolved = resolve_mode(mode, provider)
    root = git.repo_root(repo)
    start = _line_count(ledger)
    notes: list[str] = []

    # 1. ADRs, and the commit everything is judged at.
    if commit == "HEAD":
        scan = adrs if adrs is not None else scan_adrs(root, config)
        target = scan.head if scan.head is not None else WORKTREE
    else:
        target = git.resolve_commit(root, commit)
        scan = adrs if adrs is not None else scan_adrs_at(root, target, config)
    for rel, msg in scan.errors:
        notes.append(f"could not read ADR {rel}: {msg}")
    for rel, note in scan.skipped:
        notes.append(f"skipped ADR {rel}: {note}")
    if target == WORKTREE:
        notes.append("repository has no commits; the working tree was judged")

    # 2. G1 on every decision.
    decisions = sorted(scan.decisions, key=lambda d: natural_key(d.id))
    g1s: dict[str, GroundingResult] = {}
    for dec in decisions:
        gr = verify_source_quote(root, dec.source, check_id="G1", subject=dec.id)
        ledger.append(gr)
        g1s[dec.id] = gr
    reasons = {d.id: _not_judged_reason(d, g1s[d.id]) for d in decisions}
    judged_decisions = [d for d in decisions if reasons[d.id] is None]

    # 3. Claims for the judged decisions (every G1 result to the ledger).
    sets = structure_scan(judged_decisions, root, mode=resolved, provider=provider, ledger=ledger)
    claims: list[Claim] = sorted(
        (c for s in sets for c in s.claims), key=lambda c: natural_key(c.id)
    )
    unverified = sorted((u for s in sets for u in s.unverified), key=lambda u: natural_key(u.id))
    for s in sets:
        notes.extend(f"{s.decision_id}: {n}" for n in s.notes)

    # 4. Judge, at one snapshot.
    snap = load_snapshot(root, target, config)
    judge = Judge(
        root, mode=resolved, provider=provider, config=config, ledger=ledger, snapshot=snap
    )
    runner = ConsistencyRunner(judge, runs=runs) if resolved == "llm" else None
    changed = (
        {p for p in (_canon(x) for x in changed_paths) if p} if changed_paths is not None else None
    )
    absent: set[str] = set()
    manifests: set[str] = set()
    if changed is not None:
        present = {f.path for f in snap.files}
        absent = {p for p in changed if p not in present}
        manifests = {p for p in changed if detect_manifest(p) is not None}
    results: list[ClaimResult] = []
    for claim in claims:
        es = judge.evidence(claim)
        verdict = runner.run(claim, es) if runner is not None else judge.judge(claim, es)
        in_change = None
        if changed is not None:
            # Relevance uses the UNCAPPED evidence, keyword (code) candidates included: the
            # judge's caps must never hide the changed file, and a free-form claim has only
            # keyword evidence. Plus everything the verdict (or any consistency run) cited.
            # It only tags; everything is judged regardless.
            full = collect_evidence(claim, snap, max_per_relation=UNCAPPED, max_keywords=UNCAPPED)
            cited = [*verdict.evidence]
            if verdict.consistency is not None:
                cited += [e for vote in verdict.consistency.votes for e in vote.evidence]
            full = full.model_copy(update={"candidates": [*full.candidates, *cited]})
            in_change = claim_touches(claim, full, changed, absent=absent, manifests=manifests)
        results.append(ClaimResult(claim=claim, judged=True, verdict=verdict, in_change=in_change))

    # 5. Undocumented decisions (needs a commit).
    at_commit_claims = [c for c in claims if c.source.commit == snap.commit]
    at_commit = all(d.source.commit == snap.commit for d in decisions)
    found = []
    undoc_cnv = []
    if snap.commit == WORKTREE:
        notes.append("undocumented-decision detection skipped: it needs a commit")
    else:
        und = detect_undocumented(
            root,
            snap.commit,
            decisions=decisions if at_commit else None,
            claims=at_commit_claims,
            config=config,
            snapshot=snap,
            ledger=ledger,
        )
        found = sorted(und.findings, key=lambda r: natural_key(r.id))
        undoc_cnv = sorted(und.could_not_verify, key=lambda r: natural_key(r.id))
        notes.extend(und.notes)

    # 6. Drafts (never written).
    drafts: list[DraftADR] = []
    failed_drafts: list[DraftADR] = []
    if draft_adrs:
        # One shared list of taken ADR paths: each verified draft reserves its suggested
        # path before the next is numbered, so drafts of one scan never share a number.
        reserved = existing_adr_paths(root, snap.commit, config)
        for rec in found:
            d = draft_adr(
                root,
                rec,
                existing_adrs=list(reserved),
                decisions=decisions if at_commit else None,
                claims=at_commit_claims,
                config=config,
                write=False,
                ledger=ledger,
            )
            (failed_drafts if d.could_not_verify else drafts).append(d)
            if not d.could_not_verify and d.path:
                reserved.append(d.path)

    # 7. Assemble.
    items: list[UnverifiedItem] = []
    for dec in decisions:
        gr = g1s[dec.id]
        if gr.status != "VERIFIED":
            items.append(
                UnverifiedItem(
                    kind="decision",
                    id=dec.id,
                    check_id="G1",
                    reasons=[gr.reason],
                    decision_id=dec.id,
                    provenance=dec.source,
                )
            )
    items.extend(_unverified_claim_item(u) for u in unverified)
    for cr in results:
        if cr.verdict is not None:
            items.extend(_verdict_items(cr.claim, cr.verdict))
    for rec in undoc_cnv:
        items.append(UnverifiedItem(kind="undocumented", id=rec.id, reasons=list(rec.reasons)))
    for d in failed_drafts:
        items.append(UnverifiedItem(kind="draft", id=d.record_id, reasons=list(d.reasons)))

    # Catch-all (D1): a failed ledger row is "already reported" only when that exact row,
    # (check_id, subject, reason), is one of the verifier results behind an item above.
    # Never by subject prefix: a different failure about the same claim is its own item.
    reported: list[GroundingResult] = [g1s[d.id] for d in decisions]
    reported += [u.grounding for u in unverified if u.grounding is not None]
    reported += [c for cr in results if cr.verdict is not None and cr.verdict.could_not_verify
                 for c in cr.verdict.checks]  # fmt: skip
    reported += [c for rec in undoc_cnv for c in rec.checks]
    reported += [c for d in failed_drafts for c in d.checks]
    seen: set[tuple] = {
        (g.check_id, g.subject or "", g.reason) for g in reported if g.status != "VERIFIED"
    }
    rows, bad_rows = _ledger_rows(ledger, start)
    for r in rows:
        if r["status"] == "VERIFIED":
            continue
        subject = r.get("subject") if isinstance(r.get("subject"), str) else ""
        key = (r["check_id"], subject, r["reason"])
        if key in seen:
            continue
        seen.add(key)
        item = dict(kind="check", id=subject or r["check_id"], check_id=r["check_id"],
                    reasons=[r["reason"]])  # fmt: skip
        try:
            items.append(UnverifiedItem(**item, provenance=r.get("provenance")))
        except ValidationError:  # an unreadable provenance must not hide the failure
            items.append(UnverifiedItem(**item))
    for n, why in enumerate(bad_rows, 1):
        # A ledger record that cannot be read is itself a grounding gap: report it.
        items.append(UnverifiedItem(kind="check", id=f"ledger-record-{n}", reasons=[why]))
    items = _sort_items(items)

    claim_ids: dict[str, list[str]] = {}
    for c in claims:
        claim_ids.setdefault(c.decision_id, []).append(c.id)
    decision_results: list[DecisionResult] = []
    for dec in decisions:
        why = reasons[dec.id]
        if why is None and not claim_ids.get(dec.id):
            why = "no testable claim was extracted from the decision text"
        decision_results.append(
            DecisionResult(
                id=dec.id,
                title=dec.title,
                status=dec.status,
                format=dec.format,
                date=dec.date,
                superseded_by=dec.superseded_by,
                source=dec.source,
                g1=g1s[dec.id],
                judged=why is None,
                not_judged_reason=why,
                claim_ids=claim_ids.get(dec.id, []),
            )
        )

    judged = [cr for cr in results if cr.judged and cr.verdict is not None]
    by_status = {s: sum(1 for cr in judged if cr.status == s) for s in VERDICT_STATUSES}
    decided = by_status["HOLDING"] + by_status["DRIFTING"] + by_status["VIOLATED"]
    drift = (by_status["DRIFTING"] + by_status["VIOLATED"]) / decided if decided else None
    if any(i.check_id == "G1" for i in items):
        exit_code = 3
    elif by_status["VIOLATED"]:
        exit_code = 1
    else:
        exit_code = 0

    provider_name = model = None
    if resolved == "llm" and provider is not None:
        provider_name = getattr(provider, "name", None)
        model = getattr(provider, "model", None)
    meta = Metadata(
        tool_version=__version__,
        repo=root.name,
        commit=snap.commit,
        scanned_at=_now(),
        mode=resolved,
        requested_mode=mode or "auto",
        provider=provider_name,
        model=model,
        changed_paths=sorted(changed) if changed is not None else None,
        draft_adrs=draft_adrs,
    )
    return Report(
        metadata=meta,
        decisions=decision_results,
        claims=results,
        unverified_claims=unverified,
        could_not_verify=items,
        undocumented=found,
        drafts=sorted(drafts, key=lambda d: natural_key(d.record_id)),
        timeline=[],
        grounding_summary=grounding_summary(rows),
        summary=Summary(
            decisions=len(decisions),
            decisions_judged=sum(1 for d in decision_results if d.judged),
            claims=len(claims),
            claims_judged=len(judged),
            by_status=by_status,
            unknown=by_status["UNKNOWN"],
            could_not_verify=len(items),
            undocumented=len(found),
            drafts=len(drafts),
            drift_score=drift,
            exit_code=exit_code,
        ),
        notes=notes,
    )


__all__ = ["RULE_PATH_KEYS", "claim_touches", "grounding_summary", "run_scan"]
