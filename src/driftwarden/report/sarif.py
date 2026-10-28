"""SARIF 2.1.0 for GitHub code scanning (L-012).

One run, tool ``DriftWarden``. Rules: one per claim kind (``forbid``, ``require``,
``only``, ``boundary``, ``free``) plus ``undocumented-decision`` and
``could-not-verify``. Results, built from :func:`driftwarden.report.view.build_view`:

=====================  ==========  ===============================================
What                   level       primary location
=====================  ==========  ===============================================
VIOLATED claim         error       the first VERIFIED evidence item against it
DRIFTING claim         warning     the same
undocumented decision  note        its first VERIFIED evidence item
could not verify       note        the ADR line (never the unverified code line)
=====================  ==========  ===============================================

HOLDING and UNKNOWN produce no result. Only evidence that passed the report-time
cross-check (``view.evidence_verified``) may become a location; an item that failed is
reported only as ``could-not-verify``. ``relatedLocations`` hold the ADR source lines
and the other verified evidence. Locations are repo-relative POSIX URIs
(percent-encoded, no leading ``./``) against ``uriBaseId`` ``SRCROOT``, with
``startLine``/``endLine`` >= 1 and no columns. A could-not-verify item with no ADR line
to anchor on (e.g. a failed undocumented record) has no valid location: it is listed in
``run.properties.driftwarden.unlocated`` instead of being dropped.

``partialFingerprints["driftwarden/v1"]`` is a SHA-256 of (rule id, claim or record id,
primary path, item discriminator); it leaves out commits, line numbers and messages, so
GitHub matches the same alert across runs.

GitHub upload limits are enforced: at most ``MAX_RESULTS`` results per run and
``MAX_BYTES`` bytes of SARIF (stricter than GitHub's 10 MB gzip limit), and at most
``MAX_RELATED`` related locations per result. Results are emitted most important first
(errors, could-not-verify, warnings, undocumented), so truncation drops the least
important; ``run.properties.driftwarden.truncated`` says what was cut.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

from driftwarden.models import Evidence, Provenance
from driftwarden.report.model import Report, rule_text
from driftwarden.report.view import (
    Finding,
    Undocumented,
    Unverified,
    build_view,
    location_ok,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/vshalsh/driftwarden"
MAX_RESULTS = 25_000
MAX_BYTES = 10 * 1024 * 1024
MAX_RELATED = 1_000
FINGERPRINT_KEY = "driftwarden/v1"
_TEXT_LIMIT = 2_000

_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    # id, name, level, short, full
    (
        "forbid",
        "ForbiddenTechnology",
        "error",
        "Code uses a technology an accepted ADR forbids",
        "An accepted architecture decision forbids this technology, and the repository "
        "uses it. The evidence lines were checked verbatim by a deterministic verifier.",
    ),
    (
        "require",
        "RequiredTechnology",
        "error",
        "Code departs from a technology an accepted ADR requires",
        "An accepted architecture decision requires a technology; the repository is missing "
        "it or uses an alternative. The evidence lines were checked verbatim.",
    ),
    (
        "only",
        "OnlyAllowedTechnology",
        "error",
        "Code uses a technology outside the only one(s) an accepted ADR allows",
        "An accepted architecture decision allows only certain technologies in a category; "
        "the repository uses another one. The evidence lines were checked verbatim.",
    ),
    (
        "boundary",
        "ModuleBoundary",
        "error",
        "Code crosses a boundary an accepted ADR sets",
        "An accepted architecture decision limits where a module or technology may be used; "
        "the repository uses it outside those paths. The evidence lines were checked verbatim.",
    ),
    (
        "free",
        "FreeFormDecision",
        "error",
        "Code contradicts a free-form accepted ADR",
        "A judged free-form architecture decision does not hold. Every cited line was "
        "checked verbatim by a deterministic verifier.",
    ),
    (
        "undocumented-decision",
        "UndocumentedDecision",
        "note",
        "Architectural choice in the code that no ADR covers",
        "The repository uses a technology (datastore, queue, framework, cloud SDK...) that "
        "no ADR records. DriftWarden can draft the missing ADR (--draft-adrs).",
    ),
    (
        "could-not-verify",
        "CouldNotVerify",
        "note",
        "A finding DriftWarden could not verify",
        "A decision, claim, verdict or evidence item failed its deterministic verifier. It "
        "is not a finding and is never shown as a violation; the reason is in the message.",
    ),
)
RULE_IDS = tuple(r[0] for r in _RULES)
_RULE_INDEX = {rid: i for i, rid in enumerate(RULE_IDS)}


_EMBEDDED_LINK = re.compile(r"\[([^\[\]]*)\]\(")


def _text(s: object, limit: int = _TEXT_LIMIT) -> str:
    """SARIF plain-text message: one line, and no ``[text](target)`` embedded link can
    form (SARIF §3.11.6 escapes ``\\[`` / ``\\]``); other brackets stay as written."""
    t = " ".join(str(s).split())
    if len(t) > limit:
        t = t[: limit - 1] + "…"
    t = re.sub(r"\\(?=[\[\]])", r"\\\\", t)
    return _EMBEDDED_LINK.sub(lambda m: "\\[" + m.group(1) + "\\](", t)


def _uri(path: str) -> str:
    return quote(path, safe="/-._~")


def _physical(ref: Provenance) -> dict[str, Any]:
    start = max(1, ref.line_start)
    region = {"startLine": start, "endLine": max(start, ref.line_end)}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(ref.path), "uriBaseId": "SRCROOT"},
            "region": region,
        }
    }


def _location(ref: Provenance | None) -> dict[str, Any] | None:
    if ref is None or not location_ok(ref):
        return None
    return _physical(ref)


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _related(entries: list[tuple[Provenance, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ref, msg in entries:
        loc = _location(ref)
        if loc is None:
            continue
        loc = {"id": len(out) + 1, **loc, "message": {"text": _text(msg, 500)}}
        out.append(loc)
        if len(out) >= MAX_RELATED:
            break
    return out


def _ev_msg(ev: Evidence) -> str:
    return f"evidence {ev.id}: {ev.detail or ev.ref.quote}"


def _finding_result(f: Finding, commit: str) -> dict[str, Any]:
    c, v = f.claim, f.verdict
    level = "error" if v.status == "VIOLATED" else "warning"
    title = f.decision.title if f.decision is not None else c.decision_id
    primary = f.primary()
    msg = (
        f"{c.id} {v.status}: {rule_text(c)}. ADR {c.decision_id} ({title}) says "
        f'"{c.source.quote}" at {c.source.path}:{c.source.line_start}. {v.rationale}'
    )
    related = [(c.source, f"ADR {c.decision_id} source ({c.id})")]
    related += [(ev.ref, _ev_msg(ev)) for ev in f.evidence if ev is not primary]
    loc = _location(primary.ref if primary is not None else None) or _location(c.source)
    primary_path = primary.ref.path if primary is not None else c.source.path
    props: dict[str, Any] = {
        "status": v.status,
        "grounding": v.grounding,
        "commit": commit,
        "adrId": c.decision_id,
        "claimId": c.id,
        "evidence": [e.id for e in f.evidence],
    }
    if f.in_change is not None:
        props["inChange"] = f.in_change
    return {
        "ruleId": c.kind,
        "ruleIndex": _RULE_INDEX[c.kind],
        "level": level,
        "message": {"text": _text(msg)},
        "locations": [loc] if loc else [],
        "relatedLocations": _related(related),
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(c.kind, c.id, primary_path)},
        "properties": props,
    }


def _undocumented_result(u: Undocumented, commit: str) -> dict[str, Any]:
    rec = u.record
    primary = u.evidence[0]
    first = rec.introducing_commits[0][:12] if rec.introducing_commits else "?"
    msg = (
        f"Undocumented decision {rec.id}: {rec.title or rec.technology} "
        f"(category {rec.category}). No ADR covers it; introduced by commit {first}."
    )
    return {
        "ruleId": "undocumented-decision",
        "ruleIndex": _RULE_INDEX["undocumented-decision"],
        "level": "note",
        "message": {"text": _text(msg)},
        "locations": [_physical(primary.ref)],
        "relatedLocations": _related([(ev.ref, _ev_msg(ev)) for ev in u.evidence[1:]]),
        "partialFingerprints": {
            FINGERPRINT_KEY: fingerprint("undocumented-decision", rec.id, primary.ref.path)
        },
        "properties": {
            "status": "UNDOCUMENTED",
            "grounding": rec.grounding,
            "commit": commit,
            "recordId": rec.id,
            "introducingCommits": list(rec.introducing_commits),
        },
    }


def _cnv_result(u: Unverified, commit: str) -> dict[str, Any] | None:
    loc = _location(u.anchor)
    if loc is None:
        return None
    assert u.anchor is not None
    check = f" [{u.check_id}]" if u.check_id else ""
    proposed = (
        f" (proposed {u.proposed_status}, not reported as a finding)" if u.proposed_status else ""
    )
    msg = f"Could not verify {u.kind} {u.id}{check}{proposed}: " + "; ".join(u.reasons)
    props: dict[str, Any] = {
        "status": "COULD_NOT_VERIFY",
        "grounding": "MISMATCH",
        "commit": commit,
        "kind": u.kind,
        "itemId": u.id,
        "reasons": list(u.reasons),
    }
    if u.decision_id:
        props["adrId"] = u.decision_id
    if u.claim_id:
        props["claimId"] = u.claim_id
    if u.check_id:
        props["checkId"] = u.check_id
    if u.in_change is not None:
        props["inChange"] = u.in_change
    claim_or_id = u.claim_id or u.decision_id or u.id
    return {
        "ruleId": "could-not-verify",
        "ruleIndex": _RULE_INDEX["could-not-verify"],
        "level": "note",
        "message": {"text": _text(msg)},
        "locations": [loc],
        "partialFingerprints": {
            FINGERPRINT_KEY: fingerprint(
                "could-not-verify", claim_or_id, u.anchor.path, u.kind, u.id, u.check_id or ""
            )
        },
        "properties": props,
    }


def _driver(report: Report) -> dict[str, Any]:
    v = report.metadata.tool_version
    rules = []
    for rid, name, level, short, full in _RULES:
        rules.append(
            {
                "id": rid,
                "name": name,
                "shortDescription": {"text": short},
                "fullDescription": {"text": full},
                "helpUri": INFORMATION_URI
                + ("#grounding--traceability" if rid == "could-not-verify" else ""),
                "help": {"text": full},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": ["architecture", "adr", "drift"]},
            }
        )
    return {
        "name": "DriftWarden",
        "version": v,
        "semanticVersion": v,
        "informationUri": INFORMATION_URI,
        "rules": rules,
    }


def _build(report: Report) -> tuple[list[dict[str, Any]], list[str]]:
    view = build_view(report)
    commit = report.metadata.commit
    results: list[dict[str, Any]] = [_finding_result(f, commit) for f in view.violated]
    unlocated: list[str] = []
    for u in view.could_not_verify:
        r = _cnv_result(u, commit)
        if r is None:
            unlocated.append(f"{u.kind} {u.id}: " + "; ".join(u.reasons))
        else:
            results.append(r)
    results += [_finding_result(f, commit) for f in view.drifting]
    results += [_undocumented_result(u, commit) for u in view.undocumented]
    return results, unlocated


def _document(report: Report, results: list, props: dict[str, Any]) -> dict[str, Any]:
    m = report.metadata
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": _driver(report)},
                "invocations": [{"executionSuccessful": True, "endTimeUtc": m.scanned_at}],
                "results": results,
                "properties": {"driftwarden": props},
            }
        ],
    }


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_sarif(
    report: Report, *, max_results: int = MAX_RESULTS, max_bytes: int = MAX_BYTES
) -> str:
    """SARIF 2.1.0 text for ``report`` (see the module docstring)."""
    m = report.metadata
    results, unlocated = _build(report)
    props: dict[str, Any] = {
        "reportSchemaVersion": m.schema_version,
        "repo": m.repo,
        "commit": m.commit,
        "mode": m.mode,
        "driftScore": report.summary.drift_score,
        "exitCode": report.summary.exit_code,
        "resultsTotal": len(results),
    }
    if unlocated:
        props["unlocated"] = unlocated
    total = len(results)

    def emit(k: int, reason: str | None) -> str:
        p = dict(props)
        if reason is not None:
            p["truncated"] = {
                "reason": reason,
                "resultsTotal": total,
                "resultsEmitted": k,
                "resultsDropped": total - k,
            }
        return _dump(_document(report, results[:k], p))

    k = min(total, max_results)
    reason = f"more than {max_results} results (GitHub limit per run)" if k < total else None
    text = emit(k, reason)
    if len(text.encode("utf-8")) <= max_bytes:
        return text
    lo, hi = 0, k  # largest k whose document fits
    size_reason = f"SARIF larger than {max_bytes} bytes (GitHub upload limit)"
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(emit(mid, size_reason).encode("utf-8")) <= max_bytes:
            lo = mid
        else:
            hi = mid - 1
    return emit(lo, size_reason)


__all__ = [
    "FINGERPRINT_KEY",
    "INFORMATION_URI",
    "MAX_BYTES",
    "MAX_RELATED",
    "MAX_RESULTS",
    "RULE_IDS",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "fingerprint",
    "render_sarif",
]
