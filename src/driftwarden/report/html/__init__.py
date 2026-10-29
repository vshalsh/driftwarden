"""Self-contained HTML report (L-013).

``render_html(report, link_base=...)`` turns a :class:`~driftwarden.report.model.Report`
into one HTML file that works fully offline: the design tokens (``tokens.css``, a
vendored copy of ``design/tokens.css`` that a test keeps byte-identical), the component
styles and a small vanilla script are inlined; there are no external requests, fonts or
frameworks. The page is complete with JavaScript disabled; the script only adds search,
the theme toggle, expand/collapse-all and copy buttons.

Grounding (README "Grounding & traceability"): the page renders the shared verified view
(:func:`driftwarden.report.view.build_view`, L-012), exactly like the Markdown and SARIF
reporters. A finding is shown under its status only when every evidence item carries its
own VERIFIED G2 (and G3) record at the judged commit; anything else, and everything in
``Report.could_not_verify``, is shown under *Could not verify* with its reasons, in violet
with its own icon, never as a violation. That section is always rendered, with an
explicit empty state.

Security: every string in a Report comes from a scanned repository and is untrusted. The
template is rendered with Jinja2 autoescape on and nothing from the report is marked
safe. The page has no event handlers. The only ``href`` built from data is an ADR link:
the ADR path must be canonical (``view.canonical_path``), it is percent-encoded, and the
prefix is the ``link_base`` validated by the Markdown reporter's rule, so it can never
carry a scheme. Unicode bidi and control characters are made visible (an RTL override
cannot disguise a path). A CSP meta tag forbids every fetch.
"""

from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.parse import quote

from jinja2 import Environment, StrictUndefined
from markupsafe import Markup

from driftwarden.models import DependencyRef, Evidence, Provenance, Verdict
from driftwarden.report.markdown import NO_LINKS, _anchor, _link_prefix
from driftwarden.report.model import CHECK_IDS, Report, rule_text
from driftwarden.report.view import (
    Finding,
    Undocumented,
    Unverified,
    build_view,
    canonical_path,
    full_sha,
    short_sha,
)

PROJECT_URL = "https://github.com/vshalsh/driftwarden"

CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"

DRIFT_SCORE_DEFINITION = (
    "Share of decided claims that are not holding: (drifting + violated) / "
    "(holding + drifting + violated), counting only claims of accepted decisions with a "
    "verified verdict. Unknown and Could-not-verify claims are left out of both sides."
)

CHECK_NAMES = {
    "G1": "Claim quote is at its cited ADR lines",
    "G2": "Code evidence is at its cited lines",
    "G3": "Dependency re-parsed from its manifest",
    "G4": "First violating commit (timeline)",
    "G5": "Draft ADR cites only real commits and evidence",
    "G6": "Verdict stable across independent runs",
}

KIND_LABELS = {
    "decision": "ADR decision",
    "claim": "Claim",
    "verdict": "Verdict",
    "evidence": "Evidence",
    "undocumented": "Undocumented decision",
    "draft": "Draft ADR",
    "check": "Verifier check",
}

# Bidi embedding/override/isolate controls and marks. Shown as visible text so a
# path or snippet cannot be visually reordered (Trojan Source).
_BIDI = re.compile("[؜‎‏‪-‮⁦-⁩]")
# Other C0/C1 controls except tab and newline.
_CTRL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _visible(text: str) -> str:
    text = _BIDI.sub(lambda m: f"[U+{ord(m.group()):04X}]", text)
    return _CTRL.sub(lambda m: f"[U+{ord(m.group()):04X}]", text)


def _finalize(value: Any) -> Any:
    """Applied to every ``{{ }}`` output before autoescape."""
    if value is None:
        return ""
    if isinstance(value, Markup):  # only our own package assets are Markup
        return value
    if isinstance(value, str):
        return _visible(value)
    return value


def _lines(a: int, b: int) -> str:
    return f"L{a}" if a == b else f"L{a}-L{b}"


def range_label(p: Provenance) -> str:
    """``path:Lstart-Lend@sha``, the ADR link label."""
    return f"{p.path}:L{p.line_start}-L{p.line_end}@{short_sha(p.commit)}"


def loc_label(p: Provenance) -> str:
    """``file:line@sha`` (``file:Lstart-Lend@sha`` for a range)."""
    return f"{p.path}:{_lines(p.line_start, p.line_end)}@{short_sha(p.commit)}"


def dep_label(d: DependencyRef) -> str:
    line = f":L{d.line}" if d.line is not None else ""
    return f"{d.manifest_path}{line}@{short_sha(d.commit)}"


def adr_href(p: Provenance, link_base: str | None) -> str | None:
    """Link target for an ADR line, by the same rule as the Markdown report; None = text."""
    if link_base == NO_LINKS or not canonical_path(p.path):
        return None
    base = _link_prefix(link_base)
    if base is None:
        return None
    return f"{base}{quote(p.path, safe='/-._~')}{_anchor(p.line_start, p.line_end)}"


def _prov_view(p: Provenance | DependencyRef | None) -> dict | None:
    if p is None:
        return None
    if isinstance(p, Provenance):
        return {"label": loc_label(p), "quote": p.quote}
    spec = f" {p.version_spec}" if p.version_spec else ""
    return {"label": dep_label(p), "quote": f"{p.package}{spec}"}


def _evidence_view(e: Evidence) -> dict:
    tags = [e.kind]
    if e.technology:
        tags.append(e.technology)
    if e.relation:
        tags.append(e.relation.replace("_", " "))
    if not e.production:
        tags.append("non-production")
    return {
        "id": e.id,
        "label": loc_label(e.ref),
        "snippet": e.ref.quote,
        "tags": tags,
        "detail": e.detail,
    }


def _grounding_view(checks: list, extra: list[tuple[str, int, int]] | None = None) -> dict:
    """Per-check verified/total counts for a grounding badge."""
    total: Counter[str] = Counter()
    ok: Counter[str] = Counter()
    for cid, v, t in extra or []:
        ok[cid] += v
        total[cid] += t
    for c in checks:
        total[c.check_id] += 1
        ok[c.check_id] += c.status == "VERIFIED"
    items = [
        {"id": cid, "ok": ok[cid], "total": total[cid], "all": ok[cid] == total[cid]}
        for cid in sorted(total, key=lambda x: (x not in CHECK_IDS, x))
    ]
    return {"items": items, "all": all(i["all"] for i in items)}


def _consistency_label(v: Verdict) -> str | None:
    c = v.consistency
    if c is None:
        return None
    if c.basis == "deterministic":
        return "G6 deterministic"
    agree = sum(1 for x in c.votes if x.status == v.status)
    return f"G6 {agree}/{c.executed} agree"


def _in_change_first(items: list) -> list:
    """PR mode: in-change items first (stable), as the Markdown report orders them."""
    return sorted(items, key=lambda x: 0 if x.in_change else 1)


class _View:
    def __init__(self, report: Report, link_base: str | None) -> None:
        self.r = report
        self.view = build_view(report)
        self.link_base = link_base
        self.timeline = {t.claim_id: t for t in report.timeline}
        self.counter = 0

    def uid(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def adr(self, p: Provenance) -> dict:
        return {"label": range_label(p), "href": adr_href(p, self.link_base)}

    def since(self, claim_id: str) -> dict | None:
        t = self.timeline.get(claim_id)
        if t is None:
            return None
        if t.grounding == "VERIFIED" and t.first_violating_commit:
            return {
                "known": True,
                "commit": short_sha(t.first_violating_commit),
                "full": full_sha(t.first_violating_commit),
                "date": t.date,
                "subject": t.subject,
            }
        return {"known": False}

    def finding(self, f: Finding) -> dict:
        c, v, dec = f.claim, f.verdict, f.decision
        g1 = [("G1", 1, 1)] if dec is None or dec.g1.status == "VERIFIED" else [("G1", 0, 1)]
        return {
            "uid": self.uid("f"),
            "id": c.id,
            "status": v.status,
            "decision_id": c.decision_id,
            "decision_title": dec.title if dec else "",
            "adr": self.adr(c.source),
            "quote": c.source.quote,
            "rule": rule_text(c),
            "rationale": v.rationale,
            "notes": list(v.notes),
            "evidence": [_evidence_view(e) for e in f.evidence],
            "since": self.since(c.id),
            "grounding": _grounding_view(v.checks, g1),
            "consistency": _consistency_label(v),
            "in_change": f.in_change,
            "not_judged_reason": None,
        }

    def not_judged(self, cr) -> dict:
        c = cr.claim
        dec = self.view.decisions.get(c.decision_id)
        return {
            "uid": self.uid("n"),
            "id": c.id,
            "status": "NOT_JUDGED",
            "decision_id": c.decision_id,
            "decision_title": dec.title if dec else "",
            "adr": self.adr(c.source),
            "rule": rule_text(c),
            "rationale": "",
            "evidence": [],
            "in_change": cr.in_change,
            "not_judged_reason": cr.not_judged_reason or "not judged",
        }

    def unverified(self, u: Unverified) -> dict:
        dec = self.view.decisions.get(u.decision_id or "")
        return {
            "uid": self.uid("u"),
            "kind": KIND_LABELS.get(u.kind, u.kind),
            "id": u.id,
            "check_id": u.check_id,
            "reasons": list(u.reasons),
            "decision_id": u.decision_id,
            "decision_title": dec.title if dec else None,
            "claim_id": u.claim_id if u.claim_id != u.id else None,
            "anchor": self.adr(u.anchor) if u.anchor is not None else None,
            "prov": _prov_view(u.provenance),
            "proposed_status": u.proposed_status,
            "report_check": u.report_check,
            "in_change": u.in_change,
        }

    def undocumented(self, u: Undocumented) -> dict:
        rec, draft = u.record, u.draft
        intro: dict[str, list[str]] = {}
        for i in rec.introductions:
            intro.setdefault(i.commit, []).append(loc_label(i.ref))
        commits = [
            {"short": short_sha(sha), "full": full_sha(sha), "refs": intro.get(sha, [])}
            for sha in rec.introducing_commits
        ]
        d = None
        if draft is not None:
            d = {
                "uid": self.uid("draft"),
                "markdown": draft.markdown or "",
                "path": draft.path,
                "origin": draft.origin,
                "grounding": _grounding_view(draft.checks),
            }
        return {
            "uid": self.uid("ud"),
            "id": rec.id,
            "title": rec.title or f"{rec.technology} ({rec.category})",
            "technology": rec.technology,
            "category": rec.category,
            "commit": short_sha(rec.commit),
            "evidence": [_evidence_view(e) for e in u.evidence],
            "commits": commits,
            "searched_terms": list(rec.searched_terms),
            "grounding": _grounding_view(rec.checks),
            "draft": d,
        }

    def build(self) -> dict:
        r, view = self.r, self.view
        m = r.metadata
        violated = [self.finding(f) for f in _in_change_first(view.violated)]
        drifting = [self.finding(f) for f in _in_change_first(view.drifting)]
        holding = [self.finding(f) for f in _in_change_first(view.holding)]
        unknown = [self.finding(f) for f in _in_change_first(view.unknown)]
        cnv = [self.unverified(u) for u in _in_change_first(view.could_not_verify)]
        undocumented = [self.undocumented(u) for u in view.undocumented]
        not_judged = [self.not_judged(c) for c in view.not_judged]
        decisions_not_judged = [
            {"id": d.id, "title": d.title, "status": d.status, "reason": d.not_judged_reason}
            for d in r.decisions
            if not d.judged
        ]
        decided = len(violated) + len(drifting) + len(holding)
        not_holding = len(violated) + len(drifting)
        gs = r.grounding_summary
        checks = []
        for cid in sorted(set(CHECK_IDS) | set(gs.by_check), key=lambda x: (x not in CHECK_IDS, x)):
            cs = gs.by_check.get(cid)
            checks.append(
                {
                    "id": cid,
                    "name": CHECK_NAMES.get(cid, ""),
                    "total": cs.total if cs else 0,
                    "verified": cs.verified if cs else 0,
                    "mismatch": cs.mismatch if cs else 0,
                    "rate": _pct(cs.pass_rate) if cs else None,
                }
            )
        timeline = [
            {
                "claim_id": t.claim_id,
                "commit": short_sha(t.first_violating_commit),
                "full": full_sha(t.first_violating_commit),
                "parent": short_sha(t.parent) if t.parent else None,
                "date": t.date,
                "subject": t.subject,
                "verified": t.grounding == "VERIFIED" and bool(t.first_violating_commit),
            }
            for t in r.timeline
        ]
        # The score is computed from the facts on this page (the verified view), so it
        # always agrees with the counts beside it; on a fresh scan it equals
        # summary.drift_score.
        score = not_holding / decided if decided else None
        return {
            "meta": {
                "repo": m.repo,
                "commit": short_sha(m.commit),
                "commit_full": full_sha(m.commit),
                "scanned_at": m.scanned_at,
                "mode": m.mode,
                "requested_mode": m.requested_mode,
                "provider": m.provider,
                "model": m.model,
                "tool": m.tool,
                "tool_version": m.tool_version,
                "changed_paths": len(m.changed_paths) if m.changed_paths is not None else None,
                "exit_code": r.summary.exit_code,
            },
            "pr_mode": view.pr_mode,
            "in_change_count": sum(1 for f in violated + drifting if f["in_change"]),
            "score": None if score is None else f"{score * 100:.0f}%",
            "score_definition": DRIFT_SCORE_DEFINITION,
            "decided": decided,
            "not_holding": not_holding,
            "summary": r.summary,
            "demoted": view.demoted,
            "violated": violated,
            "drifting": drifting,
            "holding": holding,
            "unknown": unknown,
            "cnv": cnv,
            "undocumented": undocumented,
            "not_judged": not_judged,
            "decisions_not_judged": decisions_not_judged,
            "timeline": timeline,
            "checks": checks,
            "gs": {
                "total": gs.total,
                "verified": gs.verified,
                "mismatch": gs.mismatch,
                "rate": _pct(gs.pass_rate),
            },
            "notes": list(r.notes),
        }


def _pct(rate: float | None) -> str | None:
    return None if rate is None else f"{rate * 100:.1f}%"


def _read(name: str) -> str:
    return resources.files(__package__).joinpath(name).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(
        autoescape=True,
        undefined=StrictUndefined,
        finalize=_finalize,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.globals.update(project_url=PROJECT_URL, csp=CSP)
    return env


@lru_cache(maxsize=1)
def _assets() -> dict[str, str]:
    return {
        "tokens_css": _read("tokens.css"),
        "report_css": _read("report.css"),
        "head_js": _read("head.js"),
        "report_js": _read("report.js"),
        "template": _read("report.html.j2"),
    }


def render_html(report: Report, *, link_base: str | None = None) -> str:
    """Render ``report`` as one self-contained, offline HTML document.

    ``link_base`` follows ``render_markdown``: None gives repo-relative ADR links, a
    relative POSIX path (what the CLI passes: from the output directory to the repo root)
    or an ``https://`` blob URL prefixes them, and ``NO_LINKS`` (``""``) or anything else
    gives plain-text locations.
    """
    assets = _assets()
    template = _env().from_string(assets["template"])
    # The four assets are our own package files, not report data; they are passed
    # through dedicated variables and inserted raw inside <style>/<script>.
    return template.render(
        v=_View(report, link_base).build(),
        tokens_css=Markup(assets["tokens_css"]),
        report_css=Markup(assets["report_css"]),
        head_js=Markup(assets["head_js"]),
        report_js=Markup(assets["report_js"]),
    )


__all__ = ["CSP", "PROJECT_URL", "adr_href", "render_html"]
