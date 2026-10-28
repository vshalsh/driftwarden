"""Self-contained HTML report (L-013).

``render_html(report)`` turns a :class:`~driftwarden.report.model.Report` into one
HTML file that works fully offline: the design tokens (``tokens.css``, a vendored
copy of ``design/tokens.css`` that a test keeps byte-identical), the component
styles and a small vanilla script are inlined; there are no external requests,
fonts or frameworks. The page is complete with JavaScript disabled; the script
only adds search, the theme toggle, expand/collapse-all and copy buttons.

Security: every string in a Report comes from a scanned repository and is
untrusted. The template is rendered with Jinja2 autoescape on, nothing from the
report is marked safe, no data ever reaches an ``href``/``src`` or an event
handler (the page has none), and Unicode bidi controls are made visible (so an
RTL override cannot disguise a path). A CSP meta tag forbids every fetch.

Grounding (README "Grounding & traceability"): VIOLATED / DRIFTING / HOLDING are
shown only from ``Report.verdicts()``, i.e. VERIFIED verdicts; everything in
``Report.could_not_verify`` is shown under *Could not verify* with its reasons,
in violet with its own icon, and never as a violation. That section is always
rendered, with an explicit empty state.
"""

from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from importlib import resources
from typing import Any

from jinja2 import Environment, StrictUndefined
from markupsafe import Markup

from driftwarden.models import WORKTREE, DependencyRef, Evidence, Provenance, Verdict
from driftwarden.report.model import CHECK_IDS, Report, rule_text

PROJECT_URL = "https://github.com/vshalsh/driftwarden"
SHORT_SHA = 12

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


def short(sha: str | None) -> str:
    if not sha:
        return "unknown"
    if sha == WORKTREE:
        return WORKTREE
    return sha[:SHORT_SHA]


def range_label(p: Provenance) -> str:
    """``path:Lstart-Lend@sha``, the ADR link label."""
    return f"{p.path}:L{p.line_start}-L{p.line_end}@{short(p.commit)}"


def loc_label(p: Provenance) -> str:
    """``file:line@sha`` (``file:Lstart-Lend@sha`` for a range)."""
    lines = f"L{p.line_start}" if p.line_start == p.line_end else f"L{p.line_start}-L{p.line_end}"
    return f"{p.path}:{lines}@{short(p.commit)}"


def dep_label(d: DependencyRef) -> str:
    line = f":L{d.line}" if d.line is not None else ""
    return f"{d.manifest_path}{line}@{short(d.commit)}"


def _prov_view(p: Provenance | DependencyRef | dict | None) -> dict | None:
    if p is None:
        return None
    if isinstance(p, dict):  # tolerate a raw ledger row
        try:
            p = Provenance(**p) if "path" in p else DependencyRef(**p)
        except Exception:
            return {"label": str(p), "quote": None}
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
        "dependency": dep_label(e.dependency) if e.dependency else None,
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


class _View:
    def __init__(self, report: Report) -> None:
        self.r = report
        self.decisions = {d.id: d for d in report.decisions}
        self.timeline = {t.claim_id: t for t in report.timeline}
        self.counter = 0

    def uid(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def since(self, claim_id: str) -> dict | None:
        t = self.timeline.get(claim_id)
        if t is None:
            return None
        if t.grounding == "VERIFIED" and t.first_violating_commit:
            return {
                "known": True,
                "commit": short(t.first_violating_commit),
                "full": t.first_violating_commit,
                "date": t.date,
                "subject": t.subject,
            }
        return {"known": False}

    def claim(self, cr) -> dict:
        c = cr.claim
        dec = self.decisions.get(c.decision_id)
        v = cr.verdict
        g1 = [("G1", 1, 1)] if dec is None or dec.g1.status == "VERIFIED" else [("G1", 0, 1)]
        return {
            "uid": self.uid("f"),
            "id": c.id,
            "status": cr.status or "NOT_JUDGED",
            "decision_id": c.decision_id,
            "decision_title": dec.title if dec else "",
            "adr_label": range_label(c.source),
            "quote": c.source.quote,
            "rule": rule_text(c),
            "origin": c.origin,
            "rationale": v.rationale if v else "",
            "notes": list(v.notes) if v else [],
            "evidence": [_evidence_view(e) for e in v.evidence] if v else [],
            "since": self.since(c.id),
            "grounding": _grounding_view(v.checks if v else [], g1),
            "consistency": _consistency_label(v) if v else None,
            "verdict_origin": v.origin if v else None,
            "not_judged_reason": cr.not_judged_reason,
        }

    def unverified(self, item) -> dict:
        prov = _prov_view(item.provenance)
        dec = self.decisions.get(item.decision_id or "")
        return {
            "uid": self.uid("u"),
            "kind": KIND_LABELS.get(item.kind, item.kind),
            "id": item.id,
            "check_id": item.check_id,
            "reasons": list(item.reasons),
            "decision_id": item.decision_id,
            "decision_title": dec.title if dec else None,
            "claim_id": item.claim_id if item.claim_id != item.id else None,
            "prov": prov,
            "proposed_status": item.proposed_status,
        }

    def undocumented(self, rec, draft) -> dict:
        intro = {}
        for i in rec.introductions:
            intro.setdefault(i.commit, []).append(loc_label(i.ref))
        commits = [
            {"short": short(sha), "full": sha, "refs": intro.get(sha, [])}
            for sha in rec.introducing_commits
        ]
        d = None
        if draft is not None:
            d = {
                "uid": self.uid("draft"),
                "markdown": draft.markdown or "",
                "path": draft.path,
                "number": draft.number,
                "origin": draft.origin,
                "grounding": _grounding_view(draft.checks),
            }
        return {
            "uid": self.uid("ud"),
            "id": rec.id,
            "title": rec.title or f"{rec.technology} ({rec.category})",
            "technology": rec.technology,
            "category": rec.category,
            "commit": short(rec.commit),
            "evidence": [_evidence_view(e) for e in rec.evidence],
            "commits": commits,
            "searched_terms": list(rec.searched_terms),
            "grounding": _grounding_view(rec.checks),
            "draft": d,
        }

    def build(self) -> dict:
        r = self.r
        m = r.metadata
        violated = [self.claim(c) for c in r.verdicts("VIOLATED")]
        drifting = [self.claim(c) for c in r.verdicts("DRIFTING")]
        holding = [self.claim(c) for c in r.verdicts("HOLDING")]
        unknown = [self.claim(c) for c in r.verdicts("UNKNOWN")]
        cnv = [self.unverified(i) for i in r.could_not_verify]
        drafts = {d.record_id: d for d in r.drafts}
        undocumented = [self.undocumented(u, drafts.get(u.id)) for u in r.undocumented]
        not_judged = [self.claim(c) for c in r.claims if not c.judged]
        decisions_not_judged = [
            {"id": d.id, "title": d.title, "status": d.status, "reason": d.not_judged_reason}
            for d in r.decisions
            if not d.judged
        ]
        decided = len(violated) + len(drifting) + len(holding)
        score = r.summary.drift_score
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
                "commit": short(t.first_violating_commit) if t.first_violating_commit else None,
                "full": t.first_violating_commit,
                "parent": short(t.parent) if t.parent else None,
                "date": t.date,
                "subject": t.subject,
                "verified": t.grounding == "VERIFIED" and bool(t.first_violating_commit),
            }
            for t in r.timeline
        ]
        return {
            "meta": {
                "repo": m.repo,
                "commit": short(m.commit),
                "commit_full": m.commit,
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
            "score": None if score is None else f"{score * 100:.0f}%",
            "score_definition": DRIFT_SCORE_DEFINITION,
            "decided": decided,
            "not_holding": len(violated) + len(drifting),
            "summary": r.summary,
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


def render_html(report: Report) -> str:
    """Render ``report`` as one self-contained, offline HTML document."""
    assets = _assets()
    template = _env().from_string(assets["template"])
    # The four assets are our own package files, not report data; they are passed
    # through dedicated variables and inserted raw inside <style>/<script>.
    return template.render(
        v=_View(report).build(),
        tokens_css=Markup(assets["tokens_css"]),
        report_css=Markup(assets["report_css"]),
        head_js=Markup(assets["head_js"]),
        report_js=Markup(assets["report_js"]),
    )


__all__ = ["CSP", "PROJECT_URL", "render_html"]
