"""Markdown reports (L-012): the full report and the compact PR comment.

``render_markdown(report)`` is a human report that reads well on GitHub;
``render_markdown(report, compact=True)`` and ``render_pr_comment(report)`` stay under
GitHub's 65,536-character comment limit (``COMPACT_BUDGET``) by truncating lists with
"… and N more".

What is shown as fact comes from :func:`driftwarden.report.view.build_view`: only
findings whose evidence carries its own VERIFIED verifier record. Everything else is
under **Could not verify**, a section that is always present.

**Escaping.** Every piece of user-controlled text (ADR text, titles, rationale,
reasons, commit subjects, paths, ids) goes through :func:`esc` (inline Markdown or,
inside ``<summary>``, HTML) or :func:`code` (a code span sized to its backticks).
``esc`` folds newlines and shows every other Unicode control, format, line or paragraph
separator character (categories Cc, Cf, Zl, Zp: bidi controls, zero-width characters,
BOM...) as a visible ``\\uXXXX``; it backslash-escapes the Markdown punctuation that
can open a link, image, emphasis, code span, HTML tag, entity, table cell or math span;
it puts a zero-width joiner after ``@`` (no ``@mention`` pings), after ``://``, ``www``,
``GH-`` and a ``#`` before a digit or name (no autolink or issue cross-reference), and
inside ``<!--`` (user text can never forge the PR-comment marker). Code spans and fenced
blocks get the same character and ``<!--`` treatment. Draft ADRs are shown as the
Markdown *source* in a fenced block longer than any backtick run inside them, so nothing
in a draft renders. Link targets are repo paths, percent-encoded (a ``javascript:``
target cannot form). Commit SHAs that are not hex are shown as ``invalid``.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, replace
from urllib.parse import quote

from driftwarden.models import DependencyRef, Evidence, Provenance
from driftwarden.report.model import Report, rule_text
from driftwarden.report.view import (
    Finding,
    ReportView,
    Undocumented,
    Unverified,
    build_view,
    canonical_path,
    full_sha,
    short_sha,
)

PR_COMMENT_MARKER = "<!-- driftwarden-report -->"
GITHUB_COMMENT_LIMIT = 65_536
COMPACT_BUDGET = 60_000  # headroom under the limit for the Action's own lines
ZWJ = "\u200d"

# --------------------------------------------------------------------------- escaping

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>&|~$!#])")
_INVISIBLE = ("Cc", "Cf", "Zl", "Zp")
_AUTOLINK = (
    (re.compile(r"://"), ":" + ZWJ + "//"),
    (re.compile(r"(?i)\bwww(?=\.)"), "www" + ZWJ),
    (re.compile(r"#(?=[\w])"), "#" + ZWJ),
    (re.compile(r"(?i)\bGH-(?=\d)"), "GH-" + ZWJ),
)


def visible(text: str, keep: str = "") -> str:
    """Every Cc/Cf/Zl/Zp character not in ``keep`` as a visible ``\\uXXXX``; ``<!--``
    broken with a zero-width joiner so user text cannot forge an HTML comment / marker."""
    out = []
    for ch in text:
        if ch in keep:
            out.append(ch)
        elif unicodedata.category(ch) in _INVISIBLE:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out).replace("<!--", "<!" + ZWJ + "--")


def _clean(text: object, limit: int | None = None) -> str:
    s = str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = " ".join(visible(s).split())  # one line, runs of spaces -> one space
    if limit is not None and len(s) > limit:
        s = s[: max(1, limit - 1)].rstrip() + "…"
    return s


def esc(text: object, *, html_ctx: bool = False, limit: int | None = None) -> str:
    """The one escaping helper for user-controlled text (see the module docstring)."""
    s = _clean(text, limit)
    if html_ctx:
        s = html.escape(s, quote=True)
    else:
        for pattern, repl in _AUTOLINK:
            s = pattern.sub(repl, s)
        s = _MD_SPECIAL.sub(r"\\\1", s)
    return s.replace("@", "@" + ZWJ)


def code(text: object, *, limit: int | None = None) -> str:
    """An inline code span holding ``text`` literally (one line)."""
    s = _clean(text, limit)
    if not s:
        return "` `"
    run = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (run + 1)
    pad = " " if (s.startswith("`") or s.endswith("`") or run) else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def fenced(text: str, info: str = "") -> list[str]:
    """A fenced block holding ``text`` verbatim (longer fence than any inside)."""
    body = visible(text.replace("\r\n", "\n").replace("\r", "\n"), keep="\n\t")
    run = max((len(m) for m in re.findall(r"`{3,}", body)), default=2)
    fence = "`" * max(3, run + 1)
    return [f"{fence}{info}", *body.rstrip("\n").split("\n"), fence]


def _lines(a: int, b: int) -> str:
    return f"{a}" if a >= b else f"{a}-{b}"


def _anchor(a: int, b: int) -> str:
    return f"#L{a}" if a >= b else f"#L{a}-L{b}"


def adr_link(p: Provenance, link_base: str | None = None) -> str:
    """``[path#Lline](path#Lline) @ `sha``` for an ADR source line."""
    # The path is user text; the #Lline anchor is ours (escaped, no joiner needed).
    text = esc(p.path) + "\\" + _anchor(p.line_start, p.line_end)
    sha = code(short_sha(p.commit))
    if not canonical_path(p.path):
        return f"{text} @ {sha}"
    target = quote(p.path, safe="/-._~") + _anchor(p.line_start, p.line_end)
    if link_base and re.match(r"^https://[^\s()<>]+$", link_base):
        target = link_base.rstrip("/") + "/" + target
    return f"[{text}]({target}) @ {sha}"


def _loc(path: str, a: int, b: int, commit: str | None) -> str:
    sha = code(short_sha(commit)) if commit else "`?`"
    return f"{code(f'{path}:{_lines(a, b)}')} @ {sha}"


def _detail(ev: Evidence) -> str:
    head, _, rest = ev.detail.partition(" ")
    return rest if rest and head.startswith(f"{ev.ref.path}:") else ev.detail


# --------------------------------------------------------------------------- limits


@dataclass(frozen=True)
class _Limits:
    findings: int | None = None  # violated, drifting, could not verify
    holding: int | None = None
    unknown: int | None = None
    undocumented: int | None = None
    evidence: int | None = None
    reasons: int | None = None
    notes: int | None = None
    drafts: bool = True
    text: int | None = 1000
    snippet: int = 200


_FULL = _Limits()
_LADDER = (
    _Limits(holding=20, unknown=20, evidence=5, reasons=5, notes=10, text=400, snippet=160),
    _Limits(holding=20, unknown=20, evidence=5, reasons=5, notes=10, text=400, drafts=False),
    _Limits(
        holding=10,
        unknown=10,
        undocumented=20,
        evidence=3,
        reasons=3,
        notes=5,
        text=300,
        drafts=False,
        snippet=120,
    ),
    _Limits(
        findings=50,
        holding=5,
        unknown=5,
        undocumented=10,
        evidence=2,
        reasons=2,
        notes=0,
        text=200,
        drafts=False,
        snippet=100,
    ),
    _Limits(
        findings=10,
        holding=0,
        unknown=0,
        undocumented=3,
        evidence=1,
        reasons=1,
        notes=0,
        text=120,
        drafts=False,
        snippet=80,
    ),
    _Limits(
        findings=0,
        holding=0,
        unknown=0,
        undocumented=0,
        evidence=0,
        reasons=0,
        notes=0,
        text=80,
        drafts=False,
        snippet=60,
    ),
)


def _take(items: list, n: int | None) -> tuple[list, int]:
    if n is None or len(items) <= n:
        return items, 0
    return items[:n], len(items) - n


def _more(n: int) -> list[str]:
    return [f"- … and {n} more (see the full report)"] if n else []


# --------------------------------------------------------------------------- items


@dataclass(frozen=True)
class _Ctx:
    view: ReportView
    lim: _Limits
    link_base: str | None
    h: str  # heading prefix, "##" or "###"


def _evidence_lines(evs: tuple[Evidence, ...] | list[Evidence], ctx: _Ctx, indent: str) -> list:
    out: list[str] = []
    shown, more = _take(list(evs), ctx.lim.evidence)
    for ev in shown:
        r = ev.ref
        snippet = r.quote.strip().splitlines()[0] if r.quote.strip() else ""
        line = f"{indent}- {_loc(r.path, r.line_start, r.line_end, r.commit)}"
        detail = _detail(ev)
        if detail:
            line += f" {esc(detail, limit=ctx.lim.text)}"
        if snippet:
            line += f": {code(snippet, limit=ctx.lim.snippet)}"
        out.append(line)
    if more:
        out.append(f"{indent}- … and {more} more evidence item(s)")
    return out


def _title(f: Finding) -> str:
    return f.decision.title if f.decision is not None else f.claim.decision_id


def _change_tag(in_change: bool | None) -> str:
    """PR mode only: whether the change touches the claim (``ClaimResult.in_change``)."""
    if in_change is None:
        return ""
    return " · **in this change**" if in_change else " · present before this change"


def _in_change_first(items: list) -> list:
    """Stable: items the change touches first (PR mode); unchanged order otherwise."""
    return sorted(items, key=lambda x: 0 if x.in_change else 1)


def _finding(f: Finding, ctx: _Ctx) -> list[str]:
    c, v, t = f.claim, f.verdict, ctx.lim.text
    out = [
        f"- **{esc(c.id)}** ({esc(c.decision_id)}: {esc(_title(f), limit=t)})"
        + _change_tag(f.in_change),
        f"  - Rule: {code(rule_text(c), limit=t)}",
        f"  - ADR: {adr_link(c.source, ctx.link_base)}: {esc(c.source.quote, limit=t)}",
    ]
    if v.rationale:
        out.append(f"  - Why: {esc(v.rationale, limit=t)}")
    if v.status == "UNKNOWN":
        reasons, more = _take(list(v.reasons), ctx.lim.reasons)
        out.extend(f"  - Reason: {esc(r, limit=t)}" for r in reasons)
        if more:
            out.append(f"  - … and {more} more reason(s)")
    if f.evidence:
        out.append("  - Evidence:")
        out.extend(_evidence_lines(f.evidence, ctx, "    "))
    return out


def _cited(p: Provenance | DependencyRef | None) -> str | None:
    if isinstance(p, Provenance):
        return _loc(p.path, p.line_start, p.line_end, p.commit)
    if isinstance(p, DependencyRef):
        line = f":{p.line}" if p.line else ""
        return f"{code(p.manifest_path + line)} @ {code(short_sha(p.commit))} " + esc(
            f"declares {p.package} {p.version_spec or ''}".strip()
        )
    return None


def _unverified(u: Unverified, ctx: _Ctx) -> list[str]:
    t = ctx.lim.text
    head = f"- **{esc(u.kind)} {esc(u.id, limit=t)}**"
    if u.check_id:
        head += f" \\[{esc(u.check_id)}\\]"
    if u.proposed_status:
        head += f" (proposed {esc(u.proposed_status)}, not shown as a finding)"
    out = [head + _change_tag(u.in_change)]
    if u.anchor is not None:
        out.append(f"  - ADR: {adr_link(u.anchor, ctx.link_base)}")
    cited = _cited(u.provenance)
    if cited and not (isinstance(u.provenance, Provenance) and u.provenance == u.anchor):
        out.append(f"  - Cited (not verified): {cited}")
    reasons, more = _take(list(u.reasons), ctx.lim.reasons)
    out.extend(f"  - Reason: {esc(r, limit=t)}" for r in reasons)
    if more:
        out.append(f"  - … and {more} more reason(s)")
    if u.report_check:
        out.append("  - Found by the report-time evidence re-check (see README).")
    return out


def _undocumented(u: Undocumented, ctx: _Ctx) -> list[str]:
    rec, t = u.record, ctx.lim.text
    first = short_sha(rec.introducing_commits[0]) if rec.introducing_commits else "?"
    out = [
        f"**{esc(rec.id)}**: {esc(rec.title or rec.technology, limit=t)} "
        f"(category {esc(rec.category)}, introduced {code(first)})",
        "",
        *_evidence_lines(u.evidence, ctx, ""),
        "",
    ]
    d = u.draft
    if d is not None and d.markdown and ctx.lim.drafts:
        where = f": suggested path {d.path}" if d.path else ""
        out += [
            "<details>",
            f"<summary>Draft ADR for {esc(rec.id, html_ctx=True)}"
            f"{esc(where, html_ctx=True)} (shown only, not written)</summary>",
            "",
            *fenced(d.markdown, "markdown"),
            "",
            "</details>",
            "",
        ]
    return out


# --------------------------------------------------------------------------- sections


def _pct(x: float | None) -> str:
    return f"{x:.1%}" if x is not None else "n/a"


def _header(ctx: _Ctx, title: str) -> list[str]:
    m = ctx.view.report.metadata
    rows = [
        ("Repository", esc(m.repo, limit=200)),
        ("Commit", code(full_sha(m.commit))),
        (
            "Mode",
            esc(m.mode) + (f" ({esc(m.provider)} {esc(m.model or '')})" if m.provider else ""),
        ),
        ("Scanned at", esc(m.scanned_at)),
        ("Drift score", _pct(ctx.view.report.summary.drift_score)),
        ("Exit code", str(ctx.view.report.summary.exit_code)),
    ]
    if m.changed_paths is not None:
        rows.append(("PR mode", f"{len(m.changed_paths)} changed path(s)"))
    out = [f"# {title}", "", "| | |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in rows]
    return out + [""]


def _summary(ctx: _Ctx) -> list[str]:
    v, s = ctx.view, ctx.view.report.summary
    cols = [
        ("Violated", len(v.violated)),
        ("Drifting", len(v.drifting)),
        ("Holding", len(v.holding)),
        ("Unknown", len(v.unknown)),
        ("Could not verify", len(v.could_not_verify)),
        ("Undocumented", len(v.undocumented)),
        ("Drafts", sum(1 for u in v.undocumented if u.draft is not None)),
    ]
    out = [
        f"{ctx.h} Summary",
        "",
        "| " + " | ".join(c for c, _ in cols) + " |",
        "|" + "---:|" * len(cols),
        "| " + " | ".join(str(n) for _, n in cols) + " |",
        "",
        f"{s.decisions} decision(s), {s.decisions_judged} judged; {s.claims} claim(s), "
        f"{s.claims_judged} judged"
        + (f", {len(v.not_judged)} not judged" if v.not_judged else "")
        + ". The drift score is the share of decided claims (holding, drifting, violated) "
        "that are not holding.",
        "",
    ]
    if v.pr_mode:
        touched = [f for f in v.violated + v.drifting if f.in_change]
        out += [
            f"PR mode: {sum(1 for f in touched if f.status == 'VIOLATED')} violated and "
            f"{sum(1 for f in touched if f.status == 'DRIFTING')} drifting claim(s) are in this "
            "change; the rest were already present before it.",
            "",
        ]
    if v.demoted:
        out += [
            f"{v.demoted} finding(s) failed the report-time evidence re-check and are listed "
            "under Could not verify.",
            "",
        ]
    return out


def _findings_section(name: str, items: list[Finding], ctx: _Ctx, n: int | None) -> list[str]:
    out = [f"{ctx.h} {name} ({len(items)})", ""]
    if not items:
        return out + ["None.", ""]
    shown, more = _take(items, n)
    for f in shown:
        out += _finding(f, ctx)
    return out + _more(more) + [""]


def _collapsed_section(name: str, items: list[Finding], ctx: _Ctx, n: int | None) -> list[str]:
    out = [f"{ctx.h} {name} ({len(items)})", ""]
    if not items:
        return out + ["None.", ""]
    shown, more = _take(items, n)
    out += ["<details>", f"<summary>Show {len(items)} {name.lower()} claim(s)</summary>", ""]
    for f in shown:
        out += _finding(f, ctx)
    return out + _more(more) + ["", "</details>", ""]


def _cnv_section(ctx: _Ctx) -> list[str]:
    items = ctx.view.could_not_verify
    out = [f"{ctx.h} Could not verify ({len(items)})", ""]
    if not items:
        return out + ["None: every finding above passed its verifier.", ""]
    out += [
        "These items failed a deterministic verifier. They are not findings and are never "
        "shown as violations.",
        "",
    ]
    shown, more = _take(_in_change_first(items), ctx.lim.findings)
    for u in shown:
        out += _unverified(u, ctx)
    return out + _more(more) + [""]


def _undocumented_section(ctx: _Ctx) -> list[str]:
    items = ctx.view.undocumented
    out = [f"{ctx.h} Undocumented decisions ({len(items)})", ""]
    if not items:
        return out + ["None.", ""]
    out += ["Technology choices in the code that no ADR covers.", ""]
    shown, more = _take(items, ctx.lim.undocumented)
    for u in shown:
        out += _undocumented(u, ctx)
    if not ctx.lim.drafts and any(u.draft for u in items):
        out += ["Draft ADRs are left out of this compact view; see the full report.", ""]
    return out + _more(more) + ([""] if more else [])


def _grounding_section(ctx: _Ctx) -> list[str]:
    gs = ctx.view.report.grounding_summary
    out = [
        f"{ctx.h} Grounding summary",
        "",
        "| Check | Total | Verified | Pass rate |",
        "|---|---:|---:|---:|",
    ]
    for cid, cs in gs.by_check.items():
        out.append(f"| {esc(cid)} | {cs.total} | {cs.verified} | {_pct(cs.pass_rate)} |")
    out.append(f"| **All** | {gs.total} | {gs.verified} | {_pct(gs.pass_rate)} |")
    return out + [""]


def _timeline_section(ctx: _Ctx) -> list[str]:
    tl = ctx.view.report.timeline
    if not tl:
        return []
    out = [
        f"{ctx.h} Drift timeline",
        "",
        "| Claim | First violating commit | Parent | Date | Subject | Grounding |",
        "|---|---|---|---|---|---|",
    ]
    shown, more = _take(list(tl), ctx.lim.findings)
    for e in shown:
        ok = e.grounding == "VERIFIED" and e.first_violating_commit
        first = code(short_sha(e.first_violating_commit)) if ok else "first seen: unknown"
        parent = code(short_sha(e.parent)) if ok and e.parent else ""
        out.append(
            f"| {esc(e.claim_id)} | {first} | {parent} | {esc(e.date or '') if ok else ''} | "
            f"{esc(e.subject or '', limit=ctx.lim.text) if ok else ''} | "
            f"{esc(e.grounding or 'n/a')} |"
        )
    if more:
        out.append(f"| … and {more} more | | | | | |")
    return out + [""]


def _notes_section(ctx: _Ctx) -> list[str]:
    notes = ctx.view.report.notes
    if not notes or ctx.lim.notes == 0:
        return []
    shown, more = _take(list(notes), ctx.lim.notes)
    out = [f"{ctx.h} Notes ({len(notes)})", "", "<details>", "<summary>Scan notes</summary>", ""]
    out += [f"- {esc(n, limit=ctx.lim.text)}" for n in shown]
    return out + _more(more) + ["", "</details>", ""]


def _footer(report: Report) -> list[str]:
    return [
        "---",
        "",
        f"Generated by DriftWarden {esc(report.metadata.tool_version)}. Only findings whose "
        "evidence passed a deterministic verifier are shown as facts; everything else is "
        "under Could not verify.",
        "",
    ]


def _full(view: ReportView, lim: _Limits, link_base: str | None) -> str:
    ctx = _Ctx(view=view, lim=lim, link_base=link_base, h="##")
    out = _header(ctx, f"DriftWarden report: {esc(view.report.metadata.repo, limit=200)}")
    out += _summary(ctx)
    out += _findings_section("Violated", _in_change_first(view.violated), ctx, lim.findings)
    out += _findings_section("Drifting", _in_change_first(view.drifting), ctx, lim.findings)
    out += _cnv_section(ctx)
    out += _undocumented_section(ctx)
    out += _collapsed_section("Holding", view.holding, ctx, lim.holding)
    out += _findings_section("Unknown", view.unknown, ctx, lim.unknown)
    out += _grounding_section(ctx)
    out += _timeline_section(ctx)
    out += _notes_section(ctx)
    out += _footer(view.report)
    return "\n".join(out).rstrip("\n") + "\n"


def _comment(view: ReportView, lim: _Limits, link_base: str | None) -> str:
    lim = replace(lim, drafts=False)  # drafts belong in the full report, not a comment
    ctx = _Ctx(view=view, lim=lim, link_base=link_base, h="###")
    m = view.report.metadata
    head = (
        f"## DriftWarden: {len(view.violated)} violated, "
        f"{len(view.could_not_verify)} could not verify, {len(view.drifting)} drifting"
    )
    out = [
        PR_COMMENT_MARKER,
        head,
        "",
        f"**{esc(m.repo, limit=200)}** @ {code(short_sha(m.commit))} · mode {esc(m.mode)} · "
        f"drift score {_pct(view.report.summary.drift_score)} · "
        f"exit code {view.report.summary.exit_code}",
        "",
    ]
    if view.pr_mode:
        mine = [f for f in view.violated if f.in_change]
        before = [f for f in view.violated if not f.in_change]
        out += _findings_section("Violated in this change", mine, ctx, lim.findings)
        out += _findings_section("Already present before this change", before, ctx, lim.findings)
    else:
        out += _findings_section("Violated", view.violated, ctx, lim.findings)
    out += _cnv_section(ctx)
    out += _findings_section("Drifting", _in_change_first(view.drifting), ctx, lim.findings)
    out += _undocumented_section(ctx)
    out += _collapsed_section("Holding", view.holding, ctx, lim.holding)
    out += _findings_section("Unknown", view.unknown, ctx, lim.unknown)
    out += _grounding_section(ctx)
    out += _timeline_section(ctx)
    out += _notes_section(ctx)
    out += _footer(view.report)
    return "\n".join(out).rstrip("\n") + "\n"


def _fit(render, view: ReportView, link_base: str | None, budget: int) -> str:
    text = ""
    for lim in _LADDER:
        text = render(view, lim, link_base)
        if len(text) <= budget:
            return text
    # Last resort (pathological sizes): cut on a line boundary and say so.
    note = "\n\n_Report truncated to fit the GitHub comment limit; see the full report._\n"
    cut = text[: budget - len(note)]
    cut = cut[: cut.rfind("\n")] if "\n" in cut else cut
    return cut + note


def render_markdown(report: Report, *, compact: bool = False, link_base: str | None = None) -> str:
    """The Markdown report. ``compact=True`` keeps it within ``COMPACT_BUDGET`` characters.

    ``link_base`` (an ``https://`` URL such as ``https://github.com/o/r/blob/<sha>``)
    makes ADR links absolute; by default they are repo-relative ``path#Lline``.
    """
    view = build_view(report)
    if not compact:
        return _full(view, _FULL, link_base)
    return _fit(_full, view, link_base, COMPACT_BUDGET)


def render_pr_comment(report: Report, *, link_base: str | None = None) -> str:
    """Compact PR comment (for L-014): violations and could-not-verify first, with the
    hidden marker ``<!-- driftwarden-report -->`` so the Action can find and update it."""
    return _fit(_comment, build_view(report), link_base, COMPACT_BUDGET)


__all__ = [
    "COMPACT_BUDGET",
    "GITHUB_COMMENT_LIMIT",
    "PR_COMMENT_MARKER",
    "adr_link",
    "code",
    "esc",
    "fenced",
    "render_markdown",
    "render_pr_comment",
]
