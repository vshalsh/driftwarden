"""L-013: the self-contained HTML report (``driftwarden.report.html.render_html``)."""

from __future__ import annotations

import html as html_lib
import os
import re
import shutil
import time
from html.parser import HTMLParser
from importlib import resources
from pathlib import Path

import pytest

from conftest import git
from driftwarden.models import (
    Claim,
    Consistency,
    DependencyRef,
    Evidence,
    GroundingResult,
    Introduction,
    Provenance,
    RunVote,
    UndocumentedDecision,
    Verdict,
)
from driftwarden.report.html import CSP, PROJECT_URL, render_html
from driftwarden.report.model import (
    CheckSummary,
    ClaimResult,
    DecisionResult,
    GroundingSummary,
    Metadata,
    Report,
    Summary,
    TimelineEntry,
    UnverifiedItem,
)
from driftwarden.undocumented.draft import DraftADR

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = Path(__file__).parent / "artifacts"
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"

HOSTILE = (
    '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    " javascript:alert(3) ‮gnp.exe⁦x⁩ {{ 7*7 }} </pre></details>"
)


# ------------------------------------------------------------------ builders


def prov(path="src/app.py", line=3, quote="import pymongo", commit=SHA, end=None) -> Provenance:
    return Provenance(path=path, line_start=line, line_end=end or line, commit=commit, quote=quote)


def ok(check, subject, p=None) -> GroundingResult:
    return GroundingResult(
        check_id=check, status="VERIFIED", reason="found", provenance=p, subject=subject
    )


def evidence(i=1, path="src/app.py", quote="import pymongo", line=3) -> Evidence:
    return Evidence(
        id=f"e{i}",
        kind="import",
        ref=prov(path, line, quote),
        relation="alternative",
        technology="mongodb",
        detail=f"{path}:{line} imports pymongo",
    )


def decision(did="ADR-0001", title="PostgreSQL is the only datastore", src=None):
    src = src or prov("docs/adr/0001-pg.md", 13, "PostgreSQL is the only datastore.")
    return DecisionResult(
        id=did,
        title=title,
        status="accepted",
        format="nygard",
        source=src,
        g1=ok("G1", did, src),
        judged=True,
        claim_ids=[f"{did}.c1"],
    )


def claim(cid="ADR-0001.c1", did="ADR-0001", src=None, subject="datastore") -> Claim:
    src = src or prov("docs/adr/0001-pg.md", 13, "PostgreSQL is the only datastore.")
    return Claim(
        id=cid,
        kind="only",
        subject=subject,
        rule={"only": ["PostgreSQL"], "category": "datastore"},
        source=src,
        decision_id=did,
    )


def claim_result(status, cid="ADR-0001.c1", did="ADR-0001", n_ev=2, text="import pymongo"):
    c = claim(cid, did)
    ev = [evidence(i + 1, f"src/mod{i}.py", text) for i in range(n_ev)] if n_ev else []
    v = Verdict(
        claim_id=cid,
        status=status,
        evidence=ev,
        rationale=f"rationale for {cid}",
        commit=SHA,
        checks=[ok("G2", f"{cid}/{e.id}", e.ref) for e in ev],
    )
    return ClaimResult(claim=c, judged=True, verdict=v)


def cnv_claim_result(cid="ADR-0002.c1", did="ADR-0002"):
    c = claim(cid, did)
    v = Verdict(
        claim_id=cid,
        status="UNKNOWN",
        grounding="MISMATCH",
        reasons=["src/x.py:9-9@0123456789ab: quote not found in range"],
        proposed_status="VIOLATED",
        evidence=[evidence(1, "src/x.py", "import redis", 9)],
        commit=SHA,
    )
    return ClaimResult(claim=c, judged=True, verdict=v)


def undocumented(uid="UD-queue-kafka", tech="kafka", text="from kafka import Producer"):
    ev = [evidence(1, "src/events.py", text, 1)]
    return UndocumentedDecision(
        id=uid,
        technology=tech,
        category="queue",
        title=f"Use {tech} as queue",
        commit=SHA,
        evidence=ev,
        introductions=[
            Introduction(evidence_id="e1", commit=SHA2, ref=prov("src/events.py", 1, text, SHA2))
        ],
        introducing_commits=[SHA2],
        searched_terms=[tech, "queue"],
        checks=[ok("G2", f"{uid}/e1", ev[0].ref), ok("G5", f"{uid}@{SHA2}")],
    )


def draft(rec: UndocumentedDecision, markdown="# Use kafka\n\nTODO: why\n") -> DraftADR:
    return DraftADR(
        record_id=rec.id,
        technology=rec.technology,
        category=rec.category,
        title=rec.title,
        markdown=markdown,
        number=8,
        path="docs/adr/0008-use-kafka.md",
        record=rec,
        cited_commits=[SHA2],
        evidence_refs=[e.ref for e in rec.evidence],
        checks=[ok("G5", f"draft:{rec.id}")],
    )


def metadata(**kw) -> Metadata:
    base = dict(
        tool_version="0.0.1",
        repo="shop",
        commit=SHA,
        scanned_at="2026-10-29T10:00:00Z",
        mode="offline",
        requested_mode="offline",
    )
    base.update(kw)
    return Metadata(**base)


def gsummary(total=20, mismatch=1) -> GroundingSummary:
    by = {
        cid: CheckSummary(total=0, verified=0, mismatch=0, pass_rate=None)
        for cid in ("G1", "G2", "G3", "G4", "G5", "G6")
    }
    by["G1"] = CheckSummary(total=5, verified=5, mismatch=0, pass_rate=1.0)
    by["G2"] = CheckSummary(
        total=total - 5,
        verified=total - 5 - mismatch,
        mismatch=mismatch,
        pass_rate=(total - 5 - mismatch) / (total - 5),
    )
    return GroundingSummary(
        total=total,
        verified=total - mismatch,
        mismatch=mismatch,
        pass_rate=(total - mismatch) / total,
        by_check=by,
    )


def full_report(text="import pymongo", title="PostgreSQL is the only datastore") -> Report:
    """Every section populated."""
    decisions = [decision("ADR-0001", title), decision("ADR-0002", "Redis for caching")]
    violated = claim_result("VIOLATED", "ADR-0001.c1", "ADR-0001", text=text)
    drifting = claim_result("DRIFTING", "ADR-0001.c2", "ADR-0001", n_ev=1, text=text)
    holding = claim_result("HOLDING", "ADR-0001.c3", "ADR-0001", n_ev=1)
    unknown = claim_result("UNKNOWN", "ADR-0001.c4", "ADR-0001", n_ev=0)
    broken = cnv_claim_result()
    vote = Verdict(
        claim_id="ADR-0001.c5",
        status="VIOLATED",
        evidence=[evidence(1)],
        checks=[ok("G2", "ADR-0001.c5/e1", evidence(1).ref)],
        commit=SHA,
        origin="llm",
        consistency=Consistency(
            runs=3,
            executed=3,
            basis="vote",
            agreement=True,
            votes=[
                RunVote(run=i, status="VIOLATED", grounding="VERIFIED", origin="llm")
                for i in (1, 2, 3)
            ],
        ),
    )
    voted = ClaimResult(claim=claim("ADR-0001.c5"), judged=True, verdict=vote)
    not_judged = ClaimResult(
        claim=claim("ADR-0001.c6"),
        judged=False,
        not_judged_reason="not touched by the changed paths (PR mode)",
    )
    rec = undocumented(text=text)
    cnv = [
        UnverifiedItem(
            kind="verdict",
            id="ADR-0002.c1",
            reasons=list(broken.verdict.reasons),
            decision_id="ADR-0002",
            claim_id="ADR-0002.c1",
            provenance=broken.claim.source,
            proposed_status="VIOLATED",
        ),
        UnverifiedItem(
            kind="evidence",
            id="ADR-0002.c1/e1",
            check_id="G2",
            reasons=["src/x.py:9-9@0123456789ab: quote not found in range"],
            decision_id="ADR-0002",
            claim_id="ADR-0002.c1",
            provenance=prov("src/x.py", 9, "import redis"),
        ),
        UnverifiedItem(
            kind="check",
            id="deps",
            check_id="G3",
            reasons=["manifest does not declare redis"],
            provenance=DependencyRef(
                package="redis", manifest_path="requirements.txt", line=4, commit=SHA
            ),
        ),
    ]
    return Report(
        metadata=metadata(),
        decisions=decisions,
        claims=[violated, voted, drifting, holding, unknown, broken, not_judged],
        could_not_verify=cnv,
        undocumented=[rec],
        drafts=[draft(rec)],
        timeline=[
            TimelineEntry(
                claim_id="ADR-0001.c1",
                first_violating_commit=SHA2,
                parent=SHA,
                date="2026-10-01",
                subject="add mongo cache",
                grounding="VERIFIED",
            ),
            TimelineEntry(claim_id="ADR-0001.c2", grounding="MISMATCH"),
        ],
        grounding_summary=gsummary(),
        summary=Summary(
            decisions=2,
            decisions_judged=2,
            claims=7,
            claims_judged=6,
            by_status={"HOLDING": 1, "DRIFTING": 1, "VIOLATED": 2, "UNKNOWN": 2},
            unknown=2,
            could_not_verify=3,
            undocumented=1,
            drafts=1,
            drift_score=0.75,
            exit_code=1,
        ),
        notes=["skipped ADR docs/adr/empty.md: empty file"],
    )


def hostile_report() -> Report:
    """Every user-controlled string carries markup, a javascript: URL and bidi controls."""
    H = HOSTILE
    src = prov(f"docs/adr/{H}.md", 2, H)
    rec = undocumented(text=H)
    rec = rec.model_copy(update={"title": H, "searched_terms": [H], "technology": H})
    c = Claim(
        id=f"ADR-1.{H}",
        kind="forbid",
        subject=H,
        rule={"forbid": [H]},
        source=src,
        decision_id="ADR-1",
    )
    ev = Evidence(id="e1", kind="code", ref=prov(f"src/{H}.py", 1, H), detail=H, technology=H)
    v = Verdict(
        claim_id=c.id,
        status="VIOLATED",
        evidence=[ev],
        rationale=H,
        notes=[H],
        commit=SHA,
        checks=[ok("G2", f"{c.id}/e1", ev.ref)],
    )
    dec = decision("ADR-1", H, src)
    return Report(
        metadata=metadata(repo=H, scanned_at=H, model=H, provider=H, mode="llm", requested_mode=H),
        decisions=[dec],
        claims=[
            ClaimResult(claim=c, judged=True, verdict=v),
            ClaimResult(claim=c.model_copy(update={"id": "x2"}), judged=False, not_judged_reason=H),
        ],
        could_not_verify=[
            UnverifiedItem(kind="check", id=H, check_id=H, reasons=[H], provenance=prov(H, 1, H))
        ],
        undocumented=[rec],
        drafts=[draft(rec, markdown=H)],
        timeline=[
            TimelineEntry(
                claim_id=c.id, first_violating_commit=SHA2, date=H, subject=H, grounding="VERIFIED"
            )
        ],
        notes=[H],
    )


def huge_report(n=1000) -> Report:
    claims, cnv = [], []
    for i in range(n):
        status = ("VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN", "CNV")[i % 5]
        cid = f"ADR-{i:04d}.c1"
        if status == "CNV":
            cr = cnv_claim_result(cid, f"ADR-{i:04d}")
            cnv.append(
                UnverifiedItem(
                    kind="verdict",
                    id=cid,
                    reasons=list(cr.verdict.reasons),
                    decision_id=f"ADR-{i:04d}",
                    claim_id=cid,
                    provenance=cr.claim.source,
                )
            )
        else:
            cr = claim_result(status, cid, f"ADR-{i:04d}", n_ev=0 if status == "UNKNOWN" else 3)
        claims.append(cr)
    decisions = [decision(f"ADR-{i:04d}", f"Decision number {i}") for i in range(n)]
    recs = [undocumented(f"UD-{i}", f"tech{i}") for i in range(50)]
    return Report(
        metadata=metadata(),
        decisions=decisions,
        claims=claims,
        could_not_verify=cnv,
        undocumented=recs,
        drafts=[draft(r) for r in recs],
        grounding_summary=gsummary(5000, 3),
    )


# ------------------------------------------------------------------ parsing helpers


class Doc(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self.scripts: list[str] = []
        self.headings: list[int] = []
        self._in_script = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self._in_script = True
            self.scripts.append("")
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts[-1] += data


def section(html: str, sid: str) -> str:
    start = html.index(f'<section id="{sid}"')
    end = html.index("</section>", start)
    return html[start:end]


def asset(name: str) -> str:
    return resources.files("driftwarden.report.html").joinpath(name).read_text(encoding="utf-8")


# ------------------------------------------------------------------ rendering


def test_all_sections_render_in_order():
    html = render_html(full_report())
    ids = [
        "violated",
        "drifting",
        "could-not-verify",
        "undocumented",
        "holding",
        "unknown",
        "not-judged",
        "timeline",
        "grounding",
        "notes",
    ]
    positions = [html.index(f'<section id="{i}"') for i in ids]
    assert positions == sorted(positions)
    assert html.startswith("<!doctype html>")
    assert "<main" in html and "<header" in html and "<footer" in html and "<nav" in html


def test_header_and_summary_strip():
    html = render_html(full_report())
    assert "<h1" in html and ">shop</h1>" in html
    assert SHA[:7] in html and "2026-10-29T10:00:00Z" in html and "driftwarden 0.0.1" in html
    assert "offline" in html
    assert re.search(r"<abbr title=\"[^\"]*holding \+ drifting \+ violated", html)
    assert "75%" in html
    for label in ("Violated", "Drifting", "Could not verify", "Undocumented", "Holding", "Unknown"):
        assert f"<span>{label}</span>" in html


def test_violated_card_content():
    html = render_html(full_report())
    v = section(html, "violated")
    assert "ADR-0001" in v and "PostgreSQL is the only datastore" in v
    assert f"docs/adr/0001-pg.md:L13-L13@{SHA[:7]}" in v
    assert "only(datastore) = [PostgreSQL]" in v
    assert f"src/mod0.py:L3@{SHA[:7]}" in v
    assert '<pre class="dw-snippet" dir="ltr"><code>import pymongo</code></pre>' in v
    since = f'first violated at commit <code class="dw-mono" title="{SHA2}">{SHA2[:7]}</code>'
    assert since in v
    assert "add mongo cache" in v
    assert "Verified" in v and "G1&nbsp;1/1" in v and "G2&nbsp;2/2" in v
    assert "G6 3/3 agree" in v  # the voted verdict
    assert v.count('class="dw-card dw-card--violated') == 2
    d = section(html, "drifting")
    assert d.count('class="dw-card dw-card--drifting') == 1
    assert "first seen: unknown" in d  # G4 MISMATCH timeline entry


def test_unverified_is_violet_and_never_a_violation():
    html = render_html(full_report())
    v = section(html, "violated")
    assert "ADR-0002.c1" not in v
    c = section(html, "could-not-verify")
    assert c.count("dw-card--unverified") == 3
    assert "dw-badge--violated" not in c and "dw-card--violated" not in c
    assert "dw-badge--unverified" in c and "#dw-i-unverified" in c
    assert "quote not found in range" in c and "manifest does not declare redis" in c
    assert "requirements.txt:L4@" in c
    assert "Violated (not shown as a finding" in c
    assert "They are not violations" in c


def test_could_not_verify_always_visible_with_empty_state():
    r = full_report()
    claims = [c for c in r.claims if c.id != "ADR-0002.c1"]  # the MISMATCH verdict
    r = r.model_copy(update={"could_not_verify": [], "claims": claims})
    c = section(render_html(r), "could-not-verify")
    assert "Nothing here" in c and "<details" not in c


def test_undocumented_with_draft_and_copy_button():
    u = section(render_html(full_report()), "undocumented")
    assert "UD-queue-kafka" in u and SHA2[:7] in u and f'title="{SHA2}"' in u
    assert '<details class="dw-draft">' in u and "docs/adr/0008-use-kafka.md" in u
    m = re.search(r'data-dw-copy="(draft-\d+)" hidden', u)
    assert m and f'id="{m.group(1)}"' in u
    assert "# Use kafka" in u


def test_holding_unknown_are_collapsible():
    html = render_html(full_report())
    for sid in ("holding", "unknown", "not-judged"):
        s = section(html, sid)
        assert '<details class="dw-fold">' in s and "<summary>" in s
    assert "ADR-0001.c3" in section(html, "holding")
    assert "ADR-0001.c4" in section(html, "unknown")
    assert "not touched by the changed paths" in section(html, "not-judged")


def test_grounding_table_and_footer():
    html = render_html(full_report())
    g = section(html, "grounding")
    assert g.count('<th scope="col"') == 6 and g.count('<th scope="row"') == 7
    assert "not run" in g and "93.3%" in g
    assert "re-checked against the repository by a deterministic verifier (G1–G6)" in html
    assert f'<a href="{PROJECT_URL}"' in html


def test_heading_levels_never_skip():
    doc = Doc(render_html(full_report()))
    assert doc.headings[0] == 1 and doc.headings.count(1) == 1
    for a, b in zip(doc.headings, doc.headings[1:], strict=False):
        assert b <= a + 1


def test_tables_use_th_scope():
    doc = Doc(render_html(full_report()))
    ths = [a for t, a in doc.tags if t == "th"]
    assert ths and all(a.get("scope") in ("col", "row") for a in ths)


def test_empty_report():
    html = render_html(Report(metadata=metadata(commit="WORKTREE")))
    assert "n/a" in html and "No claim was decided" in html
    assert "Nothing here" in html and "No ADR constraint is violated" in html
    assert "worktree" in html
    assert '<section id="timeline"' not in html and '<section id="not-judged"' not in html


def test_pipeline_report_renders(tmp_path):
    from driftwarden.config import Config
    from driftwarden.grounding.ledger import Ledger
    from driftwarden.pipeline import run_scan

    repo = tmp_path / "pyshop"
    shutil.copytree(Path(__file__).parent / "fixtures" / "judge_repos" / "pyshop", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")
    ledger = Ledger(tmp_path / "lg")
    r = run_scan(repo, config=Config(), mode="offline", ledger=ledger, draft_adrs=True)
    html = render_html(r)
    assert "ADR-0001" in section(html, "violated")
    assert "UD-queue-kafka" in section(html, "undocumented")
    assert html.count('<details class="dw-draft">') == len(r.drafts)


# ------------------------------------------------------------------ security


ALLOWED_TAGS = {
    "html",
    "head",
    "meta",
    "title",
    "script",
    "style",
    "body",
    "svg",
    "symbol",
    "circle",
    "path",
    "use",
    "a",
    "header",
    "div",
    "p",
    "button",
    "h1",
    "h2",
    "h3",
    "h4",
    "dl",
    "dt",
    "dd",
    "code",
    "time",
    "nav",
    "abbr",
    "strong",
    "span",
    "ul",
    "li",
    "main",
    "label",
    "input",
    "section",
    "article",
    "q",
    "ol",
    "pre",
    "details",
    "summary",
    "table",
    "caption",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "footer",
}


def test_injection_is_inert():
    html = render_html(hostile_report())
    doc = Doc(html)
    tags = {t for t, _ in doc.tags}
    assert tags <= ALLOWED_TAGS, tags - ALLOWED_TAGS
    assert "img" not in tags
    ours = [asset("head.js").strip(), asset("report.js").strip()]
    assert [s.strip() for s in doc.scripts] == ours
    for _tag, attrs in doc.tags:
        for name, value in attrs.items():
            assert not name.startswith("on"), name
            if name == "href":  # in-page, the project, or a percent-encoded ADR path
                assert (
                    value.startswith("#")
                    or value == PROJECT_URL
                    or re.fullmatch(r"[A-Za-z0-9._~/%-]+#L\d+(-L\d+)?", value)
                ), value
            assert name != "src"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert" not in html and "<img" not in html
    assert "{{ 7*7 }}" in html


def test_bidi_controls_are_made_visible():
    html = render_html(hostile_report())
    for ch in ("‮", "⁦", "⁩"):
        assert ch not in html
    assert "[U+202E]gnp.exe[U+2066]x[U+2069]" in html


def test_csp_meta_is_first_in_head():
    html = render_html(full_report())
    head = html[html.index("<head>") : html.index("</head>")]
    first = [html_lib.unescape(m) for m in re.findall(r"<meta[^>]*>", head)[:2]]
    assert 'charset="utf-8"' in first[0]
    assert f'http-equiv="Content-Security-Policy" content="{CSP}"' in first[1]
    assert CSP == (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"
    )


def test_no_safe_filter_in_template():
    tpl = asset("report.html.j2")
    assert "|safe" not in tpl.replace(" ", "") and "Markup" not in tpl
    assert not re.search(r"\son[a-z]+\s*=", tpl)


@pytest.mark.parametrize("make", [full_report, huge_report, lambda: Report(metadata=metadata())])
def test_no_external_urls(make):
    html = render_html(make())
    assert not re.search(r"""src\s*=\s*["']?\s*https?:""", html, re.I)
    assert "@import" not in html
    assert not re.search(r"url\(\s*['\"]?\s*https?:", html, re.I)
    assert "@font-face" not in html
    assert set(re.findall(r"https?://[^\s\"'<>]+", html)) <= {PROJECT_URL}


# ------------------------------------------------------------------ design tokens


def test_tokens_copy_matches_design_tokens():
    vendored = resources.files("driftwarden.report.html").joinpath("tokens.css").read_bytes()
    assert vendored == (ROOT / "design" / "tokens.css").read_bytes()


def test_tokens_inlined_verbatim():
    assert asset("tokens.css") in render_html(full_report())


def test_component_css_adds_no_colours():
    css = asset("report.css")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css)
    assert not re.search(r"\b(rgb|rgba|hsl|hsla|hwb|lab|lch|oklch|color-mix)\(", css)
    named = r"(?<![-\w])(white|black|red|green|blue|gray|grey|purple|violet|orange|yellow)(?![-\w])"
    assert not re.search(named, re.sub(r"/\*.*?\*/", "", css, flags=re.S))
    tokens = set(re.findall(r"--dw-[a-z0-9-]+", asset("tokens.css")))
    used = set(re.findall(r"var\((--dw-[a-z0-9-]+)\)", css))
    assert used <= tokens, used - tokens


def test_every_hex_in_output_comes_from_tokens():
    html = render_html(full_report())
    style = html[html.index("<style>") : html.index("</style>")]
    allowed = {h.lower() for h in re.findall(r"#[0-9a-fA-F]{6}\b", asset("tokens.css"))}
    assert {h.lower() for h in re.findall(r"#[0-9a-fA-F]{6}\b", style)} <= allowed


def test_reduced_motion_print_and_dark_supported():
    css = asset("report.css")
    assert "prefers-reduced-motion: reduce" in css and "@media print" in css
    assert "details::details-content" in css
    t = asset("tokens.css")
    assert "prefers-color-scheme: dark" in t and '[data-theme="dark"]' in t


# ------------------------------------------------------------------ determinism & size


def test_deterministic_output():
    r = full_report()
    a = render_html(r)
    assert a == render_html(r)
    assert a == render_html(Report.model_validate_json(r.model_dump_json()))


def test_huge_report_size_and_speed():
    r = huge_report(1000)
    t0 = time.perf_counter()
    html = render_html(r)
    elapsed = time.perf_counter() - t0
    assert len(html.encode("utf-8")) < 5 * 1024 * 1024
    assert elapsed < 2.0, elapsed
    assert html.count("dw-card--violated dw-filterable") == 200
    assert section(html, "could-not-verify").count("dw-card--unverified") == 200


# ------------------------------------------------------------------ browser


def _chromium():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, None
    exe = None
    for cand in (os.environ.get("DW_CHROMIUM"), "/opt/pw-browsers/chromium"):
        if cand and Path(cand).exists():
            exe = cand
            break
    return sync_playwright, exe


@pytest.fixture(scope="module")
def browser():
    sync_playwright, exe = _chromium()
    if sync_playwright is None:
        pytest.skip("playwright not installed")
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    pw = sync_playwright().start()
    try:
        args = ["--disable-background-networking", "--no-first-run", "--disable-sync"]
        b = pw.chromium.launch(executable_path=exe, args=args)
    except Exception as e:  # no browser binary
        pw.stop()
        pytest.skip(f"chromium not available: {e}")
    yield b
    b.close()
    pw.stop()


@pytest.fixture(scope="module")
def report_file(tmp_path_factory):
    r = full_report()
    hostile = hostile_report()
    r = r.model_copy(
        update={
            "undocumented": r.undocumented + hostile.undocumented,
            "could_not_verify": r.could_not_verify + hostile.could_not_verify,
        }
    )
    path = tmp_path_factory.mktemp("html") / "report.html"
    path.write_text(render_html(r), encoding="utf-8")
    return path


def _open(browser, path, width, scheme, js=True):
    ctx = browser.new_context(
        viewport={"width": width, "height": 900}, color_scheme=scheme, java_script_enabled=js
    )
    page = ctx.new_page()
    errors, requests = [], []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("request", lambda r: requests.append(r.url))
    page.goto(path.as_uri())
    page.wait_for_load_state("load")
    return ctx, page, errors, [u for u in requests if u != path.as_uri()]


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [360, 1280])
def test_browser_layout(browser, report_file, width, scheme):
    ctx, page, errors, requests = _open(browser, report_file, width, scheme)
    try:
        overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        assert overflow <= 0, overflow
        bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
        assert bg == ("rgb(14, 18, 23)" if scheme == "dark" else "rgb(255, 255, 255)")
        assert page.is_visible("#could-not-verify")
        assert page.is_visible("[data-dw-search]")
        ARTIFACTS.mkdir(exist_ok=True)
        page.screenshot(path=str(ARTIFACTS / f"l013-{scheme}-{width}.png"), full_page=True)
        assert errors == [] and requests == []
    finally:
        ctx.close()


def test_browser_without_js(browser, report_file):
    ctx, page, errors, requests = _open(browser, report_file, 360, "dark", js=False)
    try:
        assert page.is_visible("#violated") and page.is_visible("#could-not-verify")
        assert not page.is_visible("[data-dw-search]")  # controls stay hidden
        assert page.evaluate("document.documentElement.scrollWidth - window.innerWidth") <= 0
        page.click("#holding summary")
        assert page.is_visible("#holding .dw-row")
        ARTIFACTS.mkdir(exist_ok=True)
        page.screenshot(path=str(ARTIFACTS / "l013-nojs-dark-360.png"), full_page=True)
        assert requests == []
    finally:
        ctx.close()


def test_browser_theme_toggle_filter_and_expand(browser, report_file):
    ctx, page, errors, _ = _open(browser, report_file, 1280, "dark")
    try:
        btn = page.locator("[data-dw-theme]")
        assert btn.inner_text() == "Theme: system"
        btn.click()
        assert page.evaluate("document.documentElement.dataset.theme") == "light"
        bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
        assert bg == "rgb(255, 255, 255)"
        page.reload()
        assert page.evaluate("document.documentElement.dataset.theme") == "light"
        page.locator("[data-dw-theme]").click()
        page.locator("[data-dw-theme]").click()
        assert page.evaluate("document.documentElement.dataset.theme") is None
        page.fill("[data-dw-search]", "ADR-0001.c3")
        assert page.is_visible("#holding .dw-row")  # fold opened to show the hit
        assert "1 of" in page.inner_text("[data-dw-count]")
        assert not page.is_visible("#violated .dw-card")
        page.fill("[data-dw-search]", "")
        page.click("[data-dw-expand]")
        assert page.evaluate("[...document.querySelectorAll('details')].every(d => d.open)")
        page.click("[data-dw-collapse]")
        assert page.evaluate("[...document.querySelectorAll('details')].every(d => !d.open)")
        page.emulate_media(media="print")
        page.evaluate("window.dispatchEvent(new Event('beforeprint'))")
        assert page.evaluate("[...document.querySelectorAll('details')].every(d => d.open)")
        assert errors == []
    finally:
        ctx.close()


# ------------------------------------------------------------------ L-012 integration


def test_adr_links_follow_link_base():
    r = full_report()
    rel = section(render_html(r, link_base=".."), "violated")
    assert '<a class="dw-adr-link" href="../docs/adr/0001-pg.md#L13">' in rel
    default = section(render_html(r), "violated")
    assert 'href="docs/adr/0001-pg.md#L13"' in default
    blob = f"https://github.com/o/r/blob/{SHA}"
    assert f'href="{blob}/docs/adr/0001-pg.md#L13"' in render_html(r, link_base=blob)
    for bad in ("", "javascript:alert(1)", "../a b", "file:///etc"):
        assert 'class="dw-adr-link"' not in render_html(r, link_base=bad), bad


def test_non_canonical_adr_path_is_never_a_link():
    src = prov("../../etc/passwd", 1, "x")
    r = full_report()
    cr = r.claims[0]
    bad = cr.model_copy(update={"claim": cr.claim.model_copy(update={"source": src})})
    html = render_html(r.model_copy(update={"claims": [bad, *r.claims[1:]]}), link_base="..")
    assert 'href="../../../etc' not in html and "../../etc/passwd:L1-L1" in html


def test_invalid_commits_display_as_invalid():
    r = full_report()
    meta = r.metadata.model_copy(update={"commit": "HEAD; rm -rf"})
    tl = [r.timeline[0].model_copy(update={"first_violating_commit": "not-a-sha"})]
    html = render_html(r.model_copy(update={"metadata": meta, "timeline": tl}))
    head = html[html.index("<header") : html.index("</header>")]
    assert ">invalid</code>" in head and "rm -rf" not in head
    assert "not-a-sha" not in html


def test_pr_mode_in_change_badge_and_order():
    r = full_report()
    meta = r.metadata.model_copy(update={"changed_paths": ["src/mod0.py"]})
    claims = [
        c.model_copy(update={"in_change": c.id == "ADR-0001.c5"}) if c.judged else c
        for c in r.claims
    ]
    html = render_html(r.model_copy(update={"metadata": meta, "claims": claims}))
    v = section(html, "violated")
    assert v.index("ADR-0001.c5") < v.index("ADR-0001.c1")  # in-change first
    assert v.count(">In this change<") == 1 and "Present before this change" in v
    assert "PR mode: 1 changed path" in html and "1 of 3 violated or drifting" in html
    assert ">In this change<" not in render_html(full_report())


def test_notes_are_shown():
    html = render_html(full_report())
    assert "skipped ADR docs/adr/empty.md: empty file" in section(html, "notes")


def test_unverified_evidence_moves_to_could_not_verify():
    """build_view, not Report.verdicts(): a VIOLATED verdict whose evidence has no
    VERIFIED G2 record of its own is not a fact."""
    r = full_report()
    cr = r.claims[0]
    v = cr.verdict.model_copy(update={"checks": []})
    html = render_html(r.model_copy(update={"claims": [cr.model_copy(update={"verdict": v})]}))
    assert "ADR-0001.c1" not in section(html, "violated")
    c = section(html, "could-not-verify")
    assert "ADR-0001.c1" in c and "report-time evidence re-check" in c
    assert "src/mod0.py" not in section(html, "violated")


def _tamper_cases():
    import test_l012_system as s12

    def flip_drifting(d):
        v = s12.claim_of(d, "ADR-0003.c1")["verdict"]
        v.update(status="DRIFTING", grounding="VERIFIED", reasons=[], proposed_status=None)

    def flip_no_record(d):
        v = s12.claim_of(d, "ADR-0003.c1")["verdict"]
        v.update(status="VIOLATED", grounding="VERIFIED", reasons=[], proposed_status=None)
        v["checks"] = []
        d["could_not_verify"] = [i for i in d["could_not_verify"] if i["claim_id"] != "ADR-0003.c1"]

    def edit(field, value):
        def f(d):
            s12.violated(d, "ADR-0002.c1")["verdict"]["evidence"][0]["ref"][field] = value

        return f

    def consistent_unsafe(d):
        c = s12.violated(d, "ADR-0002.c1")
        for ref in (c["verdict"]["evidence"][0]["ref"], c["verdict"]["checks"][0]["provenance"]):
            ref["path"] = "../../etc/shadow"
            ref["line_start"] = 0

    def delete_g3(d):
        c = s12.violated(d, "ADR-0001.c1")
        c["verdict"]["checks"] = [x for x in c["verdict"]["checks"] if x["check_id"] != "G3"]

    def dep_edit(d):
        s12.violated(d, "ADR-0001.c1")["verdict"]["evidence"][0]["dependency"]["package"] = "x"

    def extra_item(d):
        c = s12.violated(d, "ADR-0005.c1")
        extra = s12.copy.deepcopy(c["verdict"]["evidence"][1])
        extra["id"] = "e9"
        extra["ref"]["path"] = "src/planted.py"
        c["verdict"]["evidence"].append(extra)

    def row_mismatch(d):
        s12.violated(d, "ADR-0005.c1")["verdict"]["checks"][0]["status"] = "MISMATCH"

    def fake_claim(d):
        fake = s12.clone_claim(s12.claim_of(d, "ADR-0002.c1"), "ADR-0099.c1")
        fake["claim"]["decision_id"] = "ADR-0099"
        fake["verdict"]["checks"] = []
        fake["verdict"]["evidence"][0]["ref"]["path"] = "src/fake_violation.py"
        d["claims"].append(fake)

    return [
        ("flip_to_drifting", flip_drifting, "ADR-0003.c1", ["tests/db_check.py"]),
        ("flip_no_record", flip_no_record, "ADR-0003.c1", ["tests/db_check.py"]),
        ("s12_flip_mismatch", s12._flip_mismatch, "ADR-0003.c1", []),
        ("s12_delete_g2", s12._delete_g2, "ADR-0002.c1", ["src/shop/reports.py"]),
        ("s12_edit_path", s12._edit_path, "ADR-0002.c1", ["src/shop/other.py"]),
        ("s12_fake_claim", s12._fake_claim, "ADR-0002.c9", []),
        ("path_traversal", edit("path", "../../etc/passwd"), "ADR-0002.c1", ["../../etc/passwd"]),
        ("line_zero", edit("line_start", 0), "ADR-0002.c1", []),
        ("other_commit", edit("commit", "0" * 40), "ADR-0002.c1", []),
        ("quote_edit", edit("quote", "totally different text"), "ADR-0002.c1", []),
        ("consistent_unsafe", consistent_unsafe, "ADR-0002.c1", ["../../etc/shadow"]),
        ("delete_g3", delete_g3, "ADR-0001.c1", []),
        ("dependency_edit", dep_edit, "ADR-0001.c1", []),
        ("extra_item", extra_item, "ADR-0005.c1", ["src/planted.py"]),
        ("row_mismatch", row_mismatch, "ADR-0005.c1", []),
        ("fake_claim", fake_claim, "ADR-0099.c1", ["src/fake_violation.py"]),
    ]


FACT_SECTIONS = ("violated", "drifting", "holding", "unknown")
MD_NAMES = {"violated": "Violated", "drifting": "Drifting"}


def _html_bucket(html: str, claim_id: str) -> set[str]:
    """Sections whose cards/rows name ``claim_id`` as a code span."""
    needle = re.compile(r'class="dw-mono[^"]*">' + re.escape(claim_id) + "</")
    return {
        sid for sid in (*FACT_SECTIONS, "could-not-verify") if needle.search(section(html, sid))
    }


@pytest.mark.parametrize("case", _tamper_cases(), ids=lambda c: c[0])
@pytest.mark.parametrize("gated", [False, True], ids=["raw", "regate"])
def test_tampered_reports_match_markdown(case, gated):
    """Sonnet's L-012 tamper builders: HTML puts them in Could not verify, as Markdown."""
    import test_l012_system as s12
    from driftwarden.report.markdown import render_markdown
    from driftwarden.report.view import regate

    _name, tamper, cid, forbidden = case
    d = s12.fx()
    tamper(d)
    r = s12.rep(d)
    if gated:
        r = regate(r)
    html = render_html(r)
    md = s12.md_sections(render_markdown(r))
    assert _html_bucket(html, cid) == {"could-not-verify"}, _html_bucket(html, cid)
    assert cid in md["Could not verify"].replace("\\", "")
    for sid in FACT_SECTIONS:
        for p in forbidden:
            assert p not in section(html, sid), (p, sid)
    # every judged claim is a fact in the same section in both formats
    for c in r.claims:
        for sid, name in MD_NAMES.items():
            in_md = f"**{c.id}**" in md.get(name, "")
            assert in_md == (sid in _html_bucket(html, c.id)), (c.id, sid, in_md)


def test_untouched_fixture_has_no_demotions():
    import test_l012_system as s12

    html = render_html(s12.rep(s12.fx()))
    for cid in ("ADR-0001.c1", "ADR-0005.c1"):
        assert _html_bucket(html, cid) == {"violated"}
    assert "report-time evidence re-check" not in html


def test_cli_scan_and_report_write_html(tmp_path):
    from typer.testing import CliRunner

    from driftwarden.cli import app

    runner = CliRunner()
    repo = tmp_path / "pyshop"
    shutil.copytree(Path(__file__).parent / "fixtures" / "judge_repos" / "pyshop", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")
    args = ["scan", str(repo), "--mode", "offline", "--format", "json,html,md,sarif"]
    res = runner.invoke(app, args)
    assert res.exit_code in (0, 1), res.output
    out = repo / ".driftwarden"
    html = (out / "driftwarden.html").read_text(encoding="utf-8")
    md = (out / "driftwarden.md").read_text(encoding="utf-8")
    link = "../docs/adr/0001-postgresql-only.md#L13"
    assert f"]({link})" in md
    assert f'href="{link}"' in html  # the same link_base as Markdown
    assert "ADR-0001" in section(html, "violated")
    saved = tmp_path / "saved.json"
    saved.write_text((out / "driftwarden.json").read_text(encoding="utf-8"), encoding="utf-8")
    out2 = tmp_path / "out2"
    res = runner.invoke(app, ["report", str(saved), "--format", "html,md", "--out", str(out2)])
    assert res.exit_code == 0, res.output
    again = (out2 / "driftwarden.html").read_text(encoding="utf-8")
    md2 = (out2 / "driftwarden.md").read_text(encoding="utf-8")
    assert "ADR-0001" in section(again, "violated")
    # no --repo and the output dir is not in the repo: both formats agree on links
    assert ('class="dw-adr-link"' in again) == ("](" in md2 and "#L13)" in md2)
