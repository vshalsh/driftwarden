"""L-012: JSON, Markdown, PR comment and SARIF 2.1.0 reporters, `--format` and `report`.

Golden files live in tests/fixtures/report_golden/. Regenerate them after an intended
output change with::

    python tests/test_l012_reporters.py --update-golden            # md / pr / sarif
    python tests/test_l012_reporters.py --update-golden --rescan   # also the fixture report

(``DRIFTWARDEN_UPDATE_GOLDEN=1 python -m pytest tests/test_l012_reporters.py`` does the
first one from pytest.) The fixture report is a real offline scan of the ``pyshop``
judge fixture, committed with fixed dates, with one ADR quote and one evidence item
tampered so every *Could not verify* path is present.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from html import unescape
from pathlib import Path

import jsonschema
import pytest
from markdown_it import MarkdownIt
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))

from conftest import GIT_ENV, git  # noqa: E402
from driftwarden.cli import app  # noqa: E402
from driftwarden.config import Config  # noqa: E402
from driftwarden.discover.adr import scan_adrs  # noqa: E402
from driftwarden.grounding.ledger import Ledger  # noqa: E402
from driftwarden.judge.judge import Judge  # noqa: E402
from driftwarden.models import Provenance  # noqa: E402
from driftwarden.pipeline import run_scan  # noqa: E402
from driftwarden.report import (  # noqa: E402
    EXTENSIONS,
    HTML_UNAVAILABLE,
    RENDERERS,
    RendererUnavailable,
    render_html,
    render_json,
    render_markdown,
    render_pr_comment,
    render_sarif,
    renderer_available,
)
from driftwarden.report.markdown import (  # noqa: E402
    COMPACT_BUDGET,
    GITHUB_COMMENT_LIMIT,
    PR_COMMENT_MARKER,
    code,
    esc,
)
from driftwarden.report.model import ClaimResult, Report, TimelineEntry  # noqa: E402
from driftwarden.report.sarif import (  # noqa: E402
    FINGERPRINT_KEY,
    MAX_BYTES,
    MAX_RESULTS,
    RULE_IDS,
)
from driftwarden.report.view import build_view, evidence_verified  # noqa: E402

TESTS = Path(__file__).parent
FIXTURES = TESTS / "fixtures"
REPORTS = FIXTURES / "report_golden"
FIXTURE_REPORT = REPORTS / "pyshop.report.json"
SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
FIXED_DATE = "2026-01-01T00:00:00+00:00"
SCANNED_AT = "2026-10-29T00:00:00Z"
runner = CliRunner()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise OSError("network access is disabled in tests")

    class BlockedSocket(socket.socket):
        def connect(self, *_a, **_k):
            blocked()

    monkeypatch.setattr(socket, "socket", BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


# --------------------------------------------------------------------------- helpers


def _git_fixed(repo: Path, *args: str) -> None:
    env = {
        **os.environ,
        **GIT_ENV,
        "GIT_AUTHOR_DATE": FIXED_DATE,
        "GIT_COMMITTER_DATE": FIXED_DATE,
    }
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


def pyshop_repo(base: Path, name: str = "pyshop") -> Path:
    dest = base / name
    shutil.copytree(FIXTURES / "judge_repos" / "pyshop", dest)
    _git_fixed(dest, "init", "-q", "-b", "main")
    _git_fixed(dest, "config", "commit.gpgsign", "false")
    _git_fixed(dest, "add", "-A")
    _git_fixed(dest, "commit", "-q", "-m", "fixture")
    return dest


def build_fixture_report(base: Path) -> Report:
    """Real offline scan of pyshop (fixed commit dates) with two tamperings:
    ADR-0006's decision quote (G1, exit 3) and ADR-0003.c1's evidence (G2)."""
    repo = pyshop_repo(base)
    adrs = scan_adrs(repo, Config())
    i = next(n for n, d in enumerate(adrs.decisions) if d.id == "ADR-0006")
    d = adrs.decisions[i]
    adrs.decisions[i] = d.model_copy(
        update={"source": d.source.model_copy(update={"quote": "We will use Celery."})}
    )
    real = Judge.evidence

    def tampered(self, claim):
        es = real(self, claim)
        if claim.id != "ADR-0003.c1":
            return es
        items = [
            e.model_copy(update={"ref": e.ref.model_copy(update={"quote": "import nothing"})})
            for e in es.candidates
        ]
        return es.model_copy(update={"candidates": items})

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Judge, "evidence", tampered)
        r = run_scan(
            repo,
            config=Config(),
            mode="offline",
            ledger=Ledger(base / "ledger"),
            draft_adrs=True,
            adrs=adrs,
        )
    meta = r.metadata.model_copy(update={"scanned_at": SCANNED_AT, "tool_version": "0.0.1"})
    return r.model_copy(update={"metadata": meta})


def load_fixture() -> Report:
    return Report.model_validate_json(FIXTURE_REPORT.read_text(encoding="utf-8"))


GOLDEN = {
    "pyshop.md": lambda r: render_markdown(r),
    "pyshop.pr.md": lambda r: render_pr_comment(r),
    "pyshop.sarif": lambda r: render_sarif(r),
}


def update_golden(rescan: bool = False) -> None:
    import tempfile

    REPORTS.mkdir(parents=True, exist_ok=True)
    if rescan:
        with tempfile.TemporaryDirectory() as tmp:
            FIXTURE_REPORT.write_text(render_json(build_fixture_report(Path(tmp))), "utf-8")
    report = load_fixture()
    for name, fn in GOLDEN.items():
        (REPORTS / name).write_text(fn(report), encoding="utf-8", newline="\n")


def validate_sarif(text: str) -> dict:
    doc = json.loads(text)
    jsonschema.Draft4Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(doc)
    return doc


def sarif_locations(doc: dict) -> list[tuple[str, int, int, str]]:
    """(uri, startLine, endLine, 'primary'|'related') for every location of every result."""
    out = []
    for res in doc["runs"][0]["results"]:
        for kind, locs in (
            ("primary", res["locations"]),
            ("related", res.get("relatedLocations", [])),
        ):
            for loc in locs:
                pl = loc["physicalLocation"]
                reg = pl["region"]
                out.append((pl["artifactLocation"]["uri"], reg["startLine"], reg["endLine"], kind))
    return out


def scan(repo: Path, base: Path, **kw) -> Report:
    kw.setdefault("mode", "offline")
    return run_scan(repo, config=Config(), ledger=Ledger(base), **kw)


def clone_claim(cr: ClaimResult, new_id: str, title_extra: str = "") -> ClaimResult:
    """A copy of ``cr`` under a new claim id, with its checks re-keyed (still verified)."""
    old = cr.claim.id
    data = cr.model_dump()
    data["claim"]["id"] = new_id
    v = data["verdict"]
    v["claim_id"] = new_id
    for c in v["checks"]:
        if c["subject"] and c["subject"].startswith(old + "/"):
            c["subject"] = new_id + c["subject"][len(old) :]
    if title_extra:
        v["rationale"] = (v["rationale"] + " " + title_extra).strip()
    return ClaimResult.model_validate(data)


def html_of(md: str) -> str:
    return MarkdownIt("commonmark", {"html": True}).enable("table").render(md)


# --------------------------------------------------------------------------- golden


def test_fixture_report_is_current_model_and_rich():
    r = load_fixture()
    assert Report.model_validate_json(render_json(r)) == r
    kinds = {i.kind for i in r.could_not_verify}
    assert {"decision", "verdict", "evidence"} <= kinds
    assert r.verdicts("VIOLATED") and r.verdicts("HOLDING") and r.verdicts("UNKNOWN")
    assert r.undocumented and r.drafts and r.summary.exit_code == 3


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden(name):
    report = load_fixture()
    got = GOLDEN[name](report)
    if os.environ.get("DRIFTWARDEN_UPDATE_GOLDEN"):
        (REPORTS / name).write_text(got, encoding="utf-8", newline="\n")
    want = (REPORTS / name).read_text(encoding="utf-8")
    assert got == want, f"{name} changed; run python tests/test_l012_reporters.py --update-golden"
    assert got == GOLDEN[name](load_fixture())  # deterministic
    assert got.endswith("\n") and not got.endswith("\n\n")


def test_fixture_regenerates_identically(tmp_path):
    """The committed fixture is what a scan of pyshop produces today (apart from the
    ledger's run ids, which the Report does not carry)."""
    fresh = build_fixture_report(tmp_path)
    assert render_json(fresh) == FIXTURE_REPORT.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- json


def test_json_is_canonical(tmp_path):
    r = load_fixture()
    text = render_json(r)
    assert text.endswith("}\n")
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    assert Report.model_validate_json(text) == r
    assert RENDERERS["json"] is render_json and EXTENSIONS["sarif"] == "sarif"


# --------------------------------------------------------------------------- markdown


def test_markdown_sections_and_order():
    md = render_markdown(load_fixture())
    heads = [re.sub(r" \(\d+\)$", "", h) for h in re.findall(r"<h2>(.*?)</h2>", html_of(md))]
    assert heads == [
        "Summary",
        "Violated",
        "Drifting",
        "Could not verify",
        "Undocumented decisions",
        "Holding",
        "Unknown",
        "Grounding summary",
    ]
    assert "Drift timeline" not in md  # empty timeline: no section
    # header facts
    for text in ("pyshop", "offline", SCANNED_AT, "Drift score"):
        assert text in md
    # violated item: rule, ADR link path#Lline @ short sha, evidence file:line @ sha + snippet
    r = load_fixture()
    sha = r.metadata.commit[:7]
    assert "[docs/adr/0001-postgresql-only.md\\#L13](docs/adr/0001-postgresql-only.md#L13)" in md
    assert f"@ `{sha}`" in md
    assert f"`requirements.txt:2` @ `{sha}`" in md and "`pymongo==4.6.1`" in md
    assert "`only(datastore) = [PostgreSQL]`" in md
    # holding is collapsed, drafts are collapsed fenced sources
    hold = md.split("## Holding")[1].split("## Unknown")[0]
    assert "<details>" in hold and "ADR-0004.c1" in hold
    assert "<summary>Draft ADR for UD-queue-kafka" in md and "````markdown" in md


def test_could_not_verify_always_present_and_lists_reasons(pyshop_tmp):
    md = render_markdown(load_fixture())
    cnv = md.split("## Could not verify")[1].split("## Undocumented")[0]
    assert "decision ADR-0006" in cnv and "\\[G1\\]" in cnv
    assert "verdict ADR-0003.c1" in cnv and "proposed DRIFTING" in cnv
    assert "Reason:" in cnv and "Cited (not verified)" in cnv
    # the tampered claim is never shown as a finding
    assert "ADR-0003.c1" not in md.split("## Could not verify")[0]
    # empty case says none
    clean = scan(pyshop_tmp, pyshop_tmp.parent / "lg")
    md2 = render_markdown(clean)
    assert re.search(r"## Could not verify \(0\)\n\nNone", md2)


@pytest.fixture
def pyshop_tmp(tmp_path):
    return pyshop_repo(tmp_path)


def test_timeline_rendered_only_when_present():
    r = load_fixture()
    tl = [
        TimelineEntry(
            claim_id="ADR-0001.c1",
            first_violating_commit="a" * 40,
            parent="b" * 40,
            date="2026-01-01",
            subject="Add mongo | @octocat [x](javascript:alert(1))",
            grounding="VERIFIED",
        ),
        TimelineEntry(claim_id="ADR-0005.c1", grounding="MISMATCH"),
    ]
    md = render_markdown(r.model_copy(update={"timeline": tl}))
    sec = md.split("## Drift timeline")[1]
    assert "`aaaaaaa`" in sec and "`bbbbbbb`" in sec and "first seen: unknown" in sec
    html = html_of(md)
    assert "javascript:" not in re.sub(r"<code>.*?</code>", "", html).replace(
        "javascript:alert", ""
    )
    assert 'href="javascript' not in html and "@octocat" not in html
    table = html.split("Drift timeline")[1].split("</table>")[0]
    for row in re.findall(r"<tr>(.*?)</tr>", table, flags=re.S):
        assert len(re.findall(r"<t[dh]", row)) == 6  # the pipe did not add a cell


PAYLOAD = (
    "x](javascript:alert(1)) <script>alert(1)</script> <img src=x onerror=alert(1)> "
    "a|b ``` `tick` @octocat @org/team &lt; *em* _u_ ~~s~~ $x$ \u202eevil"
)


def _injected(report: Report) -> Report:
    data = json.loads(render_json(report))
    data["metadata"]["repo"] = "repo|" + PAYLOAD
    for d in data["decisions"]:
        d["title"] = PAYLOAD
    for c in data["claims"]:
        c["claim"]["source"]["quote"] = PAYLOAD
        if c["claim"]["kind"] == "only":
            c["claim"]["rule"]["only"] = [PAYLOAD]
        if c["verdict"]:
            c["verdict"]["rationale"] = PAYLOAD
    for i in data["could_not_verify"]:
        i["reasons"] = [PAYLOAD]
        i["id"] = i["id"] + " " + PAYLOAD
    for u in data["undocumented"]:
        u["title"] = PAYLOAD
    for d in data["drafts"]:
        d["markdown"] = (
            "# t\n\n````\n<script>alert(1)</script>\n[x](javascript:alert(1)) @octocat\n"
        )
        d["path"] = "docs/adr/<b>x</b>.md"
    data["notes"] = [PAYLOAD]
    data["timeline"] = [
        {
            "claim_id": "ADR-0001.c1",
            "first_violating_commit": "a" * 40,
            "parent": "b" * 40,
            "date": "2026",
            "subject": PAYLOAD,
            "grounding": "VERIFIED",
        }
    ]
    return Report.model_validate(data)


@pytest.mark.parametrize("render", [render_markdown, render_pr_comment])
def test_markdown_injection_is_inert(render):
    r = _injected(load_fixture())
    md = render(r)
    html = html_of(md)
    assert "<script" not in html and "<img" not in html and "<b>x</b>" not in html
    assert 'href="javascript' not in html.lower()
    assert "\u202e" not in md
    outside_code = re.sub(r"<code[^>]*>.*?</code>", "", html, flags=re.S)
    assert "@octocat" not in outside_code and "@org/team" not in outside_code
    assert "@\u200doctocat" in md  # mentions are broken with a zero-width joiner
    assert "<em>" not in html and "<strong>em" not in html and "<del>" not in html
    # every table keeps its column count despite pipes in the payload
    for table in re.findall(r"<table>.*?</table>", html, flags=re.S):
        rows = re.findall(r"<tr>(.*?)</tr>", table, flags=re.S)
        widths = {len(re.findall(r"<t[dh][ >]", row)) for row in rows}
        assert len(widths) == 1, table
    # the rule text survives intact inside its code span
    spans = [unescape(c) for c in re.findall(r"<code>(.*?)</code>", html)]
    assert any(PAYLOAD.replace("\u202e", "\\u202e") in c for c in spans)  # D3: shown, visibly


def test_escape_helpers():
    assert esc("[a](javascript:x)") == "\\[a\\](javascript:x)"
    assert esc("<b>&") == "\\<b\\>\\&"
    assert esc("@user") == "@\u200duser"
    assert esc("a\nb\tc") == "a b c"
    assert esc("<b>", html_ctx=True) == "&lt;b&gt;"
    assert code("a ``b`` c") == "``` a ``b`` c ```"
    assert code("`x") == "`` `x ``"
    assert esc("x" * 50, limit=10).endswith("…") and len(esc("x" * 50, limit=10)) == 10


def test_draft_fence_is_longer_than_any_backtick_run():
    r = _injected(load_fixture())
    md = render_markdown(r)
    assert "`````markdown" in md  # draft holds a 4-backtick line, so the fence has 5


def test_link_base_makes_adr_links_absolute():
    r = load_fixture()
    md = render_markdown(r, link_base="https://github.com/o/r/blob/abc/")
    assert "(https://github.com/o/r/blob/abc/docs/adr/0001-postgresql-only.md#L13)" in md
    md2 = render_markdown(r, link_base="javascript:alert(1)//")
    assert "javascript" not in md2


def test_pr_comment_marker_and_order():
    pr = render_pr_comment(load_fixture())
    assert pr.startswith(PR_COMMENT_MARKER + "\n")
    order = [pr.index(h) for h in ("### Violated", "### Could not verify", "### Drifting")]
    assert order == sorted(order)
    assert "````markdown" not in pr  # no drafts in the comment
    assert len(pr) <= COMPACT_BUDGET < GITHUB_COMMENT_LIMIT


# --------------------------------------------------------------------------- truncation


def _big_report(n_hold: int, n_viol: int, text: str = "") -> Report:
    r = load_fixture()
    hold = next(c for c in r.claims if c.id == "ADR-0004.c1")
    viol = next(c for c in r.claims if c.id == "ADR-0001.c1")
    claims = [c for c in r.claims if c.id not in ("ADR-0004.c1", "ADR-0001.c1")]
    claims += [clone_claim(hold, f"ADR-0004.c{i + 1}", text) for i in range(n_hold)]
    claims += [clone_claim(viol, f"ADR-0001.c{i + 1}", text) for i in range(n_viol)]
    return r.model_copy(update={"claims": claims})


def test_compact_markdown_truncates_holding_with_and_n_more():
    r = _big_report(500, 3)
    full = render_markdown(r)
    compact = render_markdown(r, compact=True)
    assert full.count("ADR-0004.c") > compact.count("ADR-0004.c")
    assert "… and 480 more" in compact
    assert len(compact) <= COMPACT_BUDGET
    assert "ADR-0001.c3" in compact  # violations are not cut at this size


@pytest.mark.parametrize("render", [lambda r: render_markdown(r, compact=True), render_pr_comment])
def test_compact_always_fits_the_comment_limit(render):
    r = _big_report(2000, 2000, "y" * 300)
    out = render(r)
    assert len(out) <= COMPACT_BUDGET
    assert "more (see the full report)" in out
    assert re.search(r"Violated \(2002\)", out)  # counts stay exact


def test_sarif_truncates_by_count_and_size():
    r = _big_report(0, 40)
    full = validate_sarif(render_sarif(r))
    n = len(full["runs"][0]["results"])
    assert "truncated" not in full["runs"][0]["properties"]["driftwarden"]
    cut = validate_sarif(render_sarif(r, max_results=5))
    run = cut["runs"][0]
    assert len(run["results"]) == 5
    t = run["properties"]["driftwarden"]["truncated"]
    assert t["resultsTotal"] == n and t["resultsEmitted"] == 5 and "25000" not in t["reason"]
    assert all(x["level"] == "error" for x in run["results"])  # most important kept
    small = render_sarif(r, max_bytes=40_000)
    assert len(small.encode()) <= 40_000
    doc = validate_sarif(small)
    t2 = doc["runs"][0]["properties"]["driftwarden"]["truncated"]
    assert "bytes" in t2["reason"] and 0 < t2["resultsEmitted"] < n
    assert MAX_RESULTS == 25_000 and MAX_BYTES == 10 * 1024 * 1024


# --------------------------------------------------------------------------- sarif


def test_sarif_validates_and_has_the_required_shape():
    doc = validate_sarif(render_sarif(load_fixture()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "DriftWarden" and drv["version"] == "0.0.1"
    assert drv["informationUri"] == "https://github.com/vshalsh/driftwarden"
    assert (
        [r["id"] for r in drv["rules"]]
        == list(RULE_IDS)
        == [
            "forbid",
            "require",
            "only",
            "boundary",
            "free",
            "undocumented-decision",
            "could-not-verify",
        ]
    )
    levels = {}
    for res in run["results"]:
        assert drv["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        levels.setdefault(res["properties"]["status"], set()).add(res["level"])
        assert res["locations"], res
        assert set(res["partialFingerprints"]) == {FINGERPRINT_KEY}
        p = res["properties"]
        assert p["commit"] == load_fixture().metadata.commit and p["grounding"]
        if res["ruleId"] not in ("undocumented-decision",):
            assert p.get("adrId"), res
    assert levels == {
        "VIOLATED": {"error"},
        "UNDOCUMENTED": {"note"},
        "COULD_NOT_VERIFY": {"note"},
    }  # the fixture's DRIFTING claim is tampered, so it is could-not-verify
    statuses = [r["properties"]["status"] for r in run["results"]]
    assert "HOLDING" not in statuses and "UNKNOWN" not in statuses
    for uri, a, b, _ in sarif_locations(doc):
        assert not uri.startswith(("/", "./")) and "\\" not in uri and ".." not in uri.split("/")
        assert 1 <= a <= b
    assert "startColumn" not in json.dumps(doc)


def test_sarif_drifting_is_warning(pyshop_tmp):
    doc = validate_sarif(render_sarif(scan(pyshop_tmp, pyshop_tmp.parent / "lg")))
    by = {r["properties"].get("claimId"): r for r in doc["runs"][0]["results"]}
    assert by["ADR-0003.c1"]["level"] == "warning"
    assert by["ADR-0001.c1"]["level"] == "error"


def test_sarif_could_not_verify_is_located_at_the_adr_line():
    r = load_fixture()
    doc = validate_sarif(render_sarif(r))
    cnv = [x for x in doc["runs"][0]["results"] if x["ruleId"] == "could-not-verify"]
    assert {x["properties"]["kind"] for x in cnv} >= {"decision", "verdict", "evidence"}
    adr_paths = {d.source.path for d in r.decisions}
    for x in cnv:
        assert x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] in adr_paths
        assert x["properties"]["reasons"] and "Could not verify" in x["message"]["text"]
        assert "relatedLocations" not in x


def test_sarif_locations_are_verified_evidence_or_adr_lines_only():
    r = load_fixture()
    view = build_view(r)
    allowed = {(d.source.path, d.source.line_start) for d in r.decisions}
    allowed |= {(c.claim.source.path, c.claim.source.line_start) for c in r.claims}
    for f in view.violated + view.drifting:
        allowed |= {(e.ref.path, e.ref.line_start) for e in f.evidence}
    for u in view.undocumented:
        allowed |= {(e.ref.path, e.ref.line_start) for e in u.evidence}
    doc = validate_sarif(render_sarif(r))
    for uri, a, _b, _kind in sarif_locations(doc):
        assert (uri, a) in allowed
    # the pipeline-tampered evidence (ADR-0003.c1) never became a location
    bad = next(c for c in r.claims if c.id == "ADR-0003.c1").verdict
    assert bad.grounding == "MISMATCH" and bad.evidence
    cnv = [x for x in doc["runs"][0]["results"] if x["properties"].get("claimId") == "ADR-0003.c1"]
    assert cnv and all(x["ruleId"] == "could-not-verify" for x in cnv)
    for x in cnv:
        uri = x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "docs/adr/0003-no-requests.md"
        assert uri not in {ev.ref.path for ev in bad.evidence}


def _tamper_saved_evidence(report: Report, claim_id: str, **ref_update) -> Report:
    data = json.loads(render_json(report))
    c = next(x for x in data["claims"] if x["claim"]["id"] == claim_id)
    c["verdict"]["evidence"][-1]["ref"].update(ref_update)
    return Report.model_validate(data)


@pytest.mark.parametrize(
    "update",
    [
        {"line_start": 4, "line_end": 4},
        {"quote": "from x import y"},
        {"path": "src/other.py"},
        {"path": "./src/shop/legacy/catalog.py"},
        {"line_start": 0, "line_end": 0},
    ],
)
def test_tampered_saved_evidence_never_becomes_a_location(update):
    r = _tamper_saved_evidence(load_fixture(), "ADR-0001.c1", **update)
    doc = validate_sarif(render_sarif(r))
    locs = sarif_locations(doc)
    tampered = next(c for c in r.claims if c.id == "ADR-0001.c1").verdict.evidence[-1].ref
    view = build_view(r)
    legit = {(e.ref.path, e.ref.line_start) for u in view.undocumented for e in u.evidence}
    legit |= {(e.ref.path, e.ref.line_start) for f in view.violated for e in f.evidence}
    if (tampered.path, tampered.line_start) not in legit:  # e.g. pymongo is also a UD record
        assert (tampered.path, tampered.line_start) not in {(u, a) for u, a, _b, _k in locs}
    mine = [x for x in doc["runs"][0]["results"] if x["properties"].get("claimId") == "ADR-0001.c1"]
    for x in mine:  # the whole finding is demoted: located at the ADR line only
        assert {u for u, *_ in sarif_locations({"runs": [{"results": [x]}]})} == {
            "docs/adr/0001-postgresql-only.md"
        }
    res = next(
        x for x in doc["runs"][0]["results"] if x["properties"].get("claimId") == "ADR-0001.c1"
    )
    assert res["ruleId"] == "could-not-verify" and res["level"] == "note"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "docs/adr/"
    )
    md = render_markdown(r)
    assert "ADR-0001.c1" not in md.split("## Violated")[1].split("## Drifting")[0]
    cnv = md.split("## Could not verify")[1].split("## Undocumented")[0]
    assert "verdict ADR-0001.c1" in cnv and "report-time evidence re-check" in cnv
    assert "failed the report-time evidence re-check" in md


def test_tampered_undocumented_evidence_is_demoted():
    data = json.loads(render_json(load_fixture()))
    data["undocumented"][0]["evidence"][0]["ref"]["quote"] = "nothing"
    r = Report.model_validate(data)
    rid = r.undocumented[0].id
    view = build_view(r)
    assert rid not in {u.record.id for u in view.undocumented}
    assert any(u.kind == "undocumented" and u.id == rid for u in view.could_not_verify)
    doc = validate_sarif(render_sarif(r))
    assert rid not in {x["properties"].get("recordId") for x in doc["runs"][0]["results"]}
    assert any(rid in s for s in doc["runs"][0]["properties"]["driftwarden"]["unlocated"])


def test_evidence_verified_requires_matching_records():
    r = load_fixture()
    cr = next(c for c in r.claims if c.id == "ADR-0001.c1")
    v = cr.verdict
    ev = v.evidence[0]
    assert evidence_verified(ev, v.checks, f"{cr.id}/{ev.id}", v.commit) is None
    assert "no verifier record" in evidence_verified(ev, [], f"{cr.id}/{ev.id}", v.commit)
    assert "commit" in evidence_verified(ev, v.checks, f"{cr.id}/{ev.id}", "f" * 40)
    dep = ev.dependency.model_copy(update={"version_spec": "==9"})
    assert "G3" in evidence_verified(
        ev.model_copy(update={"dependency": dep}), v.checks, f"{cr.id}/{ev.id}", v.commit
    )


def test_sarif_paths_are_percent_encoded_posix():
    r = load_fixture()
    data = json.loads(render_json(r))
    # a could-not-verify item anchored at an ADR path with a space
    item = next(i for i in data["could_not_verify"] if i["kind"] == "decision")
    item["provenance"]["path"] = "docs/adr/my adr#1.md"
    r2 = Report.model_validate(data)
    doc = validate_sarif(render_sarif(r2))
    uris = {u for u, *_ in sarif_locations(doc)}
    assert "docs/adr/my%20adr%231.md" in uris
    assert isinstance(r2.could_not_verify[0].provenance, Provenance)


# --------------------------------------------------------------------------- PR mode / notes


@pytest.fixture
def pr_report(pyshop_tmp):
    r = scan(pyshop_tmp, pyshop_tmp.parent / "lg", changed_paths=["src/shop/legacy/catalog.py"])
    flags = {c.id: c.in_change for c in r.claims if c.status == "VIOLATED"}
    assert flags["ADR-0001.c1"] is True and False in flags.values()  # both kinds present
    return r


def test_pr_comment_leads_with_in_change_violations(pr_report):
    pr = render_pr_comment(pr_report)
    mine = pr.index("### Violated in this change (1)")
    before = pr.index("### Already present before this change (")
    assert mine < before < pr.index("### Could not verify")
    assert "ADR-0001.c1" in pr[mine:before]
    old = [c.id for c in pr_report.claims if c.status == "VIOLATED" and not c.in_change]
    for cid in old:
        assert cid in pr[before:] and cid not in pr[mine:before]
    assert "### Violated (" not in pr
    md = render_markdown(pr_report)
    assert "**in this change**" in md and "present before this change" in md
    assert "PR mode: 1 violated" in md
    # outside PR mode nothing about the change is shown
    plain = render_pr_comment(load_fixture())
    assert "in this change" not in plain and "### Violated (" in plain


def test_sarif_carries_in_change(pr_report):
    doc = validate_sarif(render_sarif(pr_report))
    by = {r["properties"].get("claimId"): r["properties"] for r in doc["runs"][0]["results"]}
    for c in pr_report.claims:
        if c.status in ("VIOLATED", "DRIFTING") and c.id in by:
            assert by[c.id]["inChange"] is c.in_change
    plain = validate_sarif(render_sarif(load_fixture()))
    assert all("inChange" not in r["properties"] for r in plain["runs"][0]["results"])


def test_notes_section_is_escaped(pyshop_tmp):
    r = load_fixture()
    r = r.model_copy(update={"notes": ["skipped ADR <b>x</b> @octocat [a](javascript:1)"]})
    for out in (render_markdown(r), render_pr_comment(r)):
        assert "Notes (1)" in out
        html = html_of(out)
        assert "<b>x</b>" not in html and 'href="javascript' not in html
        assert "@octocat" not in html


def test_fingerprints_stable_across_two_scans(tmp_path):
    repo = pyshop_repo(tmp_path)
    a = validate_sarif(render_sarif(scan(repo, tmp_path / "la", draft_adrs=True)))
    (repo / "NOTES.txt").write_text("unrelated change\n", encoding="utf-8")
    git(repo, "add", "NOTES.txt")
    git(repo, "commit", "-q", "-m", "unrelated")
    b = validate_sarif(render_sarif(scan(repo, tmp_path / "lb", draft_adrs=True)))

    def fps(doc):
        return {
            r["partialFingerprints"][FINGERPRINT_KEY]: (r["ruleId"], r["level"])
            for r in doc["runs"][0]["results"]
        }

    assert (
        a["runs"][0]["properties"]["driftwarden"]["commit"]
        != (b["runs"][0]["properties"]["driftwarden"]["commit"])
    )
    fa, fb = fps(a), fps(b)
    assert fa == fb and len(fa) == len(a["runs"][0]["results"])  # stable and unique


def test_sarif_message_has_no_embedded_link():
    r = _injected(load_fixture())
    text = render_sarif(r)
    validate_sarif(text)
    for res in json.loads(text)["runs"][0]["results"]:
        assert not re.search(r"(?<!\\)\[[^\]]*(?<!\\)\]\(", res["message"]["text"])


# --------------------------------------------------------------------------- CLI


def test_cli_format_writes_files(pyshop_tmp, tmp_path):
    out = tmp_path / "out"
    jo = tmp_path / "j.json"
    res = runner.invoke(
        app,
        [
            "scan",
            str(pyshop_tmp),
            "--out",
            str(out),
            "--format",
            "json,md,sarif",
            "--json-out",
            str(jo),
        ],
    )
    assert res.exit_code == 1, res.output
    for ext in ("json", "md", "sarif"):
        p = out / f"driftwarden.{ext}"
        assert p.is_file() and f"Wrote {ext}: {p}" in res.output
    assert (out / "driftwarden.json").read_bytes() == jo.read_bytes()
    validate_sarif((out / "driftwarden.sarif").read_text(encoding="utf-8"))
    assert "## Violated (3)" in (out / "driftwarden.md").read_text(encoding="utf-8")
    assert "nothing was written" not in res.output and "L-012" not in res.output
    assert not (out / "driftwarden.html").exists()


def test_cli_format_default_out_is_self_ignored(pyshop_tmp):
    res = runner.invoke(app, ["scan", str(pyshop_tmp), "--format", "md,sarif"])
    assert res.exit_code == 1, res.output
    assert (pyshop_tmp / ".driftwarden" / "driftwarden.md").is_file()
    assert (pyshop_tmp / ".driftwarden" / "driftwarden.sarif").is_file()
    assert git(pyshop_tmp, "status", "--porcelain", "--untracked-files=all").strip() == ""


def test_report_subcommand_round_trip(pyshop_tmp, tmp_path):
    a = tmp_path / "a"
    res = runner.invoke(
        app, ["scan", str(pyshop_tmp), "--out", str(a), "--format", "json,md,sarif", "--draft-adrs"]
    )
    assert res.exit_code == 1, res.output
    b = tmp_path / "b"
    res2 = runner.invoke(
        app, ["report", str(a / "driftwarden.json"), "--format", "md,sarif,json", "--out", str(b)]
    )
    assert res2.exit_code == 0, res2.output
    for ext in ("json", "md", "sarif"):
        assert (b / f"driftwarden.{ext}").read_bytes() == (a / f"driftwarden.{ext}").read_bytes()
        assert f"Wrote {ext}: {b / f'driftwarden.{ext}'}" in res2.output
    # default --out is the directory of the report file, default format md
    c = tmp_path / "c"
    c.mkdir()
    shutil.copy(a / "driftwarden.json", c / "saved.json")
    res3 = runner.invoke(app, ["report", str(c / "saved.json")])
    assert res3.exit_code == 0 and (c / "driftwarden.md").is_file()


def test_regate_is_identity_on_a_clean_report_and_corrects_a_tampered_one(tmp_path):
    from driftwarden.report.view import REGATE_REASON, regate

    clean = load_fixture()
    assert regate(clean) is clean
    bad = _tamper_saved_evidence(clean, "ADR-0001.c1", quote="from x import y")
    fixed = regate(bad)
    cr = next(c for c in fixed.claims if c.id == "ADR-0001.c1")
    assert cr.verdict.status == "UNKNOWN" and cr.verdict.grounding == "MISMATCH"
    assert cr.verdict.proposed_status == "VIOLATED"
    item = next(
        i for i in fixed.could_not_verify if i.claim_id == "ADR-0001.c1" and i.kind == "verdict"
    )
    assert item.reasons[0] == REGATE_REASON
    s = fixed.summary
    assert s.by_status["VIOLATED"] == clean.summary.by_status["VIOLATED"] - 1
    assert s.could_not_verify == len(fixed.could_not_verify) == clean.summary.could_not_verify + 1
    assert regate(fixed) is fixed  # idempotent
    # every format renders the same corrected report
    p = tmp_path / "bad.json"
    p.write_text(render_json(bad), encoding="utf-8")
    res = runner.invoke(
        app, ["report", str(p), "--format", "json,md", "--out", str(tmp_path / "o")]
    )
    assert res.exit_code == 0, res.output
    assert (tmp_path / "o" / "driftwarden.json").read_text(encoding="utf-8") == render_json(fixed)
    assert "failed the re-render check" in res.output


def test_report_exit_code_flag_follows_the_recomputed_exit_code(tmp_path):
    res = runner.invoke(app, ["report", str(FIXTURE_REPORT), "--out", str(tmp_path), "--exit-code"])
    assert res.exit_code == 3  # the fixture carries a G1 mismatch
    data = json.loads(FIXTURE_REPORT.read_text(encoding="utf-8"))
    # drop the G1 item and edit one evidence item, so the exit code is recomputed
    data["could_not_verify"] = [i for i in data["could_not_verify"] if i["check_id"] != "G1"]
    c = next(x for x in data["claims"] if x["claim"]["id"] == "ADR-0001.c1")
    c["verdict"]["evidence"][0]["ref"]["quote"] = "edited"
    p = tmp_path / "no_g1.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    res = runner.invoke(app, ["report", str(p), "--out", str(tmp_path), "--exit-code"])
    assert res.exit_code == 1  # recomputed: no G1 left, other claims still VIOLATED
    assert runner.invoke(app, ["report", str(p), "--out", str(tmp_path)]).exit_code == 0


def test_report_subcommand_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    res = runner.invoke(app, ["report", str(bad), "--format", "md"])
    assert res.exit_code == 2 and "not a DriftWarden Report JSON" in res.output
    res = runner.invoke(app, ["report", str(tmp_path / "missing.json")])
    assert res.exit_code == 2 and "cannot read" in res.output
    newer = json.loads(FIXTURE_REPORT.read_text(encoding="utf-8"))
    newer["metadata"]["schema_version"] = 99
    p = tmp_path / "newer.json"
    p.write_text(json.dumps(newer), encoding="utf-8")
    res = runner.invoke(app, ["report", str(p)])
    assert res.exit_code == 2 and "newer" in res.output
    res = runner.invoke(app, ["report", str(FIXTURE_REPORT), "--format", "pdf"])
    assert res.exit_code == 2 and "unknown format" in res.output


@pytest.fixture
def no_html(monkeypatch):
    """Simulate a build without L-013 (stays valid after L-013 merges)."""
    monkeypatch.setitem(sys.modules, "driftwarden.report.html", None)


def test_format_html_without_l013_exits_2(no_html, pyshop_tmp, tmp_path):
    assert not renderer_available("html")
    with pytest.raises(RendererUnavailable):
        render_html(load_fixture())
    out = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(pyshop_tmp), "--out", str(out), "--format", "md,html"])
    assert res.exit_code == 2 and HTML_UNAVAILABLE in res.output
    assert not out.exists()  # failed before scanning
    res = runner.invoke(app, ["report", str(FIXTURE_REPORT), "--format", "html", "--out", str(out)])
    assert res.exit_code == 2 and HTML_UNAVAILABLE in res.output


def test_format_html_uses_l013_renderer_when_present(monkeypatch, tmp_path):
    import types

    fake = types.ModuleType("driftwarden.report.html")
    fake.render_html = lambda report: f"<html>{report.metadata.repo}</html>\n"
    monkeypatch.setitem(sys.modules, "driftwarden.report.html", fake)
    assert renderer_available("html")
    res = runner.invoke(
        app, ["report", str(FIXTURE_REPORT), "--format", "html", "--out", str(tmp_path)]
    )
    assert res.exit_code == 0, res.output
    assert (tmp_path / "driftwarden.html").read_text(encoding="utf-8") == "<html>pyshop</html>\n"


if __name__ == "__main__":  # pragma: no cover - golden regeneration helper
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--update-golden", action="store_true", help="rewrite the golden files")
    ap.add_argument("--rescan", action="store_true", help="also rebuild the fixture report")
    ns = ap.parse_args()
    if not ns.update_golden:
        ap.error("nothing to do; pass --update-golden")
    update_golden(rescan=ns.rescan)
    print(f"golden files updated in {REPORTS}")
