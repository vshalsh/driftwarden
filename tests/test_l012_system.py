"""L-012 system tests (independent of tests/test_l012_reporters.py).

Black-box-ish checks of the reporters and the ``scan --format`` / ``report`` commands:

1. SARIF: schema validity over generated reports, URI hygiene, fingerprints, limits.
2. Markdown injection: ADR text, paths, snippets etc. must not become live links, raw HTML,
   broken tables/fences, mentions, a second marker, or bidi/control characters.
3. Tamper-and-re-render through ``driftwarden report``.
4. CLI surface: ``--format``, ``--out``, output hygiene, round trip.
5. PR mode ordering and ``properties.inChange``.
6. Determinism.

Everything runs offline on the committed ``pyshop`` fixture report / repo.
"""

from __future__ import annotations

import copy
import json
import os
import posixpath
import random
import re
import shutil
import socket
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

import jsonschema
import pytest
from markdown_it import MarkdownIt
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))

from conftest import GIT_ENV  # noqa: E402
from driftwarden.cli import app  # noqa: E402
from driftwarden.config import Config  # noqa: E402
from driftwarden.grounding.ledger import Ledger  # noqa: E402
from driftwarden.pipeline import run_scan  # noqa: E402
from driftwarden.report import (  # noqa: E402
    HTML_UNAVAILABLE,
    render_json,
    render_markdown,
    render_pr_comment,
    render_sarif,
)
from driftwarden.report.markdown import (  # noqa: E402
    GITHUB_COMMENT_LIMIT,
    PR_COMMENT_MARKER,
)
from driftwarden.report.model import Report  # noqa: E402
from driftwarden.report.sarif import FINGERPRINT_KEY, MAX_BYTES, RULE_IDS  # noqa: E402
from driftwarden.report.view import canonical_path  # noqa: E402

TESTS = Path(__file__).parent
FIXTURES = TESTS / "fixtures"
FIXTURE_REPORT = FIXTURES / "report_golden" / "pyshop.report.json"
SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
SRC = Path(__file__).parent.parent / "src" / "driftwarden"
FIXED_DATE = "2026-01-01T00:00:00+00:00"
runner = CliRunner()
BASE = json.loads(FIXTURE_REPORT.read_text(encoding="utf-8"))

pytestmark = pytest.mark.filterwarnings("ignore")


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


def fx() -> dict:
    return copy.deepcopy(BASE)


def rep(d: dict) -> Report:
    return Report.model_validate(d)


def dump(d: dict) -> str:
    return json.dumps(d, ensure_ascii=False)


def subst(obj, mapping: dict[str, str]):
    """Recursively replace substrings in every string value (and dict key) of ``obj``."""
    if isinstance(obj, str):
        for a, b in mapping.items():
            obj = obj.replace(a, b)
        return obj
    if isinstance(obj, list):
        return [subst(x, mapping) for x in obj]
    if isinstance(obj, dict):
        return {subst(k, mapping): subst(v, mapping) for k, v in obj.items()}
    return obj


def claim_of(d: dict, cid: str) -> dict:
    return next(c for c in d["claims"] if c["claim"]["id"] == cid)


def clone_claim(c: dict, new_id: str, paths: dict[str, str] | None = None) -> dict:
    out = subst(copy.deepcopy(c), {c["claim"]["id"]: new_id, **(paths or {})})
    return out


def validate_sarif(text: str) -> dict:
    doc = json.loads(text)
    jsonschema.Draft4Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(doc)
    return doc


def results_of(doc: dict) -> list[dict]:
    return doc["runs"][0]["results"]


def all_locations(res: dict):
    yield from res.get("locations", [])
    yield from res.get("relatedLocations", [])


def sarif_props(doc: dict) -> dict:
    return doc["runs"][0]["properties"]["driftwarden"]


def git_run(repo: Path, *args: str) -> None:
    env = {
        **os.environ,
        **GIT_ENV,
        "GIT_AUTHOR_DATE": FIXED_DATE,
        "GIT_COMMITTER_DATE": FIXED_DATE,
    }
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


def make_pyshop(base: Path, name: str = "pyshop") -> Path:
    dest = base / name
    shutil.copytree(FIXTURES / "judge_repos" / "pyshop", dest)
    git_run(dest, "init", "-q", "-b", "main")
    git_run(dest, "config", "commit.gpgsign", "false")
    git_run(dest, "add", "-A")
    git_run(dest, "commit", "-q", "-m", "fixture")
    return dest


def run_scan_offline(repo: Path, ledger_dir: Path, **kw) -> Report:
    return run_scan(repo, config=Config(), mode="offline", ledger=Ledger(ledger_dir), **kw)


def cli(*args: str):
    return runner.invoke(app, list(args))


def out_text(result) -> str:
    text = result.output
    try:
        text += result.stderr
    except (ValueError, AttributeError):
        pass
    return text


def no_traceback(result) -> None:
    exc = result.exception
    assert exc is None or isinstance(exc, SystemExit), f"uncaught {exc!r}"
    assert "Traceback" not in out_text(result)


def md_sections(md: str) -> dict[str, str]:
    """``## Name (n)`` / ``### Name (n)`` -> section body."""
    parts = re.split(r"^#{2,3} (.+?)(?: \(\d+\))?$", md, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


# --------------------------------------------------------------------------- generators

WEIRD_PATHS = [
    "src/app.py",
    "src/my app/main module.py",
    "src/[brackets]/x[1].py",
    "src/ünïcödé/файл.py",
    "src/日本語/ファイル.py",
    "src/emoji_\U0001f600/a.py",
    "src/100%/a b#c?d.py",
    "src/{curly}/a;b,c=d&e.py",
    "src/a+b/c@d.py",
    "src/quote'\"/x.py",
    "src/tab\tname.py",
    "src/very/" + "deep/" * 30 + "f.py",
]


def gen_report(seed: int, n: int, paths=WEIRD_PATHS) -> Report:
    """A report of ``n`` cloned violated-claims with random statuses and weird paths, plus
    random could-not-verify items."""
    rng = random.Random(seed)
    d = fx()
    templates = [claim_of(d, "ADR-0001.c1"), claim_of(d, "ADR-0002.c1"), claim_of(d, "ADR-0005.c1")]
    kinds = ["only", "boundary", "require", "forbid", "free"]
    claims = []
    for i in range(n):
        t = rng.choice(templates)
        p1, p2 = rng.choice(paths), rng.choice(paths)
        mapping = {
            "requirements.txt": p1,
            "src/shop/legacy/catalog.py": p2,
            "src/shop/reports.py": p2,
            "src/shop/events.py": p2,
        }
        c = clone_claim(t, f"ADR-{1000 + i}.c{rng.randint(1, 12)}", mapping)
        c["claim"]["decision_id"] = c["claim"]["id"].split(".")[0]
        k = rng.choice(kinds)
        c["claim"]["kind"] = k
        c["claim"]["pattern"] = None
        c["claim"]["rule"] = {
            "only": {"category": "datastore", "only": ["PostgreSQL"]},
            "forbid": {"forbid": ["mongodb"]},
            "require": {"require": ["kafka"]},
            "boundary": {"target": ["boto3"], "allowed_in": ["src/adapters"]},
            "free": {"text": "something free"},
        }[k]
        st = rng.choice(["VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN"])
        c["verdict"]["status"] = st
        if rng.random() < 0.5:
            c["in_change"] = rng.choice([True, False])
        claims.append(c)
    # unique ids
    seen = set()
    for c in claims:
        cid = c["claim"]["id"]
        k = 0
        while cid in seen:
            k += 1
            cid = f"{c['claim']['id']}x{k}"
        if cid != c["claim"]["id"]:
            c.update(subst(c, {c["claim"]["id"]: cid}))
        seen.add(c["claim"]["id"])
    d["claims"] = claims
    d["decisions"] = []
    d["could_not_verify"] = []
    for i in range(rng.randint(0, 6)):
        c = rng.choice(claims) if claims else None
        d["could_not_verify"].append(
            {
                "kind": rng.choice(["verdict", "claim", "evidence", "decision"]),
                "id": f"X{i}",
                "check_id": rng.choice([None, "G1", "G2"]),
                "reasons": [rng.choice(WEIRD_PATHS) + " mismatch", "second reason"],
                "decision_id": c["claim"]["decision_id"] if c else None,
                "claim_id": c["claim"]["id"] if c else None,
                "provenance": c["claim"]["source"] if c else None,
                "proposed_status": rng.choice([None, "VIOLATED", "DRIFTING"]),
            }
        )
    return rep(d)


def many_cnv(n: int) -> Report:
    """A report holding ``n`` small could-not-verify items, each anchored at an ADR line."""
    d = fx()
    d["could_not_verify"] = [
        {
            "kind": "decision",
            "id": f"ADR-9{i:05d}",
            "check_id": "G1",
            "reasons": [f"quote not found at line {i}"],
            "decision_id": "ADR-0001",
            "claim_id": None,
            "provenance": d["decisions"][0]["source"],
            "proposed_status": None,
        }
        for i in range(n)
    ]
    return rep(d)


# =========================================================================== 1. SARIF


@pytest.mark.parametrize("seed", range(12))
def test_sarif_random_reports_validate_and_are_github_safe(seed):
    report = gen_report(seed, n=random.Random(seed).randint(1, 25))
    doc = validate_sarif(render_sarif(report))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and len(doc["runs"]) == 1
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == list(RULE_IDS)
    assert len(RULE_IDS) == 7
    for res in results_of(doc):
        assert res["ruleId"] in RULE_IDS
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert FINGERPRINT_KEY in res["partialFingerprints"]
        for loc in all_locations(res):
            pl = loc["physicalLocation"]
            uri = pl["artifactLocation"]["uri"]
            assert pl["artifactLocation"]["uriBaseId"] == "SRCROOT"
            assert not uri.startswith("/") and "\\" not in uri and not uri.startswith("./")
            assert "//" not in uri and "/./" not in uri and ".." not in uri.split("/")
            assert not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", uri), uri  # no scheme / drive
            assert " " not in uri and "[" not in uri and "]" not in uri and "\t" not in uri
            assert canonical_path(unquote(uri))
            reg = pl["region"]
            assert reg["startLine"] >= 1 and reg["endLine"] >= reg["startLine"]
            assert not ({"startColumn", "endColumn", "charOffset", "byteOffset"} & set(reg))


def test_sarif_unicode_space_bracket_paths_round_trip_percent_encoding():
    report = gen_report(3, n=30)
    doc = validate_sarif(render_sarif(report))
    wanted = {p for p in WEIRD_PATHS}
    got = {
        unquote(loc["physicalLocation"]["artifactLocation"]["uri"])
        for res in results_of(doc)
        for loc in all_locations(res)
    }
    assert got & wanted, "no weird path reached a SARIF location"
    assert got - wanted <= {
        "docs/adr/0001-postgresql-only.md",
        "docs/adr/0002-no-direct-reports.md",
        "docs/adr/0005-require-kafka.md",
    } or all(canonical_path(g) for g in got)


def test_sarif_empty_report_validates():
    d = fx()
    d.update(claims=[], decisions=[], could_not_verify=[], undocumented=[], drafts=[])
    d["unverified_claims"] = []
    doc = validate_sarif(render_sarif(rep(d)))
    assert results_of(doc) == []
    assert "truncated" not in sarif_props(doc)
    assert doc["runs"][0]["tool"]["driver"]["name"] == "DriftWarden"


def test_sarif_fixture_levels_and_no_result_for_holding_or_unknown():
    d = fx()
    report = rep(d)
    doc = validate_sarif(render_sarif(report))
    by_claim: dict[str, list[dict]] = {}
    for res in results_of(doc):
        cid = res["properties"].get("claimId")
        if cid:
            by_claim.setdefault(cid, []).append(res)
    st = {
        c["claim"]["id"]: (c["verdict"]["status"], c["verdict"]["grounding"]) for c in d["claims"]
    }
    for cid, (status, grounding) in st.items():
        rs = by_claim.get(cid, [])
        if status == "HOLDING" or (status == "UNKNOWN" and grounding == "VERIFIED"):
            assert rs == [], f"{cid} {status} must not produce a result"
        if status == "VIOLATED":
            assert [r["level"] for r in rs] == ["error"]
            assert rs[0]["ruleId"] != "could-not-verify"
        if grounding != "VERIFIED":
            assert rs and all(
                r["level"] == "note" and r["ruleId"] == "could-not-verify" for r in rs
            )
    for res in results_of(doc):
        if res["ruleId"] in ("undocumented-decision", "could-not-verify"):
            assert res["level"] == "note"
    assert any(r["level"] == "error" for r in results_of(doc))


def test_sarif_random_holding_unknown_never_produce_results():
    report = gen_report(99, n=40)
    doc = validate_sarif(render_sarif(report))
    quiet = {
        c.claim.id
        for c in report.claims
        if c.verdict
        and c.verdict.status in ("HOLDING", "UNKNOWN")
        and not c.verdict.could_not_verify
    }
    listed_cnv = {i.claim_id for i in report.could_not_verify}
    for res in results_of(doc):
        cid = res["properties"].get("claimId")
        if cid in quiet and cid not in listed_cnv:
            pytest.fail(f"{cid} produced {res['ruleId']}")


def test_sarif_could_not_verify_is_located_at_the_adr_line_only():
    d = fx()
    doc = validate_sarif(render_sarif(rep(d)))
    adr_lines = {c["claim"]["id"]: c["claim"]["source"] for c in d["claims"]}
    dec_lines = {x["id"]: x["source"] for x in d["decisions"]}
    code_paths = {
        e["ref"]["path"] for c in d["claims"] for e in (c["verdict"] or {}).get("evidence", [])
    }
    cnv = [r for r in results_of(doc) if r["ruleId"] == "could-not-verify"]
    assert cnv
    for res in cnv:
        assert len(res["locations"]) == 1 and "relatedLocations" not in res
        pl = res["locations"][0]["physicalLocation"]
        src = (
            adr_lines.get(res["properties"].get("claimId")) or dec_lines[res["properties"]["adrId"]]
        )
        assert unquote(pl["artifactLocation"]["uri"]) == src["path"]
        assert pl["region"] == {"startLine": src["line_start"], "endLine": src["line_end"]}
        assert unquote(pl["artifactLocation"]["uri"]).startswith("docs/adr/")
    tampered_only = {"tests/db_check.py"}  # evidence path that only the tampered claim cites
    for res in results_of(doc):
        for loc in all_locations(res):
            assert unquote(loc["physicalLocation"]["artifactLocation"]["uri"]) not in tampered_only
    assert code_paths  # sanity


def test_sarif_fingerprints_stable_across_two_scans_and_change_with_rule(tmp_path):
    repo = make_pyshop(tmp_path)
    a = validate_sarif(render_sarif(run_scan_offline(repo, tmp_path / "l1")))
    b = validate_sarif(render_sarif(run_scan_offline(repo, tmp_path / "l2")))
    fa = [r["partialFingerprints"][FINGERPRINT_KEY] for r in results_of(a)]
    fb = [r["partialFingerprints"][FINGERPRINT_KEY] for r in results_of(b)]
    assert fa and fa == fb
    assert len(set(fa)) == len(fa), "fingerprints must be unique per result"
    # a new commit that shifts line numbers must not change fingerprints
    f = repo / "requirements.txt"
    f.write_text("# a new first line\n# and another\n" + f.read_text(encoding="utf-8"), "utf-8")
    git_run(repo, "add", "--", "requirements.txt")
    git_run(repo, "commit", "-q", "-m", "shift lines")
    c = validate_sarif(render_sarif(run_scan_offline(repo, tmp_path / "l3")))
    assert {r["partialFingerprints"][FINGERPRINT_KEY] for r in results_of(c)} == set(fa)
    lines_a = sorted(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results_of(a)
    )
    lines_c = sorted(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results_of(c)
    )
    assert lines_a != lines_c, "the fixture edit was supposed to move a line"
    # when the rule changes, the fingerprint changes
    d = fx()
    c0 = claim_of(d, "ADR-0001.c1")
    before = results_of(validate_sarif(render_sarif(rep(d))))
    c0["claim"]["kind"] = "forbid"
    c0["claim"]["rule"] = {"forbid": ["mongodb"]}
    after = results_of(validate_sarif(render_sarif(rep(d))))
    pick = lambda rs: next(r for r in rs if r["properties"].get("claimId") == "ADR-0001.c1")  # noqa
    assert pick(before)["ruleId"] == "only" and pick(after)["ruleId"] == "forbid"
    assert (
        pick(before)["partialFingerprints"][FINGERPRINT_KEY]
        != pick(after)["partialFingerprints"][FINGERPRINT_KEY]
    )
    # and a different claim id gives a different one
    assert len({r["partialFingerprints"][FINGERPRINT_KEY] for r in before}) == len(before)


def test_sarif_truncates_by_count_and_records_a_note():
    d = fx()
    report = rep(d)
    total = len(results_of(json.loads(render_sarif(report))))
    assert total >= 5
    doc = validate_sarif(render_sarif(report, max_results=3))
    props = sarif_props(doc)
    assert len(results_of(doc)) == 3
    t = props["truncated"]
    assert t["resultsTotal"] == total and t["resultsEmitted"] == 3
    assert t["resultsDropped"] == total - 3 and "3" in t["reason"]
    # most important first: errors survive
    assert results_of(doc)[0]["level"] == "error"
    # exactly at the limit: no truncation note
    doc2 = validate_sarif(render_sarif(report, max_results=total))
    assert "truncated" not in sarif_props(doc2) and len(results_of(doc2)) == total


def test_sarif_huge_report_stays_under_github_limits_and_validates():
    report = many_cnv(25_001)  # more than GitHub's 25k results; > 10 MB once serialised
    text = render_sarif(report)
    assert len(text.encode("utf-8")) <= MAX_BYTES
    doc = validate_sarif(text)
    n = len(results_of(doc))
    t = sarif_props(doc).get("truncated")
    assert n <= 25_000
    assert t is not None, "25,001 results must be reported as truncated"
    assert t["resultsEmitted"] == n and t["resultsTotal"] >= 25_001
    assert t["resultsDropped"] == t["resultsTotal"] - n > 0
    assert "bytes" in t["reason"] or "25000" in t["reason"]


def test_sarif_only_verified_ranges_and_no_columns_anywhere():
    text = render_sarif(gen_report(5, n=20))
    assert "startColumn" not in text and "endColumn" not in text
    assert "file://" not in text


# =========================================================================== 2. Markdown injection

BIDI_CTRL = "‮evil‬ ⁦x⁩ ‎‏؜ \x1b[31m \x00 \x07 \x85     ﻿​"
PAYLOADS = {
    "js_link": "[x](javascript:alert(1)) and [y][r]\n\n[r]: javascript:alert(2)",
    "script": "<script>alert(1)</script>",
    "img": "<img src=x onerror=alert(1)> ![i](http://evil.example/a.png)",
    "pipes": "a | b | c |\n|---|---|\n| d | e |",
    "fence": "```\n# Pwned\n```\n~~~\n````",
    "mentions": "@org/team @user @everyone please review",
    "marker": "<!-- driftwarden-report -->\n<!-- driftwarden-report --> -->",
    "comment_open": "<!-- unterminated\n<!-- driftwarden-report -->",
    "bidi": BIDI_CTRL,
    "block": "# heading\n- list\n> quote\n1. num\n---\n<details><summary>x</summary>",
    "html_close": "</summary></details><h1>boo</h1>&lt;b&gt; &#64;user &amp;",
    "all": "[x](javascript:alert(1)) <script>alert(1)</script> <img onerror=alert(1)> | ``` "
    "@org/team @user <!-- driftwarden-report --> " + BIDI_CTRL,
}


def path_payload(p: str) -> str:
    p = p.replace("\x00", "").replace("\\", "")
    p = re.sub(r"/+", "/", p).strip("/")
    p = posixpath.normpath(p) or "x"
    assert canonical_path(p), repr(p)
    return p


def inject(payload: str) -> dict:
    """The fixture report with ``payload`` in every free-text field a reporter prints."""
    d = fx()
    pp = path_payload(payload)
    d = subst(
        d,
        {
            "requirements.txt": pp + ".txt",
            "src/shop/legacy/catalog.py": "src/" + pp,
            "src/shop/reports.py": "src/b/" + pp,
            "src/shop/events.py": "src/c/" + pp,
            "docs/adr/0001-postgresql-only.md": "docs/adr/" + pp,
            "pymongo==4.6.1": payload,
            "No requests library": payload,
            "PostgreSQL is the only datastore.": payload,
            "other datastore mongodb used": payload,
        },
    )
    d["metadata"]["repo"] = payload
    d["metadata"]["tool_version"] = payload
    d["metadata"]["scanned_at"] = payload
    d["metadata"]["mode"] = "offline"
    d["notes"] = [payload, payload]
    for dec in d["decisions"]:
        dec["title"] = payload
    for c in d["claims"]:
        c["verdict"]["rationale"] = payload
        c["claim"]["source"]["quote"] = payload
        c["claim"]["subject"] = payload
        for e in c["verdict"]["evidence"]:
            e["detail"] = payload
    for item in d["could_not_verify"]:
        item["reasons"] = [payload]
    d["could_not_verify"].append(
        {
            "kind": "verdict",
            "id": "ZZZ " + payload,
            "check_id": payload,
            "reasons": [payload],
            "decision_id": None,
            "claim_id": None,
            "provenance": None,
            "proposed_status": None,
        }
    )
    for u in d["undocumented"]:
        u["title"] = payload
        u["technology"] = payload
        u["category"] = payload
    for dr in d["drafts"]:
        dr["markdown"] = payload + "\n\n```\n" + payload + "\n```\n"
        dr["title"] = payload
    d["timeline"] = [
        {
            "claim_id": payload,
            "first_violating_commit": "a" * 40,
            "parent": "b" * 40,
            "date": payload,
            "subject": payload,
            "grounding": "VERIFIED",
        }
    ]
    d["grounding_summary"]["by_check"][payload] = {
        "total": 1,
        "verified": 1,
        "mismatch": 0,
        "pass_rate": 1.0,
    }
    return d


def renderings(report: Report) -> dict[str, str]:
    return {
        "full": render_markdown(report),
        "compact": render_markdown(report, compact=True),
        "pr": render_pr_comment(report),
    }


MD = MarkdownIt("commonmark", {"html": True}).enable("table")


def walk(tokens):
    for t in tokens:
        yield t
        if t.children:
            yield from walk(t.children)


def block_shape(md: str) -> list[tuple]:
    return [
        (t.type, t.tag, t.level) for t in MD.parse(md) if t.type != "inline" and t.type != "text"
    ]


def inline_active(md: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in walk(MD.parse(md)):
        if t.type in ("link_open", "image", "html_inline", "autolink"):
            counts[t.type] = counts.get(t.type, 0) + 1
    return counts


ALLOWED_HTML = re.compile(
    r"^\s*(?:<details>|</details>|<summary>[^<>]*</summary>|<!-- driftwarden-report -->)\s*$"
)


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_markdown_injection_is_inert(name):
    payload = PAYLOADS[name]
    base = renderings(rep(inject("plain text")))
    bad = renderings(rep(inject(payload)))
    for kind, md in bad.items():
        # 1. the document has exactly the same block structure as with harmless text:
        #    no broken table, no broken/forged fence, no new heading, list or quote
        assert block_shape(md) == block_shape(base[kind]), f"{kind}: structure changed"
        # 2. no live link beyond the ones the benign render has, and none to javascript:
        assert inline_active(md) == inline_active(base[kind]), f"{kind}: inline links/html/images"
        tokens = list(walk(MD.parse(md)))
        for t in tokens:
            if t.type == "link_open":
                href = t.attrGet("href")
                assert ":" not in href and not href.lower().startswith("javascript"), href
            if t.type in ("html_block", "html_inline"):
                for line in t.content.strip().splitlines():
                    assert ALLOWED_HTML.match(line), f"{kind}: raw html {line!r}"
        # 4. no mention can ping: every @ outside code is followed by the zero-width joiner
        for t in tokens:
            if t.type in ("text", "html_block") or t.type == "link_open":
                s = t.content if t.type != "link_open" else t.attrGet("href")
                assert not re.search(r"@(?![‍])\S", s), f"{kind}: live mention in {s!r}"
        # 6. size
        if kind != "full":
            assert len(md) <= GITHUB_COMMENT_LIMIT


@pytest.mark.parametrize("name", ["marker", "comment_open", "all", "html_close"])
def test_exactly_one_marker_even_when_user_text_contains_it(name):
    """The Action finds its comment by the marker: user text must never add another one,
    not even inside a code span (evidence paths and snippets are code spans)."""
    bad = renderings(rep(inject(PAYLOADS[name])))
    assert bad["pr"].count(PR_COMMENT_MARKER) == 1, "PR comment: marker count"
    assert bad["pr"].startswith(PR_COMMENT_MARKER + "\n")
    assert bad["compact"].count(PR_COMMENT_MARKER) == 0, "compact markdown: forged marker"
    assert bad["full"].count(PR_COMMENT_MARKER) == 0, "full markdown: forged marker"


@pytest.mark.parametrize("name", ["bidi", "all"])
def test_no_bidi_control_or_invisible_characters_in_markdown(name):
    for kind, md in renderings(rep(inject(PAYLOADS[name]))).items():
        for ch in md:
            cat = unicodedata.category(ch)
            assert not (cat == "Cc" and ch != "\n"), f"{kind}: control {ch!r}"
            assert not (cat in ("Cf", "Zl", "Zp") and ch != "\u200d"), f"{kind}: format {ch!r}"


def test_markdown_mentions_in_code_free_text_get_joiner():
    md = render_markdown(rep(inject("@org/team and @user")))
    outside_code = re.sub(r"(?ms)^(`{3,}).*?^\1`*$", "", md)  # fenced blocks
    outside_code = re.sub(r"`[^`\n]*`", "", outside_code)  # GitHub does not ping in code
    assert "@org/team" not in outside_code and "@user" not in outside_code
    assert "@\u200dorg" in md and "@\u200duser" in md


def test_markdown_table_cells_cannot_be_split_by_pipes_in_every_table():
    """Header table (repo, commit, mode...), summary table, grounding and timeline tables."""
    d = inject("a|b|c")
    d["metadata"]["commit"] = "abc|def|ghi"
    md = render_markdown(rep(d))
    html = MD.render(md)
    for table in re.findall(r"<table>.*?</table>", html, flags=re.S):
        widths = {
            len(re.findall(r"<t[hd]\b", row))
            for row in re.findall(r"<tr>.*?</tr>", table, flags=re.S)
        }
        assert len(widths) == 1, f"ragged table: {widths}\n{table[:400]}"
    # the commit text must sit inside one cell, not leak into extra columns
    assert "abc|def|ghi" not in md.replace(
        "`abc|def|ghi`", ""
    )  # only inside a code span, if at all
    header = md.split("\n## Summary")[0]
    for line in header.splitlines():
        if line.startswith("| Commit"):
            unescaped = re.findall(r"(?<!\\)\|", line)
            assert len(unescaped) == 3, f"commit row has {len(unescaped)} unescaped pipes: {line!r}"


def test_markdown_urls_and_issue_refs_do_not_autolink_on_github():
    """GitHub autolinks bare URLs, www. hosts, #123 and owner/repo#1 found in comment text
    (outside code spans). Attacker text must not become a live link or cross-reference."""
    payload = "see https://evil.example/phish and www.evil.example and #123 and owner/repo#5"
    md = render_pr_comment(rep(inject(payload)))
    live = re.compile(r"https?://|www\.|(?<![\w&])#\d+|[\w.-]+/[\w.-]+#\d+|\bGH-\d+")
    for t in walk(MD.parse(md)):
        if t.type == "text":
            assert not live.search(t.content), f"autolinkable text: {t.content!r}"


def test_esc_neutralises_every_markdown_special_in_every_position():
    from driftwarden.report.markdown import code, esc

    for ch in "\\`*_[]<>&|~$!#@":
        for text in (ch, ch * 3, f"a{ch}b", f"{ch}a", f"{ch}[x](y)"):
            html = MD.render("- " + esc(text) + "\n")
            assert "<script" not in html and "<a " not in html and "<img" not in html
    for s in ("a`b", "``", "`", "x ` y ``` z", "|", "<!-- driftwarden-report -->"):
        html = MD.render(code(s))
        assert html.count("<code>") == 1, (s, html)


def test_compact_and_pr_comment_fit_with_10k_findings():
    d = fx()
    tpl = [claim_of(d, "ADR-0001.c1"), claim_of(d, "ADR-0002.c1"), claim_of(d, "ADR-0005.c1")]
    long = "very long rationale " * 200
    claims = []
    for i in range(10_000):
        c = clone_claim(tpl[i % 3], f"ADR-{i:05d}.c1")
        c["claim"]["decision_id"] = f"ADR-{i:05d}"
        c["verdict"]["rationale"] = long
        c["claim"]["source"]["quote"] = long
        c["verdict"]["status"] = ("VIOLATED", "DRIFTING", "HOLDING", "UNKNOWN")[i % 4]
        c["in_change"] = bool(i % 2)
        claims.append(c)
    d["claims"] = claims
    d["metadata"]["changed_paths"] = ["a.py"]
    d["could_not_verify"] = [
        {
            "kind": "verdict",
            "id": f"ADR-{i:05d}.c1",
            "check_id": "G2",
            "reasons": [long] * 5,
            "decision_id": f"ADR-{i:05d}",
            "claim_id": f"ADR-{i:05d}.c1",
            "provenance": claims[i]["claim"]["source"],
            "proposed_status": "VIOLATED",
        }
        for i in range(10_000)
    ]
    d["notes"] = [long] * 500
    report = rep(d)
    del d, claims
    for md in (render_pr_comment(report), render_markdown(report, compact=True)):
        assert len(md) <= GITHUB_COMMENT_LIMIT, len(md)
        assert md.count("<details>") == md.count("</details>")
        assert md.count("```") % 2 == 0
        assert "more" in md
    pr = render_pr_comment(report)
    assert pr.count(PR_COMMENT_MARKER) == 1 and pr.startswith(PR_COMMENT_MARKER)
    full = render_markdown(report)
    assert len(full) > GITHUB_COMMENT_LIMIT  # the full report is not limited


def test_pr_comment_last_resort_cut_keeps_marker_and_balanced_blocks():
    d = fx()
    for i in range(4000):  # an unbounded table the ladder cannot shrink
        d["grounding_summary"]["by_check"][f"CHECK-{i:05d}-" + "x" * 30] = {
            "total": 1,
            "verified": 1,
            "mismatch": 0,
            "pass_rate": 1.0,
        }
    md = render_pr_comment(rep(d))
    assert len(md) <= GITHUB_COMMENT_LIMIT
    assert md.count(PR_COMMENT_MARKER) == 1 and md.startswith(PR_COMMENT_MARKER)
    assert md.count("<details>") == md.count("</details>")
    assert md.count("```") % 2 == 0
    assert "truncated" in md


# =========================================================================== 3. Tamper + re-render


def report_cli(tmp_path: Path, data: dict | str | bytes, fmts="json,md,sarif", name="in.json"):
    src = tmp_path / name
    if isinstance(data, dict):
        src.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif isinstance(data, bytes):
        src.write_bytes(data)
    else:
        src.write_text(data, encoding="utf-8")
    out = tmp_path / "out"
    r = cli("report", str(src), "--format", fmts, "--out", str(out))
    return r, out


def read_out(out: Path, ext: str) -> str:
    return (out / f"driftwarden.{ext}").read_text(encoding="utf-8")


def assert_demoted(tmp_path, d: dict, claim_id: str, forbidden_paths=(), fmts="md,sarif"):
    """Re-render the edited ``d`` through the CLI; ``claim_id`` must be Could not verify only."""
    r, out = report_cli(tmp_path, d, fmts)
    no_traceback(r)
    assert r.exit_code == 0, out_text(r)
    if "md" in fmts:
        md = read_out(out, "md")
        secs = md_sections(md)
        for name in ("Violated", "Drifting", "Holding", "Unknown"):
            assert f"**{claim_id}**" not in secs.get(name, ""), f"{claim_id} shown under {name}"
        assert claim_id in secs["Could not verify"].replace("\\", ""), "not listed under CNV"
        for p in forbidden_paths:
            for name in ("Violated", "Drifting", "Holding", "Unknown"):
                assert p not in secs.get(name, ""), f"{p} shown as evidence under {name}"
    if "sarif" in fmts:
        doc = validate_sarif(read_out(out, "sarif"))
        mine = [
            x
            for x in results_of(doc)
            if x["properties"].get("claimId") == claim_id
            or x["properties"].get("itemId") == claim_id
        ]
        unlocated = " ".join(sarif_props(doc).get("unlocated", []))
        assert mine or claim_id in unlocated, "tampered claim vanished from SARIF"
        for x in mine:
            assert x["ruleId"] == "could-not-verify" and x["level"] == "note", x["ruleId"]
        for x in results_of(doc):
            if x["level"] in ("error", "warning"):
                assert x["properties"].get("claimId") != claim_id
                for loc in all_locations(x):
                    uri = unquote(loc["physicalLocation"]["artifactLocation"]["uri"])
                    assert uri not in forbidden_paths
    if "json" in fmts:
        rr = json.loads(read_out(out, "json"))
        shown = [
            c
            for c in rr["claims"]
            if c["claim"]["id"] == claim_id
            and c["verdict"]
            and c["verdict"]["status"] in ("VIOLATED", "DRIFTING")
            and c["verdict"]["grounding"] == "VERIFIED"
        ]
        assert not shown, "re-rendered JSON still carries the tampered claim as a VERIFIED finding"
        assert any(
            i["claim_id"] == claim_id or i["id"] == claim_id for i in rr["could_not_verify"]
        ), "re-rendered JSON does not list it under could_not_verify"
    return out


def violated(d: dict, cid: str) -> dict:
    c = claim_of(d, cid)
    assert c["verdict"]["status"] == "VIOLATED"
    return c


def test_untouched_fixture_rerenders_without_demotions(tmp_path):
    r, out = report_cli(tmp_path, fx())
    assert r.exit_code == 0, out_text(r)
    secs = md_sections(read_out(out, "md"))
    assert "**ADR-0005.c1**" in secs["Violated"] and "**ADR-0001.c1**" in secs["Violated"]
    assert "report-time evidence re-check" not in read_out(out, "md")


def _flip_mismatch(d):
    v = claim_of(d, "ADR-0003.c1")["verdict"]
    v.update(status="VIOLATED", grounding="VERIFIED", reasons=[], proposed_status=None)


def _delete_g2(d):
    c = violated(d, "ADR-0002.c1")
    c["verdict"]["checks"] = [x for x in c["verdict"]["checks"] if x["check_id"] != "G2"]


def _edit_path(d):
    violated(d, "ADR-0002.c1")["verdict"]["evidence"][0]["ref"]["path"] = "src/shop/other.py"


def _fake_claim(d):
    fake = clone_claim(claim_of(d, "ADR-0002.c1"), "ADR-0002.c9")
    fake["verdict"]["checks"] = []
    d["claims"].append(fake)


@pytest.mark.parametrize(
    "tamper,cid",
    [
        (_flip_mismatch, "ADR-0003.c1"),
        (_delete_g2, "ADR-0002.c1"),
        (_edit_path, "ADR-0002.c1"),
        (_fake_claim, "ADR-0002.c9"),
    ],
)
def test_tampered_json_rerendered_as_json_never_keeps_a_verified_finding(tmp_path, tamper, cid):
    """`driftwarden report --format json` of an edited file must not hand the unverified
    claim on as a VERIFIED VIOLATED/DRIFTING verdict (consumers read exit_code/by_status)."""
    d = fx()
    tamper(d)
    r, out = report_cli(tmp_path, d, "json")
    no_traceback(r)
    assert r.exit_code == 0, out_text(r)
    rr = json.loads(read_out(out, "json"))
    shown = [
        c
        for c in rr["claims"]
        if c["claim"]["id"] == cid
        and c["verdict"]
        and c["verdict"]["status"] in ("VIOLATED", "DRIFTING")
        and c["verdict"]["grounding"] == "VERIFIED"
    ]
    assert not shown, "re-rendered JSON still carries the tampered claim as a VERIFIED finding"
    assert any(i["claim_id"] == cid or i["id"] == cid for i in rr["could_not_verify"])


def test_tamper_flip_mismatch_to_verified_keeping_the_mismatch_row(tmp_path):
    d = fx()
    v = claim_of(d, "ADR-0003.c1")["verdict"]
    v.update(status="DRIFTING", grounding="VERIFIED", reasons=[], proposed_status=None)
    assert_demoted(tmp_path, d, "ADR-0003.c1", ["tests/db_check.py"])


def test_tamper_flip_mismatch_to_verified_with_no_ledger_record(tmp_path):
    d = fx()
    v = claim_of(d, "ADR-0003.c1")["verdict"]
    v.update(status="VIOLATED", grounding="VERIFIED", reasons=[], proposed_status=None)
    v["checks"] = []
    d["could_not_verify"] = [i for i in d["could_not_verify"] if i["claim_id"] != "ADR-0003.c1"]
    assert_demoted(tmp_path, d, "ADR-0003.c1", ["tests/db_check.py"])


def test_tamper_flip_mismatch_row_status_but_row_for_other_evidence(tmp_path):
    """Rows for e1 exist and are VERIFIED, but e2 (also shown) has none."""
    d = fx()
    v = claim_of(d, "ADR-0003.c1")["verdict"]
    v.update(status="VIOLATED", grounding="VERIFIED", reasons=[], proposed_status=None)
    v["checks"] = [
        dict(c, status="VERIFIED") for c in v["checks"] if c["subject"] == "ADR-0003.c1/e1"
    ]
    assert_demoted(tmp_path, d, "ADR-0003.c1")


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "src/shop/other.py"),
        ("path", "../../etc/passwd"),
        ("path", "/etc/passwd"),
        ("path", "./src/shop/reports.py"),
        ("path", "src\\shop\\reports.py"),
        ("path", "src/shop//reports.py"),
        ("path", ""),
        ("line_start", 0),
        ("line_start", -3),
        ("line_start", 6),
        ("line_end", 99),
        ("commit", "0" * 40),
        ("commit", "WORKTREE"),
        ("quote", "totally different text"),
    ],
)
def test_tamper_evidence_location_edited_after_the_scan(tmp_path, field, value):
    d = fx()
    c = violated(d, "ADR-0002.c1")
    c["verdict"]["evidence"][0]["ref"][field] = value
    paths = [value] if field == "path" else []
    assert_demoted(tmp_path, d, "ADR-0002.c1", [p for p in paths if p])


def test_tamper_evidence_location_edited_consistently_in_ref_and_row_stays_safe(tmp_path):
    """An attacker who also edits the G2 row to match, with an unsafe path/line."""
    d = fx()
    c = violated(d, "ADR-0002.c1")
    for ref in (c["verdict"]["evidence"][0]["ref"], c["verdict"]["checks"][0]["provenance"]):
        ref["path"] = "../../etc/shadow"
        ref["line_start"] = 0
    assert_demoted(tmp_path, d, "ADR-0002.c1", ["../../etc/shadow"])


def test_tamper_commit_edited_consistently_is_not_the_judged_commit(tmp_path):
    d = fx()
    c = violated(d, "ADR-0002.c1")
    for ref in (c["verdict"]["evidence"][0]["ref"], c["verdict"]["checks"][0]["provenance"]):
        ref["commit"] = "f" * 40
    assert_demoted(tmp_path, d, "ADR-0002.c1")


def test_tamper_delete_g2_record(tmp_path):
    d = fx()
    c = violated(d, "ADR-0002.c1")
    c["verdict"]["checks"] = [x for x in c["verdict"]["checks"] if x["check_id"] != "G2"]
    assert_demoted(tmp_path, d, "ADR-0002.c1", ["src/shop/reports.py"])


def test_tamper_delete_g3_record_of_a_dependency_item(tmp_path):
    d = fx()
    c = violated(d, "ADR-0001.c1")
    c["verdict"]["checks"] = [x for x in c["verdict"]["checks"] if x["check_id"] != "G3"]
    assert_demoted(tmp_path, d, "ADR-0001.c1")


def test_tamper_dependency_package_edited(tmp_path):
    d = fx()
    c = violated(d, "ADR-0001.c1")
    c["verdict"]["evidence"][0]["dependency"]["package"] = "left-pad"
    assert_demoted(tmp_path, d, "ADR-0001.c1")


def test_tamper_extra_evidence_item_without_a_record(tmp_path):
    d = fx()
    c = violated(d, "ADR-0005.c1")
    extra = copy.deepcopy(c["verdict"]["evidence"][1])
    extra["id"] = "e9"
    extra["ref"]["path"] = "src/planted.py"
    c["verdict"]["evidence"].append(extra)
    assert_demoted(tmp_path, d, "ADR-0005.c1", ["src/planted.py"])


def test_tamper_row_demoted_to_mismatch_for_one_evidence_item(tmp_path):
    d = fx()
    c = violated(d, "ADR-0005.c1")
    c["verdict"]["checks"][0]["status"] = "MISMATCH"
    assert_demoted(tmp_path, d, "ADR-0005.c1")


@pytest.mark.parametrize("variant", ["no_checks", "miskeyed_checks", "unknown_decision"])
def test_tamper_fake_violated_claim_added(tmp_path, variant):
    d = fx()
    fake = clone_claim(claim_of(d, "ADR-0002.c1"), "ADR-0099.c1")
    fake["claim"]["decision_id"] = "ADR-0099"
    if variant == "no_checks":
        fake["verdict"]["checks"] = []
    elif variant == "miskeyed_checks":
        for ch in fake["verdict"]["checks"]:
            ch["subject"] = "ADR-0002.c1/e1"  # rows that belong to another claim
    else:
        fake["claim"]["decision_id"] = "ADR-4242"
        fake["verdict"]["checks"] = []
    fake["verdict"]["evidence"][0]["ref"]["path"] = "src/fake_violation.py"
    d["claims"].append(fake)
    assert_demoted(tmp_path, d, "ADR-0099.c1", ["src/fake_violation.py"])
    pr = render_pr_comment(rep(d))
    assert "**ADR-0099.c1**" not in md_sections(pr).get("Violated", "")


def test_tamper_fake_undocumented_record_is_not_shown(tmp_path):
    d = fx()
    fake = copy.deepcopy(d["undocumented"][0])
    fake["id"] = "UD-fake-1"
    fake["checks"] = []
    d["undocumented"].append(fake)
    r, out = report_cli(tmp_path, d)
    assert r.exit_code == 0, out_text(r)
    secs = md_sections(read_out(out, "md"))
    assert "UD-fake-1" not in secs["Undocumented decisions"]
    assert "UD-fake-1" in secs["Could not verify"]
    doc = validate_sarif(read_out(out, "sarif"))
    assert not [
        x
        for x in results_of(doc)
        if x["ruleId"] == "undocumented-decision" and x["properties"].get("recordId") == "UD-fake-1"
    ]


def test_tamper_absolute_adr_path_never_becomes_a_sarif_uri(tmp_path):
    d = fx()
    for c in d["claims"]:
        c["claim"]["source"]["path"] = "/etc/passwd"
    r, out = report_cli(tmp_path, d, "sarif,md")
    assert r.exit_code == 0, out_text(r)
    doc = validate_sarif(read_out(out, "sarif"))
    for res in results_of(doc):
        for loc in all_locations(res):
            assert not loc["physicalLocation"]["artifactLocation"]["uri"].startswith(("/", "%2F"))


@pytest.mark.parametrize(
    "content,needle",
    [
        ("", ""),
        ("{", ""),
        ('{"metadata": {"tool": "driftwarden"', ""),
        ("[]", ""),
        ("null", ""),
        ("{}", ""),
        ('{"metadata": 5}', ""),
        ("[" * 200000, ""),
        ("\x00\x01\x02not json", ""),
        (b"\xff\xfe\xfa binary", ""),
        (json.dumps(BASE)[:-40], ""),  # truncated mid-document
    ],
)
def test_malformed_saved_json_exits_2_with_a_message_not_a_traceback(tmp_path, content, needle):
    r, out = report_cli(tmp_path, content)
    no_traceback(r)
    assert r.exit_code == 2, out_text(r)
    text = out_text(r)
    assert "error" in text.lower() and len(text.strip()) > 10
    assert not (out / "driftwarden.md").exists()


def test_report_missing_file_and_directory_exit_2(tmp_path):
    for target in (tmp_path / "nope.json", tmp_path):
        r = cli("report", str(target), "--format", "md", "--out", str(tmp_path / "o"))
        no_traceback(r)
        assert r.exit_code == 2, out_text(r)


def test_report_newer_schema_version_exits_2(tmp_path):
    d = fx()
    d["metadata"]["schema_version"] = 99
    r, _ = report_cli(tmp_path, d)
    no_traceback(r)
    assert r.exit_code == 2 and "schema version" in out_text(r)


def test_report_invalid_model_exits_2_when_a_violated_verdict_has_no_evidence(tmp_path):
    d = fx()
    violated(d, "ADR-0002.c1")["verdict"]["evidence"] = []
    r, out = report_cli(tmp_path, d)
    no_traceback(r)
    # Either rejected by the model (2) or re-rendered with the claim under Could not verify.
    assert r.exit_code in (0, 2)
    if r.exit_code == 0:
        assert "**ADR-0002.c1**" not in md_sections(read_out(out, "md")).get("Violated", "")


# =========================================================================== 4. CLI


@pytest.fixture
def repo(tmp_path):
    return make_pyshop(tmp_path)


def scan_cli(repo: Path, *args: str):
    return cli("scan", str(repo), "--mode", "offline", *args)


def test_format_writes_exactly_the_requested_files(repo, tmp_path):
    for fmts, want in [
        ("json", {"driftwarden.json"}),
        ("md", {"driftwarden.md"}),
        ("sarif", {"driftwarden.sarif"}),
        ("md,sarif", {"driftwarden.md", "driftwarden.sarif"}),
        ("json,md,sarif", {"driftwarden.json", "driftwarden.md", "driftwarden.sarif"}),
        ("sarif,json,sarif", {"driftwarden.json", "driftwarden.sarif"}),
        ("MD, Json", {"driftwarden.json", "driftwarden.md"}),
    ]:
        out = tmp_path / ("o-" + re.sub(r"\W", "", fmts))
        r = scan_cli(repo, "--format", fmts, "--out", str(out))
        no_traceback(r)
        assert r.exit_code in (0, 1, 3), out_text(r)
        files = {p.name for p in out.iterdir() if p.is_file()}
        assert files == want, (fmts, files)
        assert not list(out.glob(".*.tmp")) and not list(out.glob("*.tmp"))
        assert (out / "logs").is_dir()  # the ledger is the only other thing there


def test_no_format_writes_no_report_file(repo, tmp_path):
    out = tmp_path / "o"
    r = scan_cli(repo, "--out", str(out))
    assert r.exit_code in (0, 1, 3)
    assert not [p for p in out.iterdir() if p.is_file()]


@pytest.mark.parametrize("fmt", ["xml", "json,xml", "pdf", "md;sarif", "sarif,txt", "*"])
def test_unknown_format_exits_2_and_writes_nothing(repo, tmp_path, fmt):
    out = tmp_path / "o"
    r = scan_cli(repo, "--format", fmt, "--out", str(out))
    no_traceback(r)
    assert r.exit_code == 2, out_text(r)
    assert "unknown format" in out_text(r).lower() or "invalid" in out_text(r).lower()
    assert not out.exists() or not [p for p in out.iterdir() if p.is_file()]
    src = fx()
    j = tmp_path / "r.json"
    j.write_text(json.dumps(src), "utf-8")
    r2 = cli("report", str(j), "--format", fmt, "--out", str(tmp_path / "o2"))
    no_traceback(r2)
    assert r2.exit_code == 2
    assert not (tmp_path / "o2").exists()


def test_html_is_unavailable_on_this_branch_and_exits_2_before_any_work(repo, tmp_path):
    assert not (SRC / "report" / "html").exists() and not (SRC / "report" / "html.py").exists()
    out = tmp_path / "o"
    r = scan_cli(repo, "--format", "md,html", "--out", str(out))
    no_traceback(r)
    assert r.exit_code == 2
    assert HTML_UNAVAILABLE in out_text(r).replace("\n", " ")
    assert not out.exists() or not list(out.iterdir()), "work was done before the html check"
    j = tmp_path / "r.json"
    j.write_text(json.dumps(fx()), "utf-8")
    r2 = cli("report", str(j), "--format", "html", "--out", str(tmp_path / "o2"))
    no_traceback(r2)
    assert r2.exit_code == 2 and HTML_UNAVAILABLE in out_text(r2).replace("\n", " ")
    assert not (tmp_path / "o2").exists()
    r3 = cli("report", str(j), "--format", "md,html", "--out", str(tmp_path / "o3"))
    assert r3.exit_code == 2 and not (tmp_path / "o3" / "driftwarden.md").exists()


def test_report_requires_a_format_that_is_not_empty(tmp_path):
    j = tmp_path / "r.json"
    j.write_text(json.dumps(fx()), "utf-8")
    r = cli("report", str(j), "--format", "", "--out", str(tmp_path / "o"))
    no_traceback(r)
    assert r.exit_code == 2


def test_default_out_is_repo_dot_driftwarden_and_does_not_dirty_the_repo(repo):
    r = scan_cli(repo, "--format", "md,json,sarif")
    assert r.exit_code in (0, 1, 3), out_text(r)
    d = repo / ".driftwarden"
    assert {"driftwarden.md", "driftwarden.json", "driftwarden.sarif"} <= {
        p.name for p in d.iterdir()
    }
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
    ).stdout
    assert status.strip() == "", f"scan dirtied the repo:\n{status}"
    assert "Wrote md" in out_text(r)


def test_report_default_out_is_the_directory_of_the_saved_json(tmp_path):
    sub = tmp_path / "saved"
    sub.mkdir()
    j = sub / "r.json"
    j.write_text(json.dumps(fx()), "utf-8")
    r = cli("report", str(j), "--format", "md,sarif")
    assert r.exit_code == 0, out_text(r)
    assert {p.name for p in sub.iterdir()} == {"r.json", "driftwarden.md", "driftwarden.sarif"}
    # default format is md
    sub2 = tmp_path / "s2"
    sub2.mkdir()
    (sub2 / "r.json").write_text(json.dumps(fx()), "utf-8")
    assert cli("report", str(sub2 / "r.json")).exit_code == 0
    assert {p.name for p in sub2.iterdir()} == {"r.json", "driftwarden.md"}


def test_printed_output_paths_are_safe_no_raw_control_characters(repo, tmp_path):
    nasty = tmp_path / "o\x1b[31m‮EVIL\x07\nspoof​[red]x[/red]"
    r = scan_cli(
        repo,
        "--format",
        "md,json",
        "--out",
        str(nasty),
        "--json-out",
        str(tmp_path / "j\x1b]8;;http://x\x07.json"),
    )
    no_traceback(r)
    assert r.exit_code in (0, 1, 3), out_text(r)
    text = out_text(r)
    assert "Wrote md" in text and "Wrote json" in text
    for ch in text:
        cat = unicodedata.category(ch)
        assert not (cat in ("Cc", "Cf", "Zl", "Zp") and ch not in "\n"), f"raw {ch!r}"
    assert "\x1b" not in text
    j = tmp_path / "r.json"
    j.write_text(json.dumps(fx()), "utf-8")
    r2 = cli("report", str(j), "--format", "md", "--out", str(nasty))
    text2 = out_text(r2)
    assert r2.exit_code == 0 and "Wrote md" in text2
    assert "\x1b" not in text2 and "\x07" not in text2 and "‮" not in text2
    # an unwritable target is also reported without raw controls
    blocker = tmp_path / "blocker\x1b[1m"
    blocker.write_text("file", "utf-8")
    r3 = cli("report", str(j), "--format", "md", "--out", str(blocker / "sub"))
    no_traceback(r3)
    assert r3.exit_code == 2 and "\x1b" not in out_text(r3)


def test_round_trip_scan_json_report_equals_direct_scan_output(repo, tmp_path):
    direct = tmp_path / "direct"
    r = scan_cli(
        repo,
        "--format",
        "json,md,sarif",
        "--out",
        str(direct),
        "--json-out",
        str(tmp_path / "jo.json"),
    )
    assert r.exit_code in (0, 1, 3), out_text(r)
    # --json-out goes through render_json: same bytes as --format json
    assert (tmp_path / "jo.json").read_bytes() == (direct / "driftwarden.json").read_bytes()
    saved = direct / "driftwarden.json"
    rt = tmp_path / "rt"
    r2 = cli("report", str(saved), "--format", "json,md,sarif", "--out", str(rt))
    assert r2.exit_code == 0, out_text(r2)
    for ext in ("json", "md", "sarif"):
        a = (direct / f"driftwarden.{ext}").read_bytes()
        b = (rt / f"driftwarden.{ext}").read_bytes()
        assert a == b, f"{ext} differs after round trip"
    # and the JSON is the canonical render of its own parse
    text = saved.read_text("utf-8")
    assert text == render_json(Report.model_validate_json(text))
    validate_sarif((rt / "driftwarden.sarif").read_text("utf-8"))


def test_round_trip_of_the_rich_fixture_is_identical_and_idempotent(tmp_path):
    j = tmp_path / "f.json"
    j.write_text(render_json(rep(fx())), "utf-8")
    r = rep(fx())
    a = tmp_path / "a"
    assert cli("report", str(j), "--format", "json,md,sarif", "--out", str(a)).exit_code == 0
    assert (a / "driftwarden.md").read_text("utf-8") == render_markdown(r)
    assert (a / "driftwarden.sarif").read_text("utf-8") == render_sarif(r)
    b = tmp_path / "b"
    assert (
        cli(
            "report", str(a / "driftwarden.json"), "--format", "json,md,sarif", "--out", str(b)
        ).exit_code
        == 0
    )
    for ext in ("json", "md", "sarif"):
        assert (a / f"driftwarden.{ext}").read_bytes() == (b / f"driftwarden.{ext}").read_bytes()


def test_json_out_unwritable_exits_2_without_traceback(repo, tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("x", "utf-8")
    r = scan_cli(repo, "--out", str(tmp_path / "o"), "--json-out", str(blocker / "x.json"))
    no_traceback(r)
    assert r.exit_code == 2


# =========================================================================== 5. PR mode


def test_pr_mode_comment_lists_in_change_violations_first_and_sarif_has_inchange(tmp_path):
    repo = make_pyshop(tmp_path)
    plain = run_scan_offline(repo, tmp_path / "l0")
    viol = [c.claim.id for c in plain.verdicts("VIOLATED")]
    assert len(viol) >= 3, viol
    last = sorted(viol, key=lambda s: (len(s), s))[-1]
    changed = {
        "ADR-0005.c1": "src/shop/events.py",
        "ADR-0002.c1": "src/shop/reports.py",
        "ADR-0001.c1": "src/shop/legacy/catalog.py",
    }[last]
    report = run_scan_offline(repo, tmp_path / "l1", changed_paths=[changed])
    touched = [c.claim.id for c in report.claims if c.in_change]
    untouched = [c.claim.id for c in report.claims if c.in_change is False]
    assert last in touched and untouched, (touched, untouched)
    first_untouched_viol = next(v for v in viol if v in untouched)
    assert viol.index(last) > viol.index(first_untouched_viol), "need an in-change id sorted last"

    pr = render_pr_comment(report)
    secs = md_sections(pr)
    mine = secs["Violated in this change"]
    before = secs["Already present before this change"]
    assert f"**{last}**" in mine and f"**{last}**" not in before
    assert pr.index("Violated in this change") < pr.index("Already present before this change")
    assert pr.index(f"**{last}**") < pr.index(f"**{first_untouched_viol}**")
    for v in viol:
        assert (f"**{v}**" in mine) == (v in touched), v
    assert pr.count(PR_COMMENT_MARKER) == 1

    full = render_markdown(report)
    assert full.index(f"**{last}**") < full.index(f"**{first_untouched_viol}**")
    assert "in this change" in full and "present before this change" in full

    doc = validate_sarif(render_sarif(report))
    flags = {
        r["properties"]["claimId"]: r["properties"]["inChange"]
        for r in results_of(doc)
        if r["ruleId"] != "undocumented-decision" and "inChange" in r["properties"]
    }
    for cid in viol:
        assert flags[cid] == (cid in touched), cid
    for res in results_of(doc):
        if (
            res["ruleId"] not in ("undocumented-decision",)
            and res["properties"].get("claimId") in viol
        ):
            assert isinstance(res["properties"]["inChange"], bool)

    # outside PR mode: no inChange anywhere, no PR sections
    doc0 = validate_sarif(render_sarif(plain))
    assert not [r for r in results_of(doc0) if "inChange" in r["properties"]]
    assert "Violated in this change" not in render_pr_comment(plain)


def test_pr_mode_cannot_hide_a_violation_that_is_not_in_the_change(tmp_path):
    repo = make_pyshop(tmp_path)
    (repo / "NOTES.txt").write_text("unrelated\n", "utf-8")  # exists, so it is not "deleted"
    git_run(repo, "add", "--", "NOTES.txt")
    git_run(repo, "commit", "-q", "-m", "notes")
    plain = run_scan_offline(repo, tmp_path / "l0")
    report = run_scan_offline(repo, tmp_path / "l1", changed_paths=["NOTES.txt"])
    assert {c.claim.id for c in report.verdicts("VIOLATED")} == {
        c.claim.id for c in plain.verdicts("VIOLATED")
    }
    pr = render_pr_comment(report)
    for c in plain.verdicts("VIOLATED"):
        assert f"**{c.claim.id}**" in md_sections(pr)["Already present before this change"]
        assert next(x for x in report.claims if x.claim.id == c.claim.id).in_change is False
    assert md_sections(pr)["Violated in this change"].strip().endswith("None.")


# =========================================================================== 6. Determinism

SCANNED = re.compile(r"\d{4}-\d\d-\d\dT[\d:.]+(?:Z|\+00:00)")


def test_two_offline_runs_are_byte_identical_apart_from_scanned_at(repo, tmp_path):
    outs = []
    for i in range(2):
        out = tmp_path / f"run{i}"
        r = scan_cli(repo, "--format", "json,md,sarif", "--out", str(out))
        assert r.exit_code in (0, 1, 3), out_text(r)
        outs.append(out)
    a, b = outs
    for ext in ("json", "md", "sarif"):
        ta = (a / f"driftwarden.{ext}").read_text("utf-8")
        tb = (b / f"driftwarden.{ext}").read_text("utf-8")
        na = SCANNED.sub("<T>", ta)
        nb = SCANNED.sub("<T>", tb)
        assert na == nb, f"{ext} differs beyond scanned_at"
        if ext == "json":
            ja, jb = json.loads(ta), json.loads(tb)
            ja["metadata"].pop("scanned_at"), jb["metadata"].pop("scanned_at")
            assert ja == jb
        # nothing machine-specific leaks into reports (absolute path of the repo or ledger)
        assert str(tmp_path) not in ta, f"{ext} leaks an absolute path"


def test_render_functions_are_pure_and_repeatable():
    r = rep(fx())
    for fn in (render_json, render_markdown, render_pr_comment, render_sarif):
        assert fn(r) == fn(r) == fn(rep(fx()))
    before = r.model_dump_json()
    render_sarif(r), render_markdown(r, compact=True)
    assert r.model_dump_json() == before, "a renderer mutated the report"
