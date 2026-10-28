"""L-015: seeded-fixture benchmark (G7): corpus determinism, truth/file agreement, scorer maths."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import run as bench_run  # noqa: E402
from bench import score as S  # noqa: E402
from bench.build_corpus import (  # noqa: E402
    MIN_RECORDS,
    MIN_REPOS,
    REPOS,
    TRUTH_DIR,
    build_corpus,
    summary,
    write_truth,
)

SHA = re.compile(r"^[0-9a-f]{40}$")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench-corpus")
    t0 = time.perf_counter()
    truths = build_corpus(out)
    elapsed = time.perf_counter() - t0
    return out, truths, elapsed


# --------------------------------------------------------------------------- corpus


def test_build_is_fast(corpus):
    assert corpus[2] < 60, f"corpus build took {corpus[2]:.1f}s"


def test_corpus_deterministic(corpus, tmp_path, monkeypatch):
    """Same SHAs across two builds, even with a hostile caller environment."""
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Mallory")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2001-01-01T00:00:00 +0000")
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    second = build_corpus(tmp_path / "again")
    first = corpus[1]
    assert sorted(first) == sorted(second) == sorted(REPOS)
    for name in REPOS:
        assert first[name]["head"] == second[name]["head"], name
        assert first[name] == second[name], name
        # and the SHA on disk is the SHA in the label
        assert _git(tmp_path / "again" / name, "rev-parse", "HEAD").strip() == second[name]["head"]


def test_build_replaces_existing_directory(corpus, tmp_path):
    """Re-running into a non-empty directory must not append history."""
    a = build_corpus(tmp_path, ["shopfront"])
    b = build_corpus(tmp_path, ["shopfront"])
    assert a["shopfront"]["head"] == b["shopfront"]["head"]
    n = int(_git(tmp_path / "shopfront", "rev-list", "--count", "HEAD").strip())
    assert n == b["shopfront"]["commits"]


def test_committed_truth_matches_fresh_build(corpus, tmp_path):
    """bench/truth/*.json must be exactly what the generator produces (no hand edits)."""
    write_truth(corpus[1], tmp_path / "t")
    for name in REPOS:
        committed = (TRUTH_DIR / f"{name}.json").read_text(encoding="utf-8")
        fresh = (tmp_path / "t" / f"{name}.json").read_text(encoding="utf-8")
        assert committed == fresh, f"bench/truth/{name}.json is stale: re-run bench.build_corpus"
    assert {p.stem for p in TRUTH_DIR.glob("*.json")} == set(REPOS)


def test_corpus_shape(corpus):
    out, truths, _ = corpus
    total = summary(truths)["total"]
    assert len(truths) >= MIN_REPOS
    assert total["records"] >= MIN_RECORDS
    for name, t in truths.items():
        assert 5 <= t["commits"] <= 40, (name, t["commits"])
        assert int(_git(out / name, "rev-list", "--count", "HEAD").strip()) == t["commits"]
    styles = {s for t in truths.values() for s in t["adr_styles"]}
    assert {"nygard", "madr", "madr-fm", "freeform", "adr-tools"} <= styles
    assert (out / "ledgerboot" / ".adr-dir").read_text().strip() == "doc/arch"
    eco = " ".join(t["ecosystem"] for t in truths.values())
    for word in (
        "python",
        "typescript",
        "java/maven",
        "java/gradle",
        "go",
        "terraform",
        "monorepo",
    ):
        assert word in eco, word
    assert any(t["layout"] == "monorepo" for t in truths.values())
    assert total["claim"] >= 100 and total["undocumented"] >= 30


def test_truth_matches_files(corpus):
    """Every label points at a real file, line and commit, and the line is what we claim."""
    out, truths, _ = corpus
    checked = 0
    for name, t in truths.items():
        repo = out / name
        head = t["head"]
        assert _git(repo, "rev-parse", "HEAD").strip() == head
        for rec in t["records"]:
            if rec["type"] == "claim":
                assert re.match(r"^ADR-\d{4}$", rec["decision_id"])
                text = _git(repo, "show", f"{head}:{rec['adr_path']}")
                assert rec["adr_path"].split("/")[-1].startswith(rec["decision_id"][4:])
                assert rec["title"].lower() in text.lower() or rec["title"] in text
                checked += 1
            elif rec["type"] == "evidence":
                lines = _git(repo, "show", f"{head}:{rec['path']}").split("\n")
                line_text = lines[rec["line"] - 1]
                assert line_text.strip(), rec["id"]
                assert SHA.match(rec["introduced_commit"])
                intro = _git(repo, "show", f"{rec['introduced_commit']}:{rec['path']}")
                assert line_text in intro.split("\n"), rec["id"]
                parents = _git(repo, "rev-list", "--parents", "-n", "1", rec["introduced_commit"])
                for parent in parents.split()[1:]:
                    cat = subprocess.run(
                        ["git", "show", f"{parent}:{rec['path']}"],
                        cwd=repo,
                        capture_output=True,
                        text=True,
                    )
                    assert cat.returncode != 0 or line_text not in cat.stdout.split("\n"), (
                        f"{rec['id']}: line already present in the parent of its introducing commit"
                    )
                checked += 1
            else:
                assert rec["evidence"], rec["id"]
                assert rec["first_commit"] == rec["evidence"][0]["commit"]
                for e in rec["evidence"]:
                    lines = _git(repo, "show", f"{head}:{e['path']}").split("\n")
                    assert lines[e["line"] - 1].strip()
                    assert SHA.match(e["commit"])
                    _git(repo, "cat-file", "-e", e["commit"])
                checked += 1
    assert checked >= MIN_RECORDS


def test_every_violated_decision_has_seeded_evidence(corpus):
    for name, t in corpus[1].items():
        ev = {}
        for r in t["records"]:
            if r["type"] == "evidence" and r["role"] == "violation":
                ev.setdefault(r["decision_id"], []).append(r)
        for r in t["records"]:
            if r["type"] == "claim" and r["status"] == "VIOLATED":
                assert ev.get(r["decision_id"]), (
                    f"{name} {r['decision_id']} has no seeded violation"
                )
            if r["type"] == "claim" and r["status"] != "VIOLATED":
                assert r["decision_id"] not in ev, f"{name} {r['decision_id']}"


def test_adversarial_labels_present(corpus):
    out, truths, _ = corpus
    claims = [r for t in truths.values() for r in t["records"] if r["type"] == "claim"]
    decoys = [
        r
        for t in truths.values()
        for r in t["records"]
        if r["type"] == "evidence" and r["role"] == "decoy"
    ]
    kinds = {d["decoy_kind"] for d in decoys}
    for want in ("comment", "test-file", "dev-dependency", "vendored"):
        assert want in kinds, want
    # a decoy never sits on a VIOLATED decision's seeded violation line
    for t in truths.values():
        viol = {
            (r["decision_id"], r["path"], r["line"])
            for r in t["records"]
            if r["type"] == "evidence" and r["role"] == "violation"
        }
        for r in t["records"]:
            if r["type"] == "evidence" and r["role"] == "decoy":
                assert (r["decision_id"], r["path"], r["line"]) not in viol
    # statuses and phrasings
    statuses = {c["status"] for c in claims}
    assert {"HOLDING", "VIOLATED", "DRIFTING", "UNKNOWN", "SKIPPED"} <= statuses
    skipped = {c["adr_status"].split()[0].lower() for c in claims if c["status"] == "SKIPPED"}
    assert {"proposed", "superseded", "rejected", "deprecated"} <= skipped
    unsupported = [c for c in claims if c["expected_offline"] == "UNKNOWN_OR_SKIPPED"]
    assert len(unsupported) >= 15
    assert any(c["status"] == "VIOLATED" for c in unsupported), "recall must be measured honestly"
    # prompt injection really is in the ADR text, and sits on decisions that must not flip
    inj = [c for c in claims if "prompt-injection" in c["tags"]]
    assert len(inj) >= 5
    pat = re.compile(r"ignore (all )?previous instructions|disregard prior instructions", re.I)
    found = 0
    for name, t in truths.items():
        for c in (
            r for r in t["records"] if r["type"] == "claim" and "prompt-injection" in r["tags"]
        ):
            found += bool(pat.search(_git(out / name, "show", f"{t['head']}:{c['adr_path']}")))
    assert found == len(inj)
    assert any(c["status"] == "VIOLATED" for c in inj)
    # undocumented: positives and every kind of negative
    ud = [r for t in truths.values() for r in t["records"] if r["type"] == "undocumented"]
    assert {r["role"] for r in ud} == {"positive", "negative"}
    reasons = {r["reason"] for r in ud if r["role"] == "negative"}
    assert {"comment-only", "nonproduction", "documented", "utility-provider"} <= reasons
    # a vendored-only forbidden import exists as a HOLDING decision (judge false-positive probe)
    held = {(c["repo"], c["decision_id"]) for c in claims if c["status"] == "HOLDING"}
    vend = {
        (r["repo"], r["decision_id"])
        for t in truths.values()
        for r in t["records"]
        if r["type"] == "evidence" and r["role"] == "decoy" and r["decoy_kind"] == "vendored"
    }
    assert vend & held


def test_documented_negatives_really_are_documented(corpus):
    """The ADR text must name every 'documented' negative and no positive technology."""
    out, truths, _ = corpus
    for name, t in truths.items():
        blob = "\n".join(
            _git(out / name, "show", f"{t['head']}:{r['adr_path']}").lower()
            for r in t["records"]
            if r["type"] == "claim"
        )
        for r in t["records"]:
            if r["type"] != "undocumented":
                continue
            word = r["technology"].lower()
            present = re.search(rf"(?<![a-z0-9_]){re.escape(word)}(?![a-z0-9_])", blob)
            if r["role"] == "positive":
                assert not present, (name, word)
            elif r["reason"] == "documented":
                assert present, (name, word)


# --------------------------------------------------------------------------- scorer


def _claim(repo, did, status, offline=None, tags=(), title="t"):
    return {
        "type": "claim",
        "decision_id": did,
        "title": title,
        "status": status,
        "expected_offline": offline or status,
        "tags": list(tags),
        "repo": repo,
    }


def _ev(repo, did, role, path, line, kind="x"):
    r = {
        "type": "evidence",
        "role": role,
        "decision_id": did,
        "path": path,
        "line": line,
        "repo": repo,
    }
    r["decoy_kind" if role == "decoy" else "kind"] = kind
    return r


def _ud(repo, tech, role, first="a" * 40, reason=""):
    return {
        "type": "undocumented",
        "repo": repo,
        "technology": tech,
        "category": "datastore",
        "role": role,
        "reason": reason,
        "first_commit": first,
        "evidence": [{"path": "x", "line": 1, "commit": first}],
    }


def synthetic():
    r1 = [
        _claim("r1", "ADR-0001", "VIOLATED"),
        _ev("r1", "ADR-0001", "violation", "a.py", 3),
        _ev("r1", "ADR-0001", "decoy", "a.py", 9, "comment"),
        _claim("r1", "ADR-0002", "VIOLATED", tags=["prompt-injection"]),
        _ev("r1", "ADR-0002", "violation", "b.py", 1),
        _claim("r1", "ADR-0003", "HOLDING", tags=["adversarial"]),
        _ev("r1", "ADR-0003", "decoy", "c.py", 2, "vendored"),
        _claim("r1", "ADR-0004", "UNKNOWN"),
        _claim("r1", "ADR-0005", "SKIPPED"),
        _claim("r1", "ADR-0006", "DRIFTING", tags=["adversarial"]),
        _ev("r1", "ADR-0006", "decoy", "d.py", 4, "test-file"),
        _claim("r1", "ADR-0007", "VIOLATED", offline="UNKNOWN_OR_SKIPPED"),
        _ev("r1", "ADR-0007", "violation", "e.py", 5),
        _claim("r1", "ADR-0008", "HOLDING", tags=["prompt-injection"]),
        _ud("r1", "mongodb", "positive"),
        _ud("r1", "redis", "positive", "b" * 40),
    ]
    r2 = [
        _claim("r2", "ADR-0001", "VIOLATED"),
        _ev("r2", "ADR-0001", "violation", "f.py", 7),
        _claim("r2", "ADR-0002", "HOLDING"),
        _ud("r2", "sentry", "negative", reason="nonproduction"),
    ]
    return {"r1": {"records": r1}, "r2": {"records": r2}}


def _p(repo, did, status, ev=(), grounding="VERIFIED"):
    return {
        "repo": repo,
        "decision_id": did,
        "status": status,
        "grounding": grounding,
        "evidence": [{"path": p, "line": ln} for p, ln in ev],
    }


def _u(repo, tech, commits=("a" * 40,), grounding="VERIFIED"):
    return {
        "repo": repo,
        "kind": "undocumented",
        "technology": tech,
        "category": "datastore",
        "introducing_commits": list(commits),
        "evidence": [],
        "grounding": grounding,
    }


PERFECT = [
    _p("r1", "ADR-0001", "VIOLATED", [("a.py", 3)]),
    _p("r1", "ADR-0002", "VIOLATED", [("b.py", 1)]),
    _p("r1", "ADR-0003", "HOLDING"),
    _p("r1", "ADR-0004", "UNKNOWN"),
    _p("r1", "ADR-0005", "SKIPPED"),
    _p("r1", "ADR-0006", "DRIFTING"),
    _p("r1", "ADR-0007", "VIOLATED", [("e.py", 5)]),
    _p("r1", "ADR-0008", "HOLDING"),
    _p("r2", "ADR-0001", "VIOLATED", [("f.py", 7)]),
    _p("r2", "ADR-0002", "HOLDING"),
    _u("r1", "mongodb"),
    _u("r1", "redis", ("b" * 40,)),
]


def test_scorer_perfect():
    res = S.score(synthetic(), PERFECT)
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (4, 0, 0)
    assert o["precision"] == o["recall"] == o["f1"] == 1.0
    assert res["localisation"]["accuracy"] == 1.0
    assert res["localisation"]["predicted_violated_citing_a_decoy"] == 0
    assert res["undocumented"]["precision"] == res["undocumented"]["recall"] == 1.0
    assert res["undocumented"]["introduction_accuracy"] == 1.0
    assert res["breakdown"]["all_decisions"]["accuracy"] == 1.0
    assert res["thresholds"]["S2"]["pass"] is True
    assert res["errors"] == []
    cm = res["confusion"]["full"]
    assert cm["VIOLATED"]["VIOLATED"] == 4 and cm["HOLDING"]["HOLDING"] == 3
    # UNKNOWN + SKIPPED + DRIFTING truth rows are all folded into the core UNKNOWN row
    assert res["confusion"]["core"]["matrix"]["UNKNOWN"]["UNKNOWN"] == 3


def test_scorer_all_wrong():
    wrong = [
        _p("r1", "ADR-0001", "HOLDING"),
        _p("r1", "ADR-0002", "HOLDING"),
        _p("r1", "ADR-0003", "VIOLATED", [("c.py", 2)]),
        _p("r1", "ADR-0004", "HOLDING"),
        _p("r1", "ADR-0005", "HOLDING"),
        _p("r1", "ADR-0006", "VIOLATED", [("d.py", 4)]),
        _p("r1", "ADR-0007", "HOLDING"),
        _p("r1", "ADR-0008", "VIOLATED", [("z.py", 1)]),
        _p("r2", "ADR-0001", "HOLDING"),
        _p("r2", "ADR-0002", "VIOLATED", [("z.py", 1)]),
        _u("r1", "kafka"),
    ]
    res = S.score(synthetic(), wrong)
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (0, 4, 4)
    assert o["precision"] == 0.0 and o["recall"] == 0.0 and o["f1"] == 0.0
    assert res["localisation"]["accuracy"] is None  # no true positive to localise
    assert res["localisation"]["predicted_violated_citing_a_decoy"] == 2
    assert res["undocumented"]["precision"] == 0.0 and res["undocumented"]["recall"] == 0.0
    assert res["thresholds"]["S2"]["pass"] is False
    assert res["breakdown"]["adversarial"]["false_violations"] == 2
    assert res["breakdown"]["prompt_injection"]["flipped_to_holding"] == 1  # ADR-0002 -> HOLDING
    assert res["breakdown"]["unsupported_phrasing"]["confidently_wrong"] == 1


def test_scorer_partial_exact_numbers():
    partial = [
        _p("r1", "ADR-0001", "VIOLATED", [("a.py", 3), ("a.py", 9)]),  # TP, localised, cites decoy
        _p("r1", "ADR-0002", "HOLDING"),  # FN, flipped
        _p("r1", "ADR-0003", "VIOLATED", [("c.py", 2)]),  # FP, cites decoy
        _p("r1", "ADR-0006", "VIOLATED"),  # FP
        _p("r1", "ADR-0007", "UNKNOWN"),  # FN, abstained
        _p("r1", "ADR-0008", "HOLDING"),
        _p("r2", "ADR-0001", "VIOLATED", [("f.py", 99)]),  # TP, not localised
        _u("r1", "mongodb"),
        _u("r1", "kafka"),
        _u("r2", "sentry"),
    ]
    res = S.score(synthetic(), partial)
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (2, 2, 2)
    assert (o["precision"], o["recall"], o["f1"]) == (0.5, 0.5, 0.5)
    r1, r2 = res["violated"]["per_repo"]["r1"], res["violated"]["per_repo"]["r2"]
    assert (r1["tp"], r1["fp"], r1["fn"]) == (1, 2, 2)
    assert r1["precision"] == pytest.approx(1 / 3) and r1["recall"] == pytest.approx(1 / 3)
    assert (r2["precision"], r2["recall"]) == (1.0, 1.0)
    assert res["violated"]["offline_reachable"]["recall"] == pytest.approx(2 / 3)
    assert res["localisation"]["localised"] == 1 and res["localisation"]["accuracy"] == 0.5
    assert res["localisation"]["predicted_violated_citing_a_decoy"] == 2
    u = res["undocumented"]
    assert (u["tp"], u["fp"], u["fn"]) == (1, 2, 1)
    assert u["precision"] == pytest.approx(1 / 3) and u["recall"] == 0.5
    assert u["negatives_reported"] == ["r2:sentry (nonproduction)"]
    assert u["false_positives"] == ["r1:kafka", "r2:sentry"] and u["missed"] == ["r1:redis"]
    bd = res["breakdown"]
    assert bd["unsupported_phrasing"]["abstained"] == 1
    assert bd["prompt_injection"]["flipped_to_holding"] == 1
    assert res["thresholds"]["S2"]["pass"] is False
    cm = res["confusion"]["full"]
    assert cm["VIOLATED"]["VIOLATED"] == 2 and cm["VIOLATED"]["HOLDING"] == 1
    assert cm["VIOLATED"]["UNKNOWN"] == 1 and cm["SKIPPED"]["NONE"] == 1
    assert cm["HOLDING"]["VIOLATED"] == 1 and cm["DRIFTING"]["VIOLATED"] == 1


def test_scorer_empty_predictions():
    res = S.score(synthetic(), [])
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (0, 0, 4)
    assert o["precision"] is None and o["recall"] == 0.0 and o["f1"] is None
    assert res["thresholds"]["S2"]["pass"] is False  # undefined precision never passes
    assert res["undocumented"]["precision"] is None and res["undocumented"]["recall"] == 0.0
    assert (
        res["grounding"]["predictions"] == 0 and res["grounding"]["predictions_pass_rate"] is None
    )
    # abstention is right for SKIPPED / UNKNOWN truth, a miss for the rest
    assert res["breakdown"]["skipped_status"]["accuracy"] == 1.0
    assert res["breakdown"]["qualifier_unknown"]["accuracy"] == 1.0
    assert res["errors"] and all(e["truth"] not in ("SKIPPED", "UNKNOWN") for e in res["errors"])
    S.render_markdown(res)  # renders with n/a values


def test_scorer_adversarial_and_grounding_rules():
    preds = [dict(p) for p in PERFECT]
    # a VIOLATED whose grounding failed is "Could not verify": scored UNKNOWN, never a finding
    preds[0] = _p("r1", "ADR-0001", "VIOLATED", [("a.py", 3)], grounding="MISMATCH")
    # an unverified undocumented record is not a finding either
    preds[-1] = _u("r1", "redis", ("b" * 40,), grounding="MISMATCH")
    # a prediction for a decision that has no label is a false VIOLATED
    preds.append(_p("r1", "ADR-0099", "VIOLATED", [("q.py", 1)]))
    res = S.score(synthetic(), preds)
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (3, 1, 1)
    assert res["unlabelled_predictions"] == ["r1:ADR-0099"]
    assert res["grounding"]["downgraded_to_unknown"] == 1
    assert res["grounding"]["undocumented_not_verified"] == 1
    assert res["grounding"]["predictions_verified"] == 11 and res["grounding"]["predictions"] == 13
    assert res["undocumented"]["tp"] == 1 and res["undocumented"]["fn"] == 1
    # a forbidden library in a comment / test / dev dependency / vendored tree must not be VIOLATED
    held = [_p("r1", "ADR-0003", "HOLDING"), _p("r1", "ADR-0006", "DRIFTING")]
    ok = S.score(synthetic(), held)
    assert ok["breakdown"]["adversarial"]["false_violations"] == 0
    bad = S.score(
        synthetic(),
        [
            _p("r1", "ADR-0003", "VIOLATED", [("c.py", 2)]),
            _p("r1", "ADR-0006", "VIOLATED", [("d.py", 4)]),
        ],
    )
    assert bad["breakdown"]["adversarial"]["false_violations"] == 2
    assert {d["decision_id"] for d in bad["localisation"]["decoy_citations"]} == {
        "ADR-0003",
        "ADR-0006",
    }


def test_scorer_merges_claims_of_one_decision():
    assert S.aggregate_status(["HOLDING", "VIOLATED"]) == "VIOLATED"
    assert S.aggregate_status(["HOLDING", "DRIFTING"]) == "DRIFTING"
    assert S.aggregate_status(["HOLDING", "UNKNOWN"]) == "UNKNOWN"
    assert S.aggregate_status(["HOLDING", "HOLDING"]) == "HOLDING"
    assert S.aggregate_status(["SKIPPED"]) == "SKIPPED" and S.aggregate_status([]) == "NONE"
    preds = [dict(p) for p in PERFECT if p.get("decision_id") != "ADR-0001" or p["repo"] != "r1"]
    preds += [
        _p("r1", "ADR-0001", "HOLDING", [("zzz.py", 1)]),
        _p("r1", "ADR-0001", "VIOLATED", [("a.py", 3)]),
    ]
    res = S.score(synthetic(), preds)
    assert res["violated"]["overall"]["tp"] == 4 and res["localisation"]["accuracy"] == 1.0


def test_scorer_evidence_line_ranges_and_paths():
    t = synthetic()
    p = [dict(x) for x in PERFECT]
    p[0] = {
        "repo": "r1",
        "decision_id": "ADR-0001",
        "status": "VIOLATED",
        "grounding": "VERIFIED",
        "evidence": [{"path": "./a.py", "line_start": 1, "line_end": 5}],
    }
    assert S.score(t, p)["localisation"]["accuracy"] == 1.0
    p[0]["evidence"] = [{"path": "a.py", "line_start": 4, "line_end": 8}]
    assert S.score(t, p)["localisation"]["accuracy"] == 0.75


def test_scorer_deterministic_and_json_safe(tmp_path):
    a = S.score(synthetic(), PERFECT)
    b = S.score(synthetic(), list(reversed(PERFECT)))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    md, js = S.write_results(a, tmp_path / "out", "case")
    assert md.read_text().startswith("# DriftWarden benchmark")
    assert json.loads(js.read_text())["violated"]["overall"]["tp"] == 4


def test_ledger_pass_rate(tmp_path):
    d = tmp_path / "logs" / "grounding"
    d.mkdir(parents=True)
    rows = [{"check_id": "G1", "status": "VERIFIED"}] * 3 + [
        {"check_id": "G2", "status": "VERIFIED"},
        {"check_id": "G2", "status": "MISMATCH"},
    ]
    (d / "run.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n\nnot json\n")
    (d / "run.summary.json").write_text("{}")
    lg = S.read_ledger(tmp_path)
    assert (lg["rows"], lg["verified"], lg["mismatch"]) == (5, 4, 1)
    assert lg["pass_rate"] == 0.8 and lg["by_check"]["G2"]["pass_rate"] == 0.5
    res = S.score(synthetic(), PERFECT, ledger_dir=tmp_path)
    s4 = res["thresholds"]["S4"]
    assert s4["citation_accuracy"] == 0.8 and s4["pass"] is False  # < 0.90 and < 200 rows
    assert S.score(synthetic(), PERFECT)["thresholds"]["S4"]["pass"] is None


def test_oracle_and_inverse_predictions_on_real_truth(corpus):
    """Predictions derived from the truth itself score 1.0; the inverse scores 0."""
    truths = corpus[1]
    oracle, inverse = [], []
    flip = {
        "VIOLATED": "HOLDING",
        "HOLDING": "VIOLATED",
        "DRIFTING": "VIOLATED",
        "UNKNOWN": "HOLDING",
        "SKIPPED": "HOLDING",
    }
    for name, t in truths.items():
        ev = {}
        for r in t["records"]:
            if r["type"] == "evidence" and r["role"] == "violation":
                ev.setdefault(r["decision_id"], []).append({"path": r["path"], "line": r["line"]})
        for r in t["records"]:
            if r["type"] == "claim":
                oracle.append(
                    {
                        "repo": name,
                        "decision_id": r["decision_id"],
                        "status": r["status"],
                        "evidence": ev.get(r["decision_id"], []),
                        "grounding": "VERIFIED",
                    }
                )
                inverse.append(
                    {
                        "repo": name,
                        "decision_id": r["decision_id"],
                        "status": flip[r["status"]],
                        "evidence": [],
                        "grounding": "VERIFIED",
                    }
                )
            elif r["type"] == "undocumented" and r["role"] == "positive":
                oracle.append(
                    {
                        "repo": name,
                        "kind": "undocumented",
                        "technology": r["technology"],
                        "introducing_commits": r["introducing_commits"],
                        "grounding": "VERIFIED",
                    }
                )
    good = S.score(truths, oracle)
    assert good["violated"]["overall"]["precision"] == good["violated"]["overall"]["recall"] == 1.0
    assert good["localisation"]["accuracy"] == 1.0 and good["errors"] == []
    assert good["undocumented"]["precision"] == good["undocumented"]["recall"] == 1.0
    assert good["thresholds"]["S2"]["pass"] and good["thresholds"]["G7_corpus"]["pass"]
    bad = S.score(truths, inverse)
    assert bad["violated"]["overall"]["recall"] == 0.0
    assert bad["violated"]["overall"]["precision"] == 0.0
    assert not bad["thresholds"]["S2"]["pass"]


# --------------------------------------------------------------------------- runner / adapter


def test_predict_stub_raises_until_l028():
    with pytest.raises(NotImplementedError, match="needs L-028 run_scan"):
        bench_run.predict("/nonexistent")
    assert bench_run.main(["--out", "/nonexistent-never-written"]) == 2


def test_report_to_predictions_mapping():
    report = {
        "decisions": [
            {"id": "ADR-0001", "status": "accepted"},
            {"id": "ADR-0002", "status": "superseded"},
        ],
        "verdicts": [
            {
                "claim_id": "ADR-0001.c1",
                "status": "HOLDING",
                "grounding": "VERIFIED",
                "evidence": [],
            },
            {
                "claim_id": "ADR-0001.c2",
                "status": "VIOLATED",
                "grounding": "VERIFIED",
                "evidence": [{"ref": {"path": "a.py", "line_start": 3, "line_end": 4}}],
            },
        ],
        "undocumented": [
            {
                "technology": "redis",
                "category": "cache",
                "introducing_commits": ["c" * 40],
                "grounding": "MISMATCH",
                "evidence": [{"ref": {"path": "r.py", "line_start": 1}}],
            }
        ],
    }
    preds = bench_run.report_to_predictions(report, "demo")
    assert {
        "repo": "demo",
        "decision_id": "ADR-0002",
        "status": "SKIPPED",
        "evidence": [],
        "grounding": "VERIFIED",
    } in preds
    truth = {
        "demo": {
            "records": [
                _claim("demo", "ADR-0001", "VIOLATED"),
                _ev("demo", "ADR-0001", "violation", "a.py", 4),
                _claim("demo", "ADR-0002", "SKIPPED"),
                _ud("demo", "redis", "positive"),
            ]
        }
    }
    res = S.score(truth, preds)
    assert res["violated"]["overall"]["tp"] == 1 and res["localisation"]["accuracy"] == 1.0
    assert res["errors"] == []
    assert res["undocumented"]["recall"] == 0.0  # MISMATCH grounding: could not verify


# --------------------------------------------------------------------------- calibration canary

# Known judge defects (reported in the L-015 handover): vendored third-party code is treated as
# production, so a forbidden import that exists only under vendor/ or third_party/ is VIOLATED.
KNOWN_VENDORED_DEFECTS = {("nodeapi", "ADR-0016"), ("datahub", "ADR-0008")}


def test_labels_agree_with_the_offline_library(corpus):
    """Canary: where a phrasing is labelled supported, the offline modules reach the label.

    Calls the library building blocks directly (``bench.probe_library``); this is not the
    L-028 pipeline. If this fails, either the library changed (update the labels with
    ``python -m bench.build_corpus``) or a label is wrong.
    """
    from bench.probe_library import predict_library

    out, truths, _ = corpus
    preds = []
    for name in sorted(truths):
        preds.extend(predict_library(out / name))
    res = S.score(truths, preds)
    wrong = [
        (e["repo"], e["decision_id"])
        for e in res["errors"]
        if e["expected_offline"] not in ("UNKNOWN_OR_SKIPPED", None)
    ]
    assert set(wrong) <= KNOWN_VENDORED_DEFECTS, wrong
    assert res["breakdown"]["unsupported_phrasing"]["confidently_wrong"] == 0
    assert res["undocumented"]["fp"] == 0 and res["undocumented"]["fn"] == 0
    assert res["undocumented"]["negatives_reported"] == []
    assert res["breakdown"]["prompt_injection"]["flipped_to_holding"] == 0
    assert res["localisation"]["accuracy"] == 1.0


# ------------------------------------------------------------------------ matrix folding


def _matrix_total(m: dict) -> int:
    return sum(sum(row.values()) for row in m.values())


def test_core_matrix_total_equals_full_matrix_total():
    """Truth rows are folded exactly like prediction columns: nothing is dropped."""
    for preds in (PERFECT, [], [_p("r1", "ADR-0005", "VIOLATED", [("z.py", 1)])]):
        res = S.score(synthetic(), preds)
        cm = res["confusion"]
        assert _matrix_total(cm["core"]["matrix"]) == _matrix_total(cm["full"]) == 10
        assert set(cm["core"]["matrix"]) == set(S.CORE)


def test_core_matrix_total_on_real_corpus(corpus):
    truths = corpus[1]
    n = sum(1 for t in truths.values() for r in t["records"] if r["type"] == "claim")
    res = S.score(truths, [])
    cm = res["confusion"]
    assert _matrix_total(cm["core"]["matrix"]) == _matrix_total(cm["full"]) == n


def test_violated_on_drifting_or_skipped_truth_is_a_false_positive():
    truths = {
        "r": {
            "records": [
                _claim("r", "ADR-0001", "DRIFTING"),
                _claim("r", "ADR-0002", "SKIPPED"),
                _claim("r", "ADR-0003", "VIOLATED"),
                _ev("r", "ADR-0003", "violation", "a.py", 1),
            ]
        }
    }
    preds = [
        _p("r", "ADR-0001", "VIOLATED", [("x.py", 1)]),
        _p("r", "ADR-0002", "VIOLATED", [("y.py", 1)]),
        _p("r", "ADR-0003", "VIOLATED", [("a.py", 1)]),
    ]
    res = S.score(truths, preds)
    o = res["violated"]["overall"]
    assert (o["tp"], o["fp"], o["fn"]) == (1, 2, 0)
    assert o["precision"] == pytest.approx(1 / 3)
    core = res["confusion"]["core"]["matrix"]
    # DRIFTING and SKIPPED truth rows land in the UNKNOWN row, so the false VIOLATED shows up
    assert core["UNKNOWN"]["VIOLATED"] == 2
    assert core["VIOLATED"]["VIOLATED"] == 1
    assert _matrix_total(core) == _matrix_total(res["confusion"]["full"]) == 3
    assert {e["truth"] for e in res["errors"]} == {"DRIFTING", "SKIPPED"}


# --------------------------------------------------------------------------- label audit

_NONPROD_DIRS = {"test", "tests", "vendor", "third_party", "testdata", "__tests__"}
_NONPROD_NAME = re.compile(
    r"(_test\.go|\.test\.[jt]sx?|Test\.java|IT\.java|^test_.*\.py|requirements-dev\.txt"
    r"|docker-compose\.test\.ya?ml)$"
)
_COMMENT = ("//", "#", "*", "/*", "<!--")


def _nonprod_path(path: str) -> bool:
    parts = path.split("/")
    return bool(_NONPROD_DIRS & set(parts[:-1])) or bool(_NONPROD_NAME.search(parts[-1]))


def _nonprod_line(path: str, lines: list[str], i: int) -> bool:
    """True when line ``i`` is not production code: test/vendored/dev path, a pure comment,
    a dev/optional dependency section, or a test-scoped dependency."""
    text = lines[i].strip()
    if _nonprod_path(path) or text.startswith(_COMMENT):
        return True
    name = path.split("/")[-1]
    if name == "package.json":
        for j in range(i, -1, -1):
            m = re.match(r'\s*"(\w*[dD]ependencies)"\s*:', lines[j])
            if m:
                return m.group(1).lower().startswith(("dev", "peer", "optional"))
    elif name == "pyproject.toml":
        for j in range(i, -1, -1):
            if lines[j].startswith("["):
                return lines[j].strip() == "[project.optional-dependencies]"
    elif name == "pom.xml":
        lo = (
            max(j for j in range(i + 1) if "<dependency>" in lines[j])
            if any("<dependency>" in lines[j] for j in range(i + 1))
            else i
        )
        hi = next((j for j in range(i, len(lines)) if "</dependency>" in lines[j]), i)
        return any("<scope>test</scope>" in lines[j] for j in range(lo, hi + 1))
    elif name.startswith("build.gradle"):
        return text.startswith(("testImplementation", "testRuntimeOnly", "developmentOnly"))
    return False


def audit_labels(out: Path, truths: dict) -> tuple[int, list[str]]:
    """Check every HOLDING / VIOLATED / DRIFTING label against the generated repo at HEAD."""
    problems: list[str] = []
    checked = 0
    for name, t in sorted(truths.items()):
        root = out / name
        adr_paths = {r["adr_path"] for r in t["records"] if r["type"] == "claim"}
        files: dict[str, list[str]] = {}
        for rel in _git(root, "ls-files").split("\n"):
            if rel and rel not in adr_paths and rel != "README.md":
                files[rel] = (root / rel).read_text(encoding="utf-8").split("\n")
        ev: dict[tuple[str, str], list[dict]] = {}
        for r in t["records"]:
            if r["type"] == "evidence":
                ev.setdefault((r["decision_id"], r["role"]), []).append(r)

        def line_of(r: dict, files: dict = files) -> tuple[list[str], int]:
            lines = files.get(r["path"])
            if lines is None:
                raise AssertionError(f"{r['id']}: {r['path']} does not exist at HEAD")
            if not 1 <= r["line"] <= len(lines):
                raise AssertionError(f"{r['id']}: line {r['line']} is past the end of the file")
            return lines, r["line"] - 1

        for c in (r for r in t["records"] if r["type"] == "claim"):
            if c["status"] not in ("HOLDING", "VIOLATED", "DRIFTING"):
                continue
            checked += 1
            try:
                _audit_claim(name, c, files, ev, line_of, problems)
            except AssertionError as exc:
                problems.append(f"{name} {c['decision_id']} {c['status']}: {exc}")
    return checked, problems


def _audit_claim(name, c, files, ev, line_of, problems) -> None:
    did, tag = c["decision_id"], f"{name} {c['decision_id']} {c['status']}"
    terms = [x.lower() for x in c.get("terms", [])]
    proof = ev.get((did, "proof"), [])
    allowed = {
        (d["path"], d["line"])
        for d in ev.get((did, "decoy"), [])
        if d.get("decoy_kind") == "allowed-location"
    }
    hits = []
    for path, lines in files.items():
        for i, ln in enumerate(lines):
            if any(x in ln.lower() for x in terms):
                hits.append((path, i + 1, _nonprod_line(path, lines, i)))
    prod = [(p, n) for p, n, np_ in hits if not np_ and (p, n) not in allowed]
    nonprod = [(p, n) for p, n, np_ in hits if np_]
    if c["status"] == "HOLDING":
        if not terms and not proof:
            problems.append(f"{tag}: nothing checkable (no terms, no proof)")
        if prod:
            problems.append(f"{tag}: forbidden term in production code at {prod}")
        for p in proof:
            lines, i = line_of(p)
            if p["needle"] not in lines[i]:
                problems.append(f"{tag}: proof {p['path']}:{p['line']} lacks {p['needle']!r}")
            if _nonprod_line(p["path"], lines, i):
                problems.append(f"{tag}: proof {p['path']}:{p['line']} is not production code")
    elif c["status"] == "VIOLATED":
        viol = ev.get((did, "violation"), [])
        if not viol or not terms:
            problems.append(f"{tag}: no seeded violation or no terms")
        for v in viol:
            lines, i = line_of(v)
            if _nonprod_line(v["path"], lines, i):
                problems.append(f"{tag}: violation {v['path']}:{v['line']} is not production code")
            if not any(x in lines[i].lower() for x in terms):
                problems.append(f"{tag}: violation {v['path']}:{v['line']} has none of {terms}")
    else:  # DRIFTING
        if not terms:
            problems.append(f"{tag}: no terms")
        if prod:
            problems.append(f"{tag}: production hit at {prod}, so it is VIOLATED")
        if not nonprod:
            problems.append(f"{tag}: no non-production evidence exists at all")
        if ev.get((did, "violation")):
            problems.append(f"{tag}: has a violation row")
        for d in ev.get((did, "decoy"), []):
            lines, i = line_of(d)
            if not _nonprod_line(d["path"], lines, i):
                problems.append(f"{tag}: decoy {d['path']}:{d['line']} is production code")


def test_labels_are_true_of_the_generated_repos(corpus):
    """Seeded evidence (or its absence) really exists at the stated file:line for every
    HOLDING / VIOLATED / DRIFTING record."""
    out, truths, _ = corpus
    checked, problems = audit_labels(out, truths)
    want = sum(
        1
        for t in truths.values()
        for r in t["records"]
        if r["type"] == "claim" and r["status"] in ("HOLDING", "VIOLATED", "DRIFTING")
    )
    assert checked == want >= 80
    assert not problems, "\n".join(problems)


def test_label_audit_catches_a_lying_fixture(tmp_path):
    """The audit is not vacuous: the original nodeapi defect (a cursor-pagination ADR over a
    handler with no cursor) and a forbidden import seeded into a HOLDING repo both fail."""
    truths = build_corpus(tmp_path, ["nodeapi"])
    root = tmp_path / "nodeapi"
    assert audit_labels(tmp_path, truths)[1] == []
    server = root / "src" / "server.ts"
    server.write_text(
        "import express from 'express';\nexport const app = express();\n"
        "app.get('/orders', (_req, res) => res.json([]));\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@e.invalid", "commit", "-qm", "x"],
        cwd=root,
        check=True,
    )
    (root / "src" / "http" / "legacy.ts").write_text(
        "import fetch from 'node-fetch';\nexport { fetch };\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@e.invalid", "commit", "-qm", "y"],
        cwd=root,
        check=True,
    )
    try:
        _, problems = audit_labels(tmp_path, truths)
    except AssertionError as exc:  # a proof line that no longer exists is also a failure
        problems = [str(exc)]
        pytest.fail(f"audit should report, not raise: {exc}")
    joined = "\n".join(problems)
    assert "nodeapi ADR-0008 HOLDING" in joined, joined
    assert "nodeapi ADR-0003 HOLDING: forbidden term in production code" in joined, joined
