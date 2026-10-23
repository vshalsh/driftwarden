from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from conftest import git
from driftwarden import git as dwgit
from driftwarden.cli import app
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import normalise, verify_source_quote
from driftwarden.models import WORKTREE, Provenance


@pytest.fixture
def repo_and_decisions(fixture_repo):
    repo = fixture_repo("basic")
    return repo, {d.id: d for d in scan_adrs(repo).decisions}


def test_verifier_passes_on_all_fixture_decisions(fixture_repo):
    total = 0
    for name in ("basic", "adr_tools"):
        repo = fixture_repo(name)
        for dec in scan_adrs(repo).decisions:
            r = verify_source_quote(repo, dec.source)
            assert r.status == "VERIFIED", r.reason
            total += 1
    assert total == 13


def test_normalisation_rules():
    assert normalise("we  **don’t**\n  “normalise”") == 'we don\'t "normalise"'
    assert normalise("a\tb\r\n\r\nc") == "a b c"
    assert normalise("~~x~~ _y_") == "x y"


def test_normalised_quote_matches(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0012"].source
    plain = src.model_copy(
        update={"quote": 'names are stored exactly as entered - we don\'t "normalise"'}
    )
    # Hyphen vs em dash is a real difference and must NOT be normalised away.
    assert verify_source_quote(repo, plain).status == "MISMATCH"
    plain = src.model_copy(
        update={"quote": 'names are stored exactly as entered — we don\'t\n"normalise" them'}
    )
    assert verify_source_quote(repo, plain).status == "VERIFIED"


def test_tamper_one_word(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0002"].source
    bad = src.model_copy(update={"quote": src.quote.replace("only", "preferred", 1)})
    r = verify_source_quote(repo, bad)
    assert r.status == "MISMATCH"
    assert "not found in cited range or anywhere in the file" in r.reason


def test_shifted_range_reports_true_location(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0002"].source  # lines 15-18
    shifted = src.model_copy(update={"line_start": 5, "line_end": 8})
    r = verify_source_quote(repo, shifted)
    assert r.status == "MISMATCH"
    assert "found at lines 15-18" in r.reason


def test_partial_overlap_range_is_mismatch(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0002"].source
    r = verify_source_quote(repo, src.model_copy(update={"line_end": 16}))
    assert r.status == "MISMATCH" and "found at lines 15-18" in r.reason


def test_out_of_bounds(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0001"].source
    for start, end in [(0, 3), (5, 4), (15, 999)]:
        r = verify_source_quote(repo, src.model_copy(update={"line_start": start, "line_end": end}))
        assert r.status == "MISMATCH"
        assert "out of bounds" in r.reason


def test_bad_commit(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0001"].source
    for commit in ["0" * 40, "not-a-sha", ""]:
        r = verify_source_quote(repo, src.model_copy(update={"commit": commit}))
        assert r.status == "MISMATCH"
        assert "unknown commit" in r.reason


def test_file_missing_at_commit(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0001"].source
    r = verify_source_quote(repo, src.model_copy(update={"path": "docs/adr/9999-nope.md"}))
    assert r.status == "MISMATCH" and "file missing at commit" in r.reason
    r = verify_source_quote(repo, src.model_copy(update={"path": "../etc/passwd"}))
    assert r.status == "MISMATCH" and "not repo-relative" in r.reason


def test_verifies_against_commit_not_worktree(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0002"].source
    old_head = src.commit
    p = repo / src.path
    p.write_text(p.read_text(encoding="utf-8").replace("PostgreSQL is", "MySQL is"), "utf-8")
    git(repo, "commit", "-q", "-am", "edit")
    assert dwgit.head_sha(repo) != old_head
    # Old provenance still verifies against its own commit.
    assert verify_source_quote(repo, src).status == "VERIFIED"


def test_worktree_provenance(repo_and_decisions):
    repo, d = repo_and_decisions
    src = d["ADR-0002"].source
    wt = src.model_copy(update={"commit": WORKTREE})
    assert verify_source_quote(repo, wt).status == "VERIFIED"
    (repo / src.path).unlink()
    r = verify_source_quote(repo, wt)
    assert r.status == "MISMATCH" and "missing in working tree" in r.reason


def test_empty_quote_is_mismatch(repo_and_decisions):
    repo, d = repo_and_decisions
    r = verify_source_quote(repo, d["ADR-0001"].source.model_copy(update={"quote": "  **  "}))
    assert r.status == "MISMATCH" and "empty" in r.reason


# ---------------------------------------------------------------- ledger


def test_ledger(tmp_path, repo_and_decisions):
    repo, d = repo_and_decisions
    led = Ledger(tmp_path, run_id="r1")
    src = d["ADR-0001"].source
    led.append(verify_source_quote(repo, src, subject="ADR-0001"))
    led.append(verify_source_quote(repo, src.model_copy(update={"commit": "0" * 40})))
    s = led.write_summary()
    assert s["total"] == 2 and s["verified"] == 1 and s["pass_rate"] == 0.5
    assert s["by_check"] == {"G1": {"VERIFIED": 1, "MISMATCH": 1}}
    rows = [json.loads(x) for x in led.path.read_text(encoding="utf-8").splitlines()]
    assert [r["status"] for r in rows] == ["VERIFIED", "MISMATCH"]
    assert rows[0]["provenance"]["commit"] == src.commit
    assert rows[0]["run_id"] == "r1" and rows[0]["subject"] == "ADR-0001"
    assert json.loads(led.summary_path.read_text(encoding="utf-8"))["total"] == 2


def test_empty_ledger_pass_rate_is_none(tmp_path):
    assert Ledger(tmp_path, run_id="x").summary()["pass_rate"] is None


# ---------------------------------------------------------------- CLI wiring


def test_scan_cli_all_verified(fixture_repo, tmp_path):
    repo = fixture_repo("basic")
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert "12/12 VERIFIED" in res.output and "100.0%" in res.output
    ledgers = list((out / "logs" / "grounding").glob("*.jsonl"))
    assert len(ledgers) == 1
    assert len(ledgers[0].read_text(encoding="utf-8").splitlines()) == 12


def test_scan_cli_exit_3_on_mismatch(fixture_repo, tmp_path, monkeypatch):
    import driftwarden.cli as cli

    repo = fixture_repo("basic")
    real = cli.scan_adrs

    def tampered(*a, **k):
        res = real(*a, **k)
        dec = res.decisions[0]
        bad = dec.source.model_copy(update={"quote": "something the ADR never said"})
        res.decisions[0] = dec.model_copy(update={"source": bad})
        return res

    monkeypatch.setattr(cli, "scan_adrs", tampered)
    res = CliRunner().invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 3
    assert "Could not verify" in res.output
    assert "11/12 VERIFIED" in res.output


def test_provenance_round_trip():
    p = Provenance(path="a.md", line_start=1, line_end=2, commit="abc", quote="q")
    assert Provenance.model_validate_json(p.model_dump_json()) == p
