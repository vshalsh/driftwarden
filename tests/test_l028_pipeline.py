"""L-028: end-to-end scan pipeline, the Report model and `driftwarden scan`."""

from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftwarden.cli as cli
from conftest import git
from driftwarden.cli import app
from driftwarden.config import Config
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.judge.judge import Judge
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.models import Claim, Provenance
from driftwarden.pipeline import claim_touches, run_scan
from driftwarden.report.model import Report, natural_key, rule_text

FIXTURES = Path(__file__).parent / "fixtures"
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


def _commit(repo: Path) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")


def copy_repo(tmp_path: Path, src: Path, name: str) -> Path:
    dest = tmp_path / name
    shutil.copytree(src, dest)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "config", "commit.gpgsign", "false")
    _commit(dest)
    return dest


@pytest.fixture
def pyshop(tmp_path):
    return copy_repo(tmp_path, FIXTURES / "judge_repos" / "pyshop", "pyshop")


def scan(repo: Path, tmp_path: Path, **kw) -> Report:
    kw.setdefault("mode", "offline")
    return run_scan(repo, config=Config(), ledger=Ledger(tmp_path / "ledger"), **kw)


def by_id(report: Report) -> dict:
    return {c.id: c for c in report.claims}


# ------------------------------------------------------------------ end to end


def test_end_to_end_pyshop_offline(pyshop, tmp_path):
    r = scan(pyshop, tmp_path, draft_adrs=True)
    claims = by_id(r)
    assert claims["ADR-0004.c1"].status == "HOLDING"  # structlog required, present
    assert claims["ADR-0001.c1"].status == "VIOLATED"  # pymongo next to PostgreSQL
    assert claims["ADR-0007.c1"].status == "UNKNOWN"  # free-form claim
    for c in r.claims:
        assert c.judged and c.verdict is not None and c.verdict.grounding == "VERIFIED"
        for ev in c.verdict.evidence:
            assert ev.ref.commit == r.metadata.commit and ev.ref.quote
    violated = claims["ADR-0001.c1"].verdict
    assert violated.evidence and all(e.relation == "alternative" for e in violated.evidence)
    assert {u.id for u in r.undocumented} >= {"UD-queue-kafka"}
    assert all(u.grounding == "VERIFIED" for u in r.undocumented)
    assert r.drafts and {d.record_id for d in r.drafts} == {u.id for u in r.undocumented}
    assert all(d.status == "DRAFT" and d.written_path is None for d in r.drafts)
    assert not (pyshop / "docs" / "adr" / "0008-use-kafka-for-queue.md").exists()
    assert r.could_not_verify == []
    assert r.timeline == []
    s = r.summary
    assert s.by_status["VIOLATED"] >= 1 and s.unknown == s.by_status["UNKNOWN"] >= 1
    decided = s.by_status["HOLDING"] + s.by_status["DRIFTING"] + s.by_status["VIOLATED"]
    assert s.drift_score == pytest.approx(
        (s.by_status["DRIFTING"] + s.by_status["VIOLATED"]) / decided
    )
    assert s.exit_code == 1
    assert r.metadata.mode == "offline" and r.metadata.provider is None
    assert r.metadata.repo == "pyshop" and len(r.metadata.commit) == 40


def test_grounding_summary_comes_from_the_ledger(pyshop, tmp_path):
    from driftwarden.models import GroundingResult

    ledger = Ledger(tmp_path / "lg")
    # a row written before the run must not be counted
    ledger.append(GroundingResult(check_id="G9", status="MISMATCH", reason="earlier"))
    r = run_scan(pyshop, config=Config(), mode="offline", ledger=ledger, draft_adrs=True)
    rows = [json.loads(x) for x in ledger.path.read_text(encoding="utf-8").splitlines()][1:]
    gs = r.grounding_summary
    assert set(gs.by_check) == {"G1", "G2", "G3", "G4", "G5", "G6"}
    assert gs.total == len(rows)
    for cid, cs in gs.by_check.items():
        mine = [x for x in rows if x["check_id"] == cid]
        assert cs.total == len(mine)
        assert cs.verified == sum(x["status"] == "VERIFIED" for x in mine)
        assert cs.pass_rate == (cs.verified / cs.total if cs.total else None)
    assert gs.by_check["G1"].total > len(r.decisions)  # decisions + claims
    assert gs.by_check["G5"].total > 0 and gs.by_check["G2"].total > 0


def test_tampered_decision_lands_in_could_not_verify(pyshop, tmp_path):
    adrs = scan_adrs(pyshop, Config())
    d = adrs.decisions[0]
    adrs.decisions[0] = d.model_copy(
        update={"source": d.source.model_copy(update={"quote": "We will use MongoDB."})}
    )
    r = scan(pyshop, tmp_path, adrs=adrs)
    item = next(i for i in r.could_not_verify if i.kind == "decision")
    assert item.id == d.id and item.check_id == "G1" and item.reasons[0]
    dec = next(x for x in r.decisions if x.id == d.id)
    assert not dec.judged and "G1" in (dec.not_judged_reason or "")
    assert not any(c.claim.decision_id == d.id for c in r.claims)
    assert r.summary.exit_code == 3  # G1 wins over VIOLATED


def test_tampered_evidence_is_could_not_verify_never_violated(pyshop, tmp_path, monkeypatch):
    real = Judge.evidence

    def tampered(self, claim):
        es = real(self, claim)
        if claim.id != "ADR-0001.c1":
            return es
        items = [
            e.model_copy(update={"ref": e.ref.model_copy(update={"quote": "import nothing"})})
            for e in es.candidates
        ]
        return es.model_copy(update={"candidates": items})

    monkeypatch.setattr(Judge, "evidence", tampered)
    r = scan(pyshop, tmp_path)
    v = by_id(r)["ADR-0001.c1"].verdict
    assert v.status == "UNKNOWN" and v.grounding == "MISMATCH" and v.proposed_status == "VIOLATED"
    kinds = {(i.kind, i.claim_id) for i in r.could_not_verify}
    assert ("verdict", "ADR-0001.c1") in kinds and ("evidence", "ADR-0001.c1") in kinds
    ev_items = [i for i in r.could_not_verify if i.kind == "evidence"]
    assert all(i.check_id in ("G2", "G3") and i.reasons for i in ev_items)
    assert "ADR-0001.c1" not in {c.id for c in r.verdicts("VIOLATED")}
    assert r.summary.exit_code == 1  # other claims are still VIOLATED; G2 is not exit 3


def test_every_ledger_mismatch_is_reported(pyshop, tmp_path, monkeypatch):
    """Catch-all: a failed verifier row the stages do not surface is still listed."""
    import driftwarden.pipeline as pipeline
    from driftwarden.models import GroundingResult

    real = pipeline.detect_undocumented

    def noisy(*a, **k):
        k["ledger"].append(
            GroundingResult(check_id="G5", status="MISMATCH", reason="stray", subject="ZZ-1")
        )
        return real(*a, **k)

    monkeypatch.setattr(pipeline, "detect_undocumented", noisy)
    r = scan(pyshop, tmp_path)
    item = next(i for i in r.could_not_verify if i.id == "ZZ-1")
    assert item.kind == "check" and item.check_id == "G5" and item.reasons == ["stray"]


# ------------------------------------------------------------------ status


ADR = """# {n}. {title}

## Status

{status}

## Context

Background jobs.

## Decision

We will not use Celery.
"""


def test_only_accepted_decisions_are_judged(make_repo, tmp_path):
    repo = make_repo(
        {
            "docs/adr/0001-a.md": ADR.format(n=1, title="No Celery", status="Accepted"),
            "docs/adr/0002-p.md": ADR.format(n=2, title="No Celery p", status="Proposed"),
            "docs/adr/0003-s.md": ADR.format(
                n=3, title="No Celery s", status="Superseded by ADR-0001"
            ),
            "docs/adr/0004-r.md": ADR.format(n=4, title="No Celery r", status="Rejected"),
            "requirements.txt": "celery==5.3.0\n",
            "app/worker.py": "import celery\n",
        }
    )
    r = scan(repo, tmp_path)
    decs = {d.id: d for d in r.decisions}
    assert decs["ADR-0001"].judged and decs["ADR-0001"].claim_ids
    for did, status in (
        ("ADR-0002", "proposed"),
        ("ADR-0003", "superseded"),
        ("ADR-0004", "rejected"),
    ):
        assert decs[did].status == status and not decs[did].judged
        assert "only accepted decisions are judged" in decs[did].not_judged_reason
        assert decs[did].claim_ids == [] and decs[did].g1.status == "VERIFIED"
    assert decs["ADR-0003"].superseded_by == "ADR-0001"
    assert {c.claim.decision_id for c in r.claims} == {"ADR-0001"}
    assert by_id(r)["ADR-0001.c1"].status == "VIOLATED"
    assert r.summary.decisions == 4 and r.summary.decisions_judged == 1


# ------------------------------------------------------------------ PR mode


def test_changed_paths_judge_everything_and_only_tag(pyshop, tmp_path):
    """Fable decision (Codex P2 #3/#4): PR mode judges every accepted claim; changed_paths
    only sets in_change."""
    full = scan(pyshop, tmp_path / "a")
    r = scan(pyshop, tmp_path / "b", changed_paths=["./docs/adr/0007-health-endpoint.md"])
    assert all(c.judged and c.verdict is not None for c in r.claims)
    assert {c.id: c.status for c in r.claims} == {c.id: c.status for c in full.claims}
    assert {c.id for c in r.claims if c.in_change} == {"ADR-0007.c1"}
    assert all(c.in_change is False for c in r.claims if c.id != "ADR-0007.c1")
    assert all(c.in_change is None for c in full.claims)
    assert r.summary.exit_code == full.summary.exit_code == 1  # nothing hidden
    assert r.metadata.changed_paths == ["docs/adr/0007-health-endpoint.md"]

    r2 = scan(pyshop, tmp_path / "c", changed_paths=["requirements.txt"])
    assert by_id(r2)["ADR-0001.c1"].in_change and not by_id(r2)["ADR-0007.c1"].in_change

    r3 = scan(pyshop, tmp_path / "d", changed_paths=[])
    assert not any(c.in_change for c in r3.claims) and r3.summary.exit_code == 1


def test_changed_file_beyond_the_evidence_cap_is_in_change(make_repo, tmp_path):
    """Codex P2: 51 files import celery; the judge caps a group at 50, so one file is not
    in the verdict's evidence. Changing exactly that file must still tag the claim."""
    files = {f"app/w{i:02d}.py": "import celery\n" for i in range(51)}
    files["docs/adr/0001-a.md"] = ADR.format(n=1, title="No Celery", status="Accepted")
    repo = make_repo(files)
    full = scan(repo, tmp_path / "a")
    v = by_id(full)["ADR-0001.c1"].verdict
    assert v.status == "VIOLATED"
    cited = {e.ref.path for e in v.evidence}
    hidden = sorted(set(f for f in files if f.startswith("app/")) - cited)
    assert hidden, "the test needs a file the capped evidence leaves out"
    r = scan(repo, tmp_path / "b", changed_paths=[hidden[0]])
    c = by_id(r)["ADR-0001.c1"]
    assert c.judged and c.status == "VIOLATED" and c.in_change is True
    assert r.summary.exit_code == 1


def test_deleting_the_last_required_occurrence_is_in_change(tmp_path):
    """Codex P2: the change deletes the only structlog import (and its requirement) while
    loguru is used elsewhere. The full scan says VIOLATED; PR mode must judge it too and tag
    it, although the deleted file is not among the evidence any more."""
    repo = copy_repo(tmp_path, FIXTURES / "judge_repos" / "pyshop", "pyshop-del")
    (repo / "src/shop/audit.py").write_text("import loguru\n", encoding="utf-8")
    req = repo / "requirements.txt"
    req.write_text(req.read_text(encoding="utf-8") + "loguru==0.7.2\n", encoding="utf-8")
    _commit(repo)
    (repo / "src/shop/log.py").unlink()
    lines = req.read_text(encoding="utf-8").splitlines(True)
    req.write_text("".join(x for x in lines if "structlog" not in x), encoding="utf-8")
    _commit(repo)
    full = scan(repo, tmp_path / "a")
    assert by_id(full)["ADR-0004.c1"].status == "VIOLATED"
    r = scan(repo, tmp_path / "b", changed_paths=["src/shop/log.py"])
    c = by_id(r)["ADR-0004.c1"]
    assert c.judged and c.status == "VIOLATED" and c.in_change is True
    assert "src/shop/log.py" not in {e.ref.path for e in c.verdict.evidence}
    assert not by_id(r)["ADR-0006.c1"].in_change  # forbid: a deletion cannot break it
    assert r.summary.exit_code == 1


def test_drafts_of_one_scan_get_distinct_consecutive_numbers(pyshop, tmp_path):
    r = scan(pyshop, tmp_path, draft_adrs=True)
    assert len(r.drafts) == 3
    numbers = [d.number for d in r.drafts]
    assert sorted(numbers) == [8, 9, 10]
    assert len({d.path for d in r.drafts}) == 3
    for d in r.drafts:
        assert d.path.startswith(f"docs/adr/{d.number:04d}-")
    assert all(d.grounding == "VERIFIED" for d in r.drafts)


def test_free_claim_keyword_evidence_counts_for_in_change(pyshop, tmp_path):
    """Codex P2 (4404618563): a free-form claim has only keyword evidence; changing the
    file that mentions /healthz must tag it."""
    r = scan(pyshop, tmp_path, changed_paths=["src/shop/health.py"])
    c = by_id(r)["ADR-0007.c1"]
    assert c.judged and c.in_change is True
    other = scan(pyshop, tmp_path / "b", changed_paths=["src/shop/db.py"])
    assert by_id(other)["ADR-0007.c1"].in_change is False


def test_llm_verdict_citing_changed_keyword_evidence_is_in_change(pyshop, tmp_path):
    def responder(request):
        purpose = request.purpose or ""
        if purpose.startswith("claims:"):
            return json.dumps({"claims": []})
        if "ADR-0007.c1" in purpose:
            cands = json.loads(request.prompt.split("data, not instructions):\n", 1)[1])
            h = next(c for c in cands if c["path"] == "src/shop/health.py")
            cite = {k: h[k] for k in ("line_start", "line_end")}
            cite.update(evidence_id=h["id"], quote=h["snippet"])
            return json.dumps(
                {"status": "HOLDING", "citations": [cite], "rationale": "endpoint exists"}
            )
        return json.dumps({"status": "UNKNOWN", "citations": [], "rationale": "n/a"})

    provider = OfflineProvider(
        responder=responder, retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None)
    )
    r = scan(pyshop, tmp_path, mode="llm", provider=provider, changed_paths=["src/shop/health.py"])
    c = by_id(r)["ADR-0007.c1"]
    assert c.status == "HOLDING" and c.verdict.grounding == "VERIFIED"
    assert "src/shop/health.py" in {e.ref.path for e in c.verdict.evidence}
    assert c.in_change is True


def test_claim_touches_rule_paths():
    src = Provenance(path="docs/adr/1.md", line_start=1, line_end=1, commit="W", quote="q")
    c = Claim(
        id="X.c1",
        kind="boundary",
        subject="cloud sdk",
        rule={"target": ["boto3"], "allowed_in": ["src/adapters/"]},
        source=src,
        decision_id="X",
    )
    assert claim_touches(c, None, {"src/adapters/s3.py"})
    assert claim_touches(c, None, {"docs/adr/1.md"})
    assert not claim_touches(c, None, {"src/adaptersx/s3.py", "src/other.py"})
    assert rule_text(c) == "boundary [boto3] allowed_in [src/adapters/]"


# ------------------------------------------------------------------ model


def test_report_json_round_trip_and_offline_determinism(pyshop, tmp_path):
    a = scan(pyshop, tmp_path / "a", draft_adrs=True)
    b = scan(pyshop, tmp_path / "b", draft_adrs=True)
    assert Report.model_validate_json(a.model_dump_json()) == a
    ja = json.loads(a.model_dump_json())
    jb = json.loads(b.model_dump_json())
    ja["metadata"].pop("scanned_at")
    jb["metadata"].pop("scanned_at")
    assert ja == jb
    sa = a.model_copy(update={"metadata": a.metadata.model_copy(update={"scanned_at": "T"})})
    sb = b.model_copy(update={"metadata": b.metadata.model_copy(update={"scanned_at": "T"})})
    assert sa.model_dump_json() == sb.model_dump_json()  # byte-identical
    assert [d.id for d in a.decisions] == sorted(d.id for d in a.decisions)


def test_round_trip_with_failures(pyshop, tmp_path):
    adrs = scan_adrs(pyshop, Config())
    d = adrs.decisions[2]
    adrs.decisions[2] = d.model_copy(
        update={"source": d.source.model_copy(update={"line_start": 1, "line_end": 1})}
    )
    r = scan(pyshop, tmp_path, adrs=adrs, draft_adrs=True)
    assert r.could_not_verify
    assert Report.model_validate_json(r.model_dump_json()) == r


def test_repo_without_commits_judges_the_worktree(tmp_path):
    repo = tmp_path / "fresh"
    shutil.copytree(FIXTURES / "judge_repos" / "pyshop", repo)
    git(repo, "init", "-q", "-b", "main")
    r = scan(repo, tmp_path)
    assert r.metadata.commit == "WORKTREE"
    assert by_id(r)["ADR-0001.c1"].status == "VIOLATED"
    assert r.undocumented == [] and any("needs a commit" in n for n in r.notes)


# ------------------------------------------------------------------ llm mode (scripted)


def test_llm_mode_uses_consistency_runner(pyshop, tmp_path):
    def responder(request):
        if (request.purpose or "").startswith("claims:"):
            return json.dumps({"claims": []})
        return json.dumps({"status": "UNKNOWN", "citations": [], "rationale": "not enough"})

    provider = OfflineProvider(
        responder=responder, retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None)
    )
    r = scan(pyshop, tmp_path, mode="llm", provider=provider)
    assert r.metadata.mode == "llm" and r.metadata.provider == "offline"
    free = by_id(r)["ADR-0007.c1"].verdict
    assert free.consistency is not None and free.consistency.basis == "vote"
    assert len(free.consistency.votes) == 3
    decided = by_id(r)["ADR-0001.c1"].verdict
    assert decided.status == "VIOLATED" and decided.consistency.basis == "deterministic"
    assert r.grounding_summary.by_check["G6"].total >= 1


# ------------------------------------------------------------------ CLI


def test_cli_exit_1_on_violation_and_json_out(pyshop, tmp_path):
    out = tmp_path / "report.json"
    res = runner.invoke(
        app, ["scan", str(pyshop), "--out", str(tmp_path / "o"), "--json-out", str(out)]
    )
    assert res.exit_code == 1, res.output
    r = Report.model_validate_json(out.read_text(encoding="utf-8"))
    assert r.summary.exit_code == 1 and r.metadata.mode == "offline"
    assert "VIOLATED (" in res.output and "ADR-0001.c1" in res.output
    assert "requirements.txt:2@" in res.output
    assert "Undocumented UD-queue-kafka" in res.output
    assert "Grounding (all checks):" in res.output
    assert "Not yet implemented: claim structuring" not in res.output
    assert "auto mode" in res.output  # fell back to offline: no key


def test_cli_exit_0(make_repo, tmp_path):
    repo = make_repo({"docs/adr/0001-a.md": ADR.format(n=1, title="x", status="Accepted")})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "HOLDING (1)" in res.output


def test_cli_exit_3_wins_over_1(pyshop, tmp_path, monkeypatch):
    real = cli.scan_adrs

    def tampered(*a, **k):
        res = real(*a, **k)
        d = res.decisions[3]
        res.decisions[3] = d.model_copy(
            update={"source": d.source.model_copy(update={"quote": "never said"})}
        )
        return res

    monkeypatch.setattr(cli, "scan_adrs", tampered)
    res = runner.invoke(app, ["scan", str(pyshop), "--out", str(tmp_path / "o")])
    assert res.exit_code == 3, res.output
    assert "Could not verify decision ADR-0004 [G1]" in res.output


def test_cli_draft_adrs_shown_not_written(pyshop, tmp_path):
    res = runner.invoke(app, ["scan", str(pyshop), "--out", str(tmp_path / "o"), "--draft-adrs"])
    assert res.exit_code == 1, res.output
    assert "Draft ADR for UD-queue-kafka" in res.output and "not written" in res.output
    assert res.output.count("status: proposed (draft)") == 3  # the markdown itself is shown
    assert "## Decision Outcome" in res.output
    assert git(pyshop, "status", "--porcelain", "--untracked-files=all").strip() == ""


def test_terminal_safe_neutralises_control_characters():
    from driftwarden.cli import terminal_safe

    assert terminal_safe("a\n\tb") == "a\n\tb"
    assert terminal_safe("x\x1b[31my\u202ez\x07") == "x\\u001b[31my\\u202ez\\u0007"


def test_cli_format_writes_nothing(pyshop, tmp_path):
    out = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(pyshop), "--out", str(out), "--format", "json,md"])
    assert "nothing was written" in res.output
    assert sorted(p.name for p in out.iterdir()) == ["logs"]


def _openai_without_model(repo: Path) -> None:
    (repo / "driftwarden.toml").write_text(
        'provider = "openai"\nbase_url = "http://127.0.0.1:9"\n', encoding="utf-8"
    )


def test_cli_auto_falls_back_when_provider_fails(pyshop, tmp_path):
    _openai_without_model(pyshop)
    res = runner.invoke(app, ["scan", str(pyshop), "--out", str(tmp_path / "o")])
    assert res.exit_code == 1, res.output
    assert "falling back to offline mode" in res.output and "mode=offline" in res.output


def test_cli_llm_mode_provider_failure_exits_2(pyshop, tmp_path):
    _openai_without_model(pyshop)
    res = runner.invoke(app, ["scan", str(pyshop), "--mode", "llm", "--out", str(tmp_path / "o")])
    assert res.exit_code == 2 and "failed to initialise" in res.output


def test_cli_llm_mode_without_key_exits_2(pyshop, tmp_path):
    res = runner.invoke(app, ["scan", str(pyshop), "--mode", "llm", "--out", str(tmp_path / "o")])
    assert res.exit_code == 2 and "ANTHROPIC_API_KEY" in res.output


def test_cli_help_documents_exit_codes():
    import re

    res = runner.invoke(app, ["scan", "--help"])
    assert res.exit_code == 0
    # Under GITHUB_ACTIONS / FORCE_COLOR typer forces a rich terminal and styles the help
    # (ANSI codes split "--json-out"); compare the plain text. This was the CI failure.
    plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", res.output)
    for text in ("--json-out", "--draft-adrs", "Exit codes", "VIOLATED", "mismatch"):
        assert text in plain


# Values cli.py may print without safe(): numbers and labels the CLI itself computes.
# Anything else interpolated into printed text must be safe(...) (D3).
CLI_TRUSTED_VALUES = {
    "__version__", "resolved", "len(decisions)", "len(judged)", "report.summary.claims",
    "len(group)", "len(report.notes)", "by.get(s, 0)", "s", "status", "colour[status]", "cid",
    "cs.verified",
    "cs.total", "gs.verified", "gs.total", "rate", "drift", "s.unknown", "s.could_not_verify",
    "s.undocumented", "s.drafts", "s.exit_code", "g1_ok", "len(result.skipped)",
    "','.join(fmts) or '(none)'", "', '.join(parts)", "check",
}  # fmt: skip


def _unsafe_print_values() -> list[str]:
    import ast
    import inspect

    import driftwarden.cli as mod

    bad: list[str] = []
    for node in ast.walk(ast.parse(inspect.getsource(mod))):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
        if name not in ("print", "add_row", "Panel", "Text", "Table"):
            continue
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            for sub in ast.walk(arg):
                if not isinstance(sub, ast.FormattedValue):
                    continue
                v = sub.value
                if isinstance(v, ast.Call) and getattr(v.func, "id", None) == "safe":
                    continue
                if sub.format_spec is not None or ast.unparse(v) in CLI_TRUSTED_VALUES:
                    continue
                bad.append(f"line {sub.lineno}: {ast.unparse(v)}")
            if name in ("add_row", "Text"):
                for a in node.args:
                    plain_call = isinstance(a, ast.Call) and getattr(a.func, "id", None) in (
                        "safe", "terminal_safe")  # fmt: skip
                    if not (plain_call or isinstance(a, ast.Constant) or ast.unparse(a) == "g"):
                        bad.append(f"line {a.lineno}: {name}({ast.unparse(a)})")
    return sorted(set(bad))


def test_malformed_ledger_record_is_reported_not_a_crash(pyshop, tmp_path, monkeypatch):
    """D2: a record that is not valid JSON (or not a row) becomes a 'check' item."""
    import driftwarden.pipeline as pipeline

    real = pipeline.detect_undocumented

    def corrupting(*a, **k):
        led = k["ledger"]
        with led.path.open("a", encoding="utf-8") as fh:
            fh.write('{"half a row\n[1, 2]\n{"run_id": "x", "check_id": "G2"}\n')
        return real(*a, **k)

    monkeypatch.setattr(pipeline, "detect_undocumented", corrupting)
    r = scan(pyshop, tmp_path)
    bad = [i for i in r.could_not_verify if i.id.startswith("ledger-record-")]
    assert len(bad) == 3 and all(i.kind == "check" and i.reasons for i in bad)
    assert "not valid JSON" in bad[0].reasons[0]
    assert Report.model_validate_json(r.model_dump_json()) == r


@pytest.mark.parametrize("ch", [" ", " ", "\x85"])
def test_line_separator_in_a_path_keeps_ledger_and_summary_whole(ch, make_repo, tmp_path):
    repo = make_repo(
        {
            "docs/adr/0001-a.md": ADR.format(n=1, title="No Celery", status="Accepted"),
            f"app/odd{ch}name.py": "import celery\n",
        }
    )
    ledger = Ledger(tmp_path / "lg")
    r = run_scan(repo, config=Config(), mode="offline", ledger=ledger)
    rows = ledger.path.read_text(encoding="utf-8").split("\n")[:-1]
    assert r.grounding_summary.total == len(rows) == len([json.loads(x) for x in rows])
    v = by_id(r)["ADR-0001.c1"].verdict
    # L-023 rule: a path with a control/separator character never verifies, so the finding
    # is Could not verify (fail closed) with the reason, never a crash and never a fact.
    assert (v.status, v.grounding, v.proposed_status) == ("UNKNOWN", "MISMATCH", "VIOLATED")
    assert any("control character" in x for x in v.reasons)
    assert any(i.kind == "verdict" and i.claim_id == "ADR-0001.c1" for i in r.could_not_verify)
    assert not any(i.id.startswith("ledger-record-") for i in r.could_not_verify)


def test_gitignore_and_go_mod_split_on_newline_only(tmp_path):
    from driftwarden.index.files import GitIgnore
    from driftwarden.index.imports import parse_go_mod

    p = tmp_path / ".gitignore"
    p.write_text("build out\r\nlogs\n", encoding="utf-8")
    gi = GitIgnore.from_file(p)
    assert gi.match("build out", False) is True  # one pattern, as git reads it
    assert gi.match("out", False) is None and gi.match("logs", False) is True
    mod, replaces = parse_go_mod("module x\n// a replace a => ./b\n")
    assert mod == "x" and replaces == []  # the comment line stays one line


def test_every_printed_value_goes_through_safe():
    """D3: an AST walk over cli.py; a new print path that skips safe() fails here."""
    assert _unsafe_print_values() == []


def test_safe_escapes_newlines_controls_and_markup():
    from driftwarden.cli import safe

    assert safe("a\nb") == "a\\u000ab"
    assert safe("\x1b]8;;http://e\x1b\\x\u202e") == "\\u001b]8;;http://e\\u001b\\x\\u202e"
    assert safe("[red]x[/red]") == "\\[red]x\\[/red]"


# ------------------------------------------------------------------ Codex round 5


def test_adr_deleted_only_in_worktree_still_documents_its_technology(pyshop, tmp_path):
    """Codex 4405326906: the detector must use the ADRs of the committed tree it judges."""
    clean = scan(pyshop, tmp_path / "a", draft_adrs=True)
    assert not any("postgres" in u.id for u in clean.undocumented)
    (pyshop / "docs/adr/0001-postgresql-only.md").unlink()  # not committed
    r = scan(pyshop, tmp_path / "b", draft_adrs=True)
    assert "ADR-0001" not in {d.id for d in r.decisions}  # the working-tree list lacks it
    assert [u.id for u in r.undocumented] == [u.id for u in clean.undocumented]
    assert [d.record_id for d in r.drafts] == [d.record_id for d in clean.drafts]
    assert not any("postgres" in i.id for i in r.could_not_verify)


class _FailingModel(OfflineProvider):
    """A non-offline provider whose every reply is unusable (not JSON)."""

    name = "scripted"
    offline = False


def test_cli_shows_llm_extraction_failures_as_warnings(pyshop, tmp_path, monkeypatch):
    """Codex 4405326918: a provider / extraction failure must reach the terminal."""
    provider = _FailingModel(
        responder=lambda _req: "not json", retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None)
    )
    monkeypatch.setattr(cli, "get_provider", lambda *_a, **_k: provider)
    res = runner.invoke(app, ["scan", str(pyshop), "--mode", "llm", "--out", str(tmp_path / "o")])
    assert res.exit_code == 1, res.output  # rule verdicts still stand
    assert "mode=llm" in res.output and "Notes (" in res.output
    assert "warning:" in res.output and "LLM structuring failed for ADR-0001" in res.output
    assert "LLM judge failed" in res.output


def test_is_failure_note():
    from driftwarden.cli import is_failure_note

    assert is_failure_note("ADR-1: LLM structuring failed for ADR-1: boom")
    assert is_failure_note("could not read ADR docs/adr/x.md: denied")
    assert not is_failure_note("ADR-1: 2 duplicate claim(s) merged")


def test_natural_key_handles_unicode_digit_characters():
    """Codex 4405326923: "²" and "①" pass str.isdigit() but int() rejects them."""
    for s in ("²", "①", "٣", "ADR-²", "a①b2", "x٣y10"):
        natural_key(s)  # never raises
    assert natural_key("c2") < natural_key("c10")
    assert sorted(["c10", "²", "c2", "①", "٣"], key=natural_key)  # total order, no crash


def test_scan_with_unicode_digit_adr_file_names(make_repo, tmp_path):
    files = {
        f"docs/adr/{name}.md": ADR.format(n=i, title=f"No Celery {i}", status="Accepted")
        for i, name in enumerate(("²", "①", "٣"), 1)
    }
    files["app/w.py"] = "import celery\n"
    r = scan(make_repo(files), tmp_path)
    assert len(r.decisions) == 3
    assert Report.model_validate_json(r.model_dump_json()) == r
    repo2 = make_repo(files, name="r2")
    res = runner.invoke(app, ["scan", str(repo2), "--out", str(tmp_path / "o")])
    assert res.exception is None or isinstance(res.exception, SystemExit), res.output
    assert res.exit_code in (0, 1, 3)
