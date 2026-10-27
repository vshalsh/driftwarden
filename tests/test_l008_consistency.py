"""L-008: consistency runner - judge each claim N times on one commit and vote (G6).

No network and no API key: the LLM path uses fake providers built on the real
BaseProvider (schema validation, cost log) or OfflineProvider with a scripted
responder; sockets are disabled for every test.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
from collections import Counter, defaultdict

import pytest

from driftwarden.grounding.ledger import Ledger
from driftwarden.judge import ConsistencyRunner, Judge, consistency
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.llm.base import BaseProvider, LLMRequest, LLMResponse, TransportError, Usage
from driftwarden.models import Claim, Verdict
from test_l007_judge import (
    _claim,
    candidates_in,
    cite,
    claim_in,
    claims_of,
    make_judge_repo,
    scripted,
)


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


@pytest.fixture
def judge_repo(tmp_path):
    return lambda name: make_judge_repo(tmp_path, name)


# ------------------------------------------------------------------ fakes


class FakeModel(BaseProvider):
    """A fake non-offline provider on the real BaseProvider path.

    ``fn(request) -> reply dict | str`` (str is sent verbatim); raising
    TransportError from ``fn`` simulates a provider failure. Every request is
    kept in ``requests``.
    """

    name = "fake"
    offline = False

    def __init__(self, fn):
        super().__init__("fake-model", retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None))
        self.fn = fn
        self.requests: list[LLMRequest] = []

    def _send(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        reply = self.fn(request)
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return LLMResponse(text=text, model=self.model, provider=self.name, usage=Usage())


def sequence(*statuses: str, quote: str | None = None):
    """Reply with ``statuses`` in call order (cycling), citing the first candidate."""
    calls = {"n": 0}

    def fn(req):
        status = statuses[calls["n"] % len(statuses)]
        calls["n"] += 1
        if status == "ERROR":
            raise TransportError("HTTP 503 from fake", status=503, retryable=False)
        if status == "UNKNOWN":
            return {"status": "UNKNOWN", "rationale": "", "citations": []}
        if status.startswith("FAKE-"):
            c = candidates_in(req.prompt)[0]
            return {
                "status": status[5:],
                "rationale": "",
                "citations": [cite(c, "def fabricated_line():")],
            }
        c = candidates_in(req.prompt)[0]
        return {"status": status, "rationale": f"r{calls['n']}", "citations": [cite(c, quote)]}

    return fn


def _free(judge_repo):
    repo = judge_repo("pyshop")
    return repo, claims_of(repo)["ADR-0007.c1"]  # free: "Every service exposes /healthz"


# ------------------------------------------------------------------ offline path


def test_offline_runs_once_and_matches_the_plain_judge(judge_repo):
    repo = judge_repo("pyshop")
    claims = list(claims_of(repo).values())
    judge = Judge(repo, mode="offline", provider=OfflineProvider())  # raises if called
    runner = ConsistencyRunner(judge)
    plain = {v.claim_id: v for v in Judge(repo, mode="offline").judge_all(claims)}
    for v in runner.run_all(claims):
        c = v.consistency
        assert c is not None and c.basis == "deterministic"
        assert (c.runs, c.executed, c.agreement, len(c.votes)) == (3, 1, True, 1)
        assert c.votes[0].status == v.status
        assert any("1 run stands for 3" in n for n in v.notes)
        p = plain[v.claim_id]
        assert (v.status, v.grounding, v.evidence) == (p.status, p.grounding, p.evidence)
    s = runner.summary()
    assert s["deterministic"] == s["claims"] == len(claims)
    assert s["voted"] == 0 and s["consistency_rate"] is None
    assert s["runs_executed"] == len(claims) and s["model_calls"] == 0


def test_offline_full_runs_are_identical(judge_repo, tmp_path):
    repo = judge_repo("pyshop")
    claims = list(claims_of(repo).values())
    ledger = Ledger(tmp_path / "l", run_id="off")
    runner = ConsistencyRunner(
        Judge(repo, mode="offline", ledger=ledger), dedupe_deterministic=False
    )
    plain = {v.claim_id: v for v in Judge(repo, mode="offline").judge_all(claims)}
    for v in runner.run_all(claims):
        c = v.consistency
        assert c.basis == "vote" and c.executed == 3 and c.agreement
        assert len({vt.model_dump_json(exclude={"run"}) for vt in c.votes}) == 1
        p = plain[v.claim_id]
        assert (v.status, v.grounding, v.evidence) == (p.status, p.grounding, p.evidence)
        assert any("consistent across 3 runs" in n for n in v.notes)
    assert runner.summary()["consistency_rate"] == 1.0
    assert ledger.check_rate("G6") == 1.0
    assert ledger.summary()["by_check"]["G6"] == {"VERIFIED": len(claims), "MISMATCH": 0}


_DETERMINISM_SCRIPT = r"""
import json, sys
from driftwarden.claims import structure_scan
from driftwarden.discover.adr import scan_adrs
from driftwarden.judge import ConsistencyRunner, Judge
repo = sys.argv[1]
claims = [c for s in structure_scan(scan_adrs(repo).decisions, repo, mode="offline")
          for c in s.claims]
out = []
for dedupe in (True, False):
    r = ConsistencyRunner(Judge(repo, mode="offline"), dedupe_deterministic=dedupe)
    out.append([v.model_dump(mode="json") for v in r.run_all(claims)])
    out.append(r.summary())
print(json.dumps(out, sort_keys=True))
"""


def test_offline_output_is_identical_across_processes_and_hash_seeds(judge_repo):
    repo = judge_repo("nodeapp")
    outs = set()
    for seed in ("0", "1", "4242", "random"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        proc = subprocess.run(
            [sys.executable, "-c", _DETERMINISM_SCRIPT, str(repo)],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        outs.add(proc.stdout)
    assert len(outs) == 1
    data = json.loads(outs.pop())
    assert data[0] and all(v["consistency"]["basis"] == "deterministic" for v in data[0])
    assert all(v["consistency"]["executed"] == 3 for v in data[2])


# ------------------------------------------------------------------ LLM path: votes


def test_each_run_is_an_independent_model_call_on_the_same_evidence(judge_repo):
    repo, claim = _free(judge_repo)
    model = FakeModel(sequence("HOLDING"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model)).run(claim)
    assert len(model.requests) == 3  # nothing cached or deduplicated
    assert [r.purpose for r in model.requests] == [f"judge:{claim.id}#run{k}/3" for k in (1, 2, 3)]
    assert len({r.prompt for r in model.requests}) == 1  # same claim, same evidence
    assert len({r.system for r in model.requests}) == 1
    assert [r["purpose"] for r in model.cost_log.records] == [r.purpose for r in model.requests]
    assert (v.status, v.grounding, v.origin) == ("HOLDING", "VERIFIED", "llm")
    assert v.consistency.basis == "vote" and v.consistency.agreement


def test_unanimous_vote_keeps_status_and_reverifies_the_evidence(judge_repo, tmp_path, monkeypatch):
    repo, claim = _free(judge_repo)
    seen = []
    real_gate = consistency.gate

    def spy(verdict, root, **kw):
        seen.append(verdict)
        return real_gate(verdict, root, **kw)

    monkeypatch.setattr(consistency, "gate", spy)
    ledger = Ledger(tmp_path / "l", run_id="u")
    # Run 2 cites a sub-range quote of the same candidate: the union keeps both.
    calls = {"n": 0}

    def fn(req):
        calls["n"] += 1
        c = candidates_in(req.prompt)[0]
        q = "healthz" if calls["n"] == 2 else None
        return {"status": "HOLDING", "rationale": "ok", "citations": [cite(c, q)]}

    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=FakeModel(fn), ledger=ledger))
    v = runner.run(claim)
    assert (v.status, v.grounding) == ("HOLDING", "VERIFIED")
    assert [e.ref.quote == "healthz" for e in v.evidence] == [False, True]
    assert len(seen) == 1 and seen[0].evidence == v.evidence  # voted evidence re-gated
    assert v.checks and all(c.status == "VERIFIED" for c in v.checks)
    assert len(v.checks) == len(v.evidence)  # fresh G2 per voted item, no stale run checks
    assert [vt.status for vt in v.consistency.votes] == ["HOLDING"] * 3
    rows = [json.loads(x) for x in ledger.path.read_text().splitlines()]
    g6 = [r for r in rows if r["check_id"] == "G6"]
    assert len(g6) == 1 and g6[0]["status"] == "VERIFIED"
    assert g6[0]["reason"] == "3/3 runs agree: HOLDING,HOLDING,HOLDING"
    assert g6[0]["subject"].startswith(claim.id + "@")
    assert g6[0]["provenance"]["path"] == claim.source.path
    Verdict.model_validate_json(v.model_dump_json())  # round-trips with the vote record


def test_disagreement_becomes_unknown_with_the_votes_recorded(judge_repo, tmp_path):
    repo, claim = _free(judge_repo)
    ledger = Ledger(tmp_path / "l", run_id="d")
    model = FakeModel(sequence("HOLDING", "VIOLATED", "HOLDING"))
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=model, ledger=ledger))
    v = runner.run(claim)
    assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED")
    assert v.reasons == ["inconsistent across runs: HOLDING,VIOLATED,HOLDING"]
    assert v.rationale == v.reasons[0]
    assert v.evidence == [] and v.proposed_status is None
    c = v.consistency
    assert (c.runs, c.executed, c.basis, c.agreement) == (3, 3, "vote", False)
    assert [vt.status for vt in c.votes] == ["HOLDING", "VIOLATED", "HOLDING"]
    assert all(vt.evidence for vt in c.votes)  # what each run cited stays on record
    assert ledger.check_rate("G6") == 0.0
    assert runner.summary()["disagreed"] == 1


def test_a_mismatched_run_makes_the_vote_could_not_verify(judge_repo):
    repo, claim = _free(judge_repo)
    model = FakeModel(sequence("VIOLATED", "FAKE-VIOLATED", "VIOLATED"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model)).run(claim)
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
    assert v.display_status == "Could not verify"
    assert v.reasons and v.reasons[0].startswith("run 2: ")
    assert any("quote not" in r for r in v.reasons)
    assert "inconsistent across runs: VIOLATED,UNKNOWN,VIOLATED" in v.reasons
    assert v.evidence and v.evidence[0].ref.quote == "def fabricated_line():"  # stays listed
    assert v.consistency.votes[1].grounding == "MISMATCH"


def test_every_run_mismatched_is_consistent_but_could_not_verify(judge_repo):
    repo, claim = _free(judge_repo)
    model = FakeModel(sequence("FAKE-HOLDING"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model)).run(claim)
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
    assert v.consistency.agreement and v.proposed_status == "HOLDING"
    assert len(v.evidence) == 1  # deduplicated across runs
    assert [r[:6] for r in v.reasons if r.startswith("run ")] == ["run 1:", "run 2:", "run 3:"]


def test_provider_error_in_one_run_is_unknown_not_a_crash(judge_repo, tmp_path):
    repo, claim = _free(judge_repo)
    ledger = Ledger(tmp_path / "l", run_id="e")
    model = FakeModel(sequence("HOLDING", "ERROR", "HOLDING"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model, ledger=ledger)).run(claim)
    assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED")
    assert v.reasons[0] == "inconsistent across runs: HOLDING,UNKNOWN,HOLDING"
    assert any(r.startswith("run 2 failed: TransportError") and "503" in r for r in v.reasons)
    vt = v.consistency.votes[1]
    assert vt.status == "UNKNOWN" and vt.error and not v.consistency.agreement
    assert ledger.check_rate("G6") == 0.0


def test_all_runs_failing_is_unknown_with_every_error(judge_repo):
    repo, claim = _free(judge_repo)
    model = scripted(lambda req: "not json", attempts=1)  # SchemaValidationError each run
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model)).run(claim)
    assert v.status == "UNKNOWN" and not v.consistency.agreement
    assert sum("SchemaValidationError" in r for r in v.reasons) == 3


def test_runs_parameter(judge_repo):
    repo, claim = _free(judge_repo)
    judge = Judge(repo, mode="llm", provider=FakeModel(sequence("HOLDING")))
    for bad in (0, -1, True, 2.0, "3"):
        with pytest.raises(ValueError):
            ConsistencyRunner(judge, runs=bad)
    model = FakeModel(sequence("HOLDING", "VIOLATED"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model), runs=5).run(claim)
    assert v.reasons == ["inconsistent across runs: HOLDING,VIOLATED,HOLDING,VIOLATED,HOLDING"]
    assert len(model.requests) == 5
    one = ConsistencyRunner(Judge(repo, mode="llm", provider=FakeModel(sequence("HOLDING"))), 1)
    v1 = one.run(claim)
    assert v1.status == "HOLDING" and v1.consistency.executed == 1


# ------------------------------------------------------------------ cost control


def test_rule_decided_claims_make_one_model_call(judge_repo):
    repo = judge_repo("pyshop")
    claim = claims_of(repo)["ADR-0001.c1"]  # PostgreSQL only -> rules say VIOLATED
    model = FakeModel(sequence("HOLDING", "UNKNOWN", "DRIFTING"))
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=model))
    v = runner.run(claim)
    assert len(model.requests) == 1
    assert (v.status, v.origin, v.grounding) == ("VIOLATED", "rule", "VERIFIED")
    assert v.consistency.basis == "deterministic" and v.consistency.executed == 1
    assert any("rules decided" in n for n in v.notes)
    assert v.proposed_status == "HOLDING"  # the model's proposal is still on record
    # Forcing all runs changes nothing: the rule verdict stands every time.
    model = FakeModel(sequence("HOLDING", "UNKNOWN", "DRIFTING"))
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=model), dedupe_deterministic=False)
    v = runner.run(claim)
    assert len(model.requests) == 3
    assert v.status == "VIOLATED" and v.consistency.agreement


def test_rule_decided_claim_survives_a_model_error(judge_repo):
    repo = judge_repo("pyshop")
    claim = claims_of(repo)["ADR-0001.c1"]
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=FakeModel(sequence("ERROR")))).run(claim)
    assert v.status == "VIOLATED" and v.consistency.basis == "deterministic"
    assert v.consistency.votes[0].error  # recorded, not hidden
    assert any("LLM judge failed" in n for n in v.notes)


def test_rule_unknown_claims_are_voted(judge_repo):
    repo = judge_repo("pyshop")
    claim = _claim("require", {"require": ["left-pad"]}, cid="X.req")  # absent: UNKNOWN
    model = FakeModel(sequence("UNKNOWN"))
    v = ConsistencyRunner(Judge(repo, mode="llm", provider=model)).run(claim)
    assert len(model.requests) == 3 and v.consistency.basis == "vote"


# ------------------------------------------------------------------ G6 run


WORDS = [
    "Every service exposes /healthz",
    "logging is structured json",
    "events are published to the broker",
    "reports read from the database",
    "storage goes through adapters",
    "the catalog module is legacy",
    "connection pooling for db",
    "zzqx nothing matches this",
]
PROFILES = ["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN", "flaky", "flaky", "error", "lie"]


def _g6_claims(n: int) -> list[Claim]:
    return [_claim("free", {"text": WORDS[i % len(WORDS)]}, cid=f"G6.c{i:03d}") for i in range(n)]


def test_g6_flaky_model_over_200_claim_runs(judge_repo, tmp_path, capsys):
    repo = judge_repo("pyshop")
    rng = random.Random(20261027)
    claims = _g6_claims(90)
    profile = {c.id: PROFILES[rng.randrange(len(PROFILES))] for c in claims}
    for i, c in enumerate(claims[: len(PROFILES)]):  # every profile at least once
        profile[c.id] = PROFILES[i]
    replies: dict[str, list[tuple[str, str]]] = defaultdict(list)  # id -> [(kind, status)]

    def fn(req):
        cid = claim_in(req.prompt)["id"]
        cands = candidates_in(req.prompt)
        p = profile.get(cid, "rule")
        run = len(replies[cid]) + 1
        if p == "error" and run == 2:
            replies[cid].append(("error", "UNKNOWN"))
            raise TransportError("fake outage", status=500, retryable=False)
        if p == "flaky":
            status = rng.choice(["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN"])
        elif p in ("error", "lie"):
            status = "VIOLATED"
        elif p == "rule":
            status = rng.choice(["HOLDING", "VIOLATED"])
        else:
            status = p
        if status == "UNKNOWN" or not cands:
            replies[cid].append(("ok", "UNKNOWN"))
            return {"status": "UNKNOWN", "rationale": "", "citations": []}
        if p == "lie" and run == 3:
            replies[cid].append(("lie", "UNKNOWN"))
            return {"status": "VIOLATED", "rationale": "", "citations": [cite(cands[0], "x=1")]}
        replies[cid].append(("ok", status))
        return {"status": status, "rationale": "", "citations": [cite(cands[0])]}

    ledger = Ledger(tmp_path / "l", run_id="g6")
    model = FakeModel(fn)
    judge = Judge(repo, mode="llm", provider=model, ledger=ledger)
    runner = ConsistencyRunner(judge)
    verdicts = {v.claim_id: v for v in runner.run_all(claims)}
    rule_claims = list(claims_of(repo).values())
    rule_verdicts = runner.run_all(rule_claims)

    claim_runs = sum(len(r) for cid, r in replies.items() if cid.startswith("G6."))
    assert claim_runs == 3 * len(claims) >= 200

    stable = disagree = violated = 0
    for c in claims:
        v, rs = verdicts[c.id], replies[c.id]
        kinds = {k for k, _ in rs}
        statuses = [s for _, s in rs]
        assert [vt.status for vt in v.consistency.votes] == statuses
        if "lie" in kinds:
            assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
        elif "error" in kinds or len(set(statuses)) > 1:
            disagree += 1
            assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED"), c.id
            assert v.reasons[0] == "inconsistent across runs: " + ",".join(statuses)
            assert not v.consistency.agreement
        else:
            assert (v.status, v.grounding) == (statuses[0], "VERIFIED"), c.id
            assert v.consistency.agreement
            if profile[c.id] not in ("flaky",):
                stable += 1
                if statuses[0] != "UNKNOWN":
                    assert statuses[0] == profile[c.id]  # stable claims keep their status
        if v.status == "VIOLATED":  # only a unanimous, verified VIOLATED survives the vote
            violated += 1
            assert statuses == ["VIOLATED"] * 3 and kinds == {"ok"}
            assert v.grounding == "VERIFIED" and all(x.status == "VERIFIED" for x in v.checks)
    assert stable and disagree and violated

    # Rule-decided claims: one model call each, the rule status regardless of the model.
    offline = {v.claim_id: v for v in Judge(repo, mode="offline").judge_all(rule_claims)}
    for v in rule_verdicts:
        if offline[v.claim_id].status != "UNKNOWN":
            assert v.consistency.basis == "deterministic"
            assert len(replies[v.claim_id]) == 1
            assert v.status == offline[v.claim_id].status

    s = runner.summary()
    voted = [v for v in [*verdicts.values(), *rule_verdicts] if v.consistency.basis == "vote"]
    agreed = sum(v.consistency.agreement for v in voted)
    assert s["voted"] == len(voted) and s["agreed"] == agreed
    assert s["consistency_rate"] == pytest.approx(agreed / len(voted))
    assert ledger.check_rate("G6") == pytest.approx(s["consistency_rate"])
    g6 = ledger.summary()["by_check"]["G6"]
    assert g6 == {"VERIFIED": agreed, "MISMATCH": len(voted) - agreed}
    assert s["model_calls"] == len(model.requests)
    final = Counter(v.display_status for v in verdicts.values())
    with capsys.disabled():
        print(
            f"\nG6: {claim_runs} claim runs over {len(claims)} claims; "
            f"voted {s['voted']}, agreed {s['agreed']}, disagreed {s['disagreed']}, "
            f"consistency rate {s['consistency_rate']:.3f}; deterministic {s['deterministic']}; "
            f"model calls {s['model_calls']}; final {dict(sorted(final.items()))}"
        )
