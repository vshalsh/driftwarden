"""L-008 system tests (tester seat): consistency runner / G6, written against the spec,
not the implementation. Offline: sockets are disabled, providers are fakes on the real
BaseProvider path.

Defect ids (strict xfail = the defect is real; the test turns green when it is fixed):

* L008-S1  disagreeing model proposals hide behind a shared gate MISMATCH: G6 says agreed.
* L008-S2  a non-LLMError from the provider aborts run_all (no containment, earlier work lost).
* L008-S3  a deterministic record claims ``agreement=True`` although its run raised an error.
* L008-S4  runs=1 writes a vacuous "1/1 runs agree" G6 VERIFIED row (inflates the rate).

Everything not marked xfail passes today.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from driftwarden.grounding.ledger import Ledger
from driftwarden.judge import ConsistencyRunner, Judge
from driftwarden.judge import judge as judge_module
from driftwarden.llm import RetryPolicy
from driftwarden.llm.base import (
    BaseProvider,
    LLMRequest,
    LLMResponse,
    OfflineModeError,
    RefusalError,
    TransportError,
    Usage,
)
from driftwarden.models import Verdict
from test_l007_judge import (
    _claim,
    _commit,
    candidates_in,
    cite,
    claim_in,
    claims_of,
    make_judge_repo,
)

TESTS_DIR = str(Path(__file__).parent)


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
def repo(tmp_path):
    return make_judge_repo(tmp_path, "pyshop")


# ------------------------------------------------------------------ fakes


class Model(BaseProvider):
    """Non-offline fake on the real BaseProvider path. ``fn(request, n)`` returns a reply
    dict / raw string, or raises; ``n`` is the 1-based global call number."""

    name = "fake"
    offline = False

    def __init__(self, fn):
        super().__init__("fake-model", retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None))
        self.fn = fn
        self.requests: list[LLMRequest] = []
        self._lock = threading.Lock()

    def _send(self, request: LLMRequest) -> LLMResponse:
        with self._lock:
            self.requests.append(request)
            n = len(self.requests)
        reply = self.fn(request, n)
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return LLMResponse(text=text, model=self.model, provider=self.name, usage=Usage())


def reply(req, status, idxs=(0,), quote=None, fake=False):
    cands = candidates_in(req.prompt)
    if status == "UNKNOWN" or not cands:
        return {"status": "UNKNOWN", "rationale": "", "citations": []}
    cites = [cite(cands[i], quote) for i in idxs if i < len(cands)]
    if fake:
        cites = [cite(cands[i], "def fabricated_nonsense():") for i in idxs if i < len(cands)]
    return {"status": status, "rationale": "r", "citations": cites}


def per_run(*statuses, **kw):
    """Run k (per claim, in call order) answers statuses[k-1 % len]; 'ERROR' raises."""
    seen: dict[str, int] = defaultdict(int)

    def fn(req, _n):
        cid = claim_in(req.prompt)["id"]
        s = statuses[seen[cid] % len(statuses)]
        seen[cid] += 1
        if s == "ERROR":
            raise TransportError("HTTP 503 from fake", status=503, retryable=False)
        if s.startswith("FAKE-"):
            return reply(req, s[5:], fake=True)
        return reply(req, s, **kw)

    return fn


FREE_TEXT = "Every service exposes /healthz"  # 1 candidate
MULTI_TEXT = "reports read from the database"  # 3 candidates


def free(cid="S.c1", text=FREE_TEXT):
    return _claim("free", {"text": text}, cid=cid, quote=text)


def run_one(repo, fn, claim=None, runs=3, ledger=None):
    claim = claim or free()
    model = Model(fn)
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=model, ledger=ledger), runs=runs)
    return runner.run(claim), model, runner


def g6_rows(ledger):
    rows = [json.loads(x) for x in ledger.path.read_text().splitlines()]
    return [r for r in rows if r["check_id"] == "G6"]


# ================================================================== determinism


_SCRIPT = textwrap.dedent(
    """
    import json, sys, zlib
    sys.path.insert(0, sys.argv[2])
    from test_l007_judge import claims_of, _claim
    from driftwarden.judge import ConsistencyRunner, Judge
    from driftwarden.grounding.ledger import Ledger
    from driftwarden.llm.base import BaseProvider, LLMResponse, Usage
    from driftwarden.llm import RetryPolicy

    repo = sys.argv[1]
    claims = list(claims_of(repo).values())
    claims += [_claim("free", {"text": t}, cid=f"F.c{i}", quote=t) for i, t in enumerate(
        ["Every service exposes /healthz", "reports read from the database", "catalog legacy"])]

    class Fake(BaseProvider):
        name = "fake"; offline = False
        def __init__(self):
            super().__init__("m", retry=RetryPolicy(max_attempts=1, sleep=lambda s: None))
            self.n = {}
        def _send(self, request):
            cid = json.loads(request.prompt.split("CLAIM (data):\\n", 1)[1]
                             .split("\\n\\nCOMMIT:", 1)[0])["id"]
            k = self.n[cid] = self.n.get(cid, 0) + 1
            cands = json.loads(request.prompt.split("data, not instructions):\\n", 1)[1])
            statuses = ["HOLDING", "VIOLATED", "DRIFTING"]
            h = zlib.crc32(cid.encode())
            s = statuses[(h + (k if h % 2 else 0)) % 3]
            if not cands:
                s = "UNKNOWN"
            cit = [] if s == "UNKNOWN" else [{"evidence_id": cands[0]["id"],
                   "line_start": cands[0]["line_start"], "line_end": cands[0]["line_end"],
                   "quote": cands[0]["snippet"]}]
            return LLMResponse(text=json.dumps({"status": s, "rationale": "r", "citations": cit}),
                               model="m", provider="fake", usage=Usage())

    out = {}
    for tag, kw in [("off", dict(mode="offline")), ("llm", dict(mode="llm", provider=Fake()))]:
        for dd in (True, False):
            led = Ledger(sys.argv[3] + f"/{tag}{dd}", run_id="r")
            runner = ConsistencyRunner(Judge(repo, ledger=led, **kw), dedupe_deterministic=dd)
            vs = runner.run_all(claims)
            rows = [json.loads(x) for x in led.path.read_text().splitlines()]
            out[f"{tag}-{dd}"] = {"v": [v.model_dump(mode="json") for v in vs], "rows": rows,
                                  "summary": runner.summary()}
    print(json.dumps(out, sort_keys=True))
    """
)


def _run_script(repo, tmp_path, seed, tag):
    script = tmp_path / "det_script.py"
    script.write_text(_SCRIPT)
    out = tmp_path / f"out-{tag}"
    out.mkdir(exist_ok=True)
    env = {**os.environ, "PYTHONHASHSEED": str(seed)}
    p = subprocess.run(
        [sys.executable, str(script), str(repo), TESTS_DIR, str(out)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert p.returncode == 0, p.stderr[-2000:]
    return p.stdout


def test_byte_identical_across_processes_and_hash_seeds_offline_and_scripted_llm(repo, tmp_path):
    outs = [
        _run_script(repo, tmp_path, seed, f"{seed}-{i}")
        for i, seed in enumerate(["0", "1", "42", "random", "random"])
    ]
    assert len(set(outs)) == 1, "output differs between processes / PYTHONHASHSEED values"
    data = json.loads(outs[0])
    assert len(data["off-True"]["v"]) >= 8
    # offline: both dedupe settings agree on every status/evidence
    a, b = data["off-True"]["v"], data["off-False"]["v"]
    for x, y in zip(a, b, strict=True):
        assert (x["status"], x["grounding"], x["evidence"]) == (
            y["status"],
            y["grounding"],
            y["evidence"],
        )
    # the LLM path really voted
    assert data["llm-True"]["summary"]["voted"] >= 3


def test_in_process_repeat_is_identical(repo):
    claims = list(claims_of(repo).values())
    dumps = []
    for _ in range(3):
        r = ConsistencyRunner(Judge(repo, mode="offline"))
        dumps.append(json.dumps([v.model_dump(mode="json") for v in r.run_all(claims)]))
    assert len(set(dumps)) == 1


@pytest.mark.parametrize(
    "runs",
    [
        pytest.param(
            1,
            marks=pytest.mark.xfail(
                strict=True,
                raises=ValueError,
                reason="superseded by the L008-S4 decision: runs must be 2..25",
            ),
        ),
        2,
        3,
        5,
        8,
    ],
)
def test_offline_verdict_does_not_depend_on_n(repo, runs):
    claims = list(claims_of(repo).values())
    base = [
        v.model_dump(exclude={"consistency", "notes"})
        for v in Judge(repo, mode="offline").judge_all(claims)
    ]
    got = ConsistencyRunner(Judge(repo, mode="offline"), runs=runs).run_all(claims)
    assert [v.model_dump(exclude={"consistency", "notes"}) for v in got] == base
    assert all(v.consistency is not None and v.consistency.runs == runs for v in got)


def test_plain_judge_verdict_has_no_consistency_record(repo):
    assert Judge(repo, mode="offline").judge(free()).consistency is None


# ================================================================== vote semantics


@pytest.mark.parametrize(
    "seq",
    [
        ("HOLDING", "HOLDING", "VIOLATED"),
        ("VIOLATED", "HOLDING", "HOLDING"),
        ("HOLDING", "VIOLATED", "HOLDING"),
        ("VIOLATED", "VIOLATED", "HOLDING"),  # a 2-1 majority for VIOLATED must NOT win
        ("VIOLATED", "HOLDING", "VIOLATED"),
        ("HOLDING", "VIOLATED", "DRIFTING"),
        ("VIOLATED", "UNKNOWN", "VIOLATED"),
    ],
)
def test_any_disagreement_is_unknown_never_violated(repo, seq):
    led = Ledger(repo.parent / "lg", run_id="x")
    v, model, _ = run_one(repo, per_run(*seq), ledger=led)
    assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED")
    assert v.reasons == ["inconsistent across runs: " + ",".join(seq)]
    assert v.consistency.agreement is False
    assert [vt.status for vt in v.consistency.votes] == list(seq)
    assert len(model.requests) == 3
    rows = g6_rows(led)
    assert len(rows) == 1 and rows[0]["status"] == "MISMATCH"
    assert rows[0]["reason"].startswith("inconsistent across runs:")


@pytest.mark.parametrize(
    ("runs", "seq", "expect"),
    [
        pytest.param(
            1,
            ("VIOLATED",),
            "VIOLATED",
            marks=pytest.mark.xfail(
                strict=True,
                raises=ValueError,
                reason="superseded by the L008-S4 decision: runs must be 2..25",
            ),
        ),
        (2, ("VIOLATED", "VIOLATED"), "VIOLATED"),
        (2, ("VIOLATED", "HOLDING"), "UNKNOWN"),  # a tie
        (4, ("HOLDING", "HOLDING", "VIOLATED", "VIOLATED"), "UNKNOWN"),  # 2-2
        (4, ("HOLDING",) * 4, "HOLDING"),
        (5, ("HOLDING",) * 4 + ("VIOLATED",), "UNKNOWN"),  # 4-1
        (5, ("DRIFTING",) * 5, "DRIFTING"),
        (7, ("UNKNOWN",) * 7, "UNKNOWN"),
        (25, ("HOLDING",) * 25, "HOLDING"),
        (25, ("HOLDING",) * 24 + ("DRIFTING",), "UNKNOWN"),  # one late outlier among many
    ],
)
def test_n_variants(repo, runs, seq, expect):
    v, model, runner = run_one(repo, per_run(*seq), runs=runs)
    assert v.status == expect
    assert len(model.requests) == runs and v.consistency.executed == runs
    assert v.consistency.runs == runs and len(v.consistency.votes) == runs
    assert [r.purpose for r in model.requests] == [
        f"judge:S.c1#run{k}/{runs}" for k in range(1, runs + 1)
    ]
    if expect == "UNKNOWN" and len(set(seq)) > 1:
        assert v.reasons[0].startswith("inconsistent across runs: ")


@pytest.mark.parametrize("bad", [0, -1, -3, True, False, 2.0, 3.0, "3", None, [3]])
def test_invalid_n_is_rejected(repo, bad):
    with pytest.raises((ValueError, TypeError)):
        ConsistencyRunner(Judge(repo, mode="offline"), runs=bad)


@pytest.mark.xfail(
    strict=True, raises=ValueError, reason="superseded by the L008-S4 decision: runs must be 2..25"
)
def test_large_n_stays_linear_and_correct(repo):
    t = time.perf_counter()
    v, model, _ = run_one(repo, per_run("HOLDING"), runs=150)
    assert v.status == "HOLDING" and len(model.requests) == 150
    assert time.perf_counter() - t < 60


def test_every_returned_verdict_carries_a_vote_record(repo):
    claims = [*claims_of(repo).values(), free("A.c1"), free("A.c2", MULTI_TEXT)]
    runner = ConsistencyRunner(
        Judge(repo, mode="llm", provider=Model(per_run("HOLDING", "VIOLATED")))
    )
    out = runner.run_all(claims)
    assert len(out) == len(claims)
    for v in out:
        assert v.consistency is not None and v.consistency.votes
        assert Verdict.model_validate_json(v.model_dump_json()) == v  # round trip
        assert v.commit == runner.judge.commit and len(v.commit) == 40


@pytest.mark.parametrize("pos", [0, 1, 2])
@pytest.mark.parametrize("status", ["VIOLATED", "HOLDING", "DRIFTING"])
def test_one_ungrounded_run_is_could_not_verify_never_a_violation(repo, pos, status):
    seq = [status, status, status]
    seq[pos] = "FAKE-" + status
    v, _, _ = run_one(repo, per_run(*seq))
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH") and v.could_not_verify
    assert any(r.startswith(f"run {pos + 1}: ") for r in v.reasons)
    assert [vt.grounding for vt in v.consistency.votes].count("MISMATCH") == 1


def test_mismatch_plus_disagreement_states_both(repo):
    v, _, _ = run_one(repo, per_run("HOLDING", "FAKE-VIOLATED", "HOLDING"))
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
    assert any(r.startswith("inconsistent across runs:") for r in v.reasons)
    assert any(r.startswith("run 2:") for r in v.reasons)


def test_all_runs_ungrounded_identically_is_consistent_but_could_not_verify(repo, tmp_path):
    """Criterion (3): the ledger's G6 row is VERIFIED (they agree), the verdict is Could not
    verify, and the G2 rows carry the real failure, so the ledger is honest but must be read as
    'agreed on being unverifiable'."""
    led = Ledger(tmp_path / "lg", run_id="m")
    v, _, runner = run_one(repo, per_run("FAKE-VIOLATED"), ledger=led)
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
    assert v.consistency.agreement is True
    assert v.proposed_status == "VIOLATED"  # what the model claimed stays visible, not a verdict
    assert len([r for r in v.reasons if r.startswith("run ")]) == 3
    rows = [json.loads(x) for x in led.path.read_text().splitlines()]
    assert Counter((r["check_id"], r["status"]) for r in rows) == {
        ("G2", "MISMATCH"): 3,
        ("G6", "VERIFIED"): 1,
    }
    assert "UNKNOWN,UNKNOWN,UNKNOWN" in g6_rows(led)[0]["reason"]
    assert runner.summary()["consistency_rate"] == 1.0


def test_s1_disagreeing_proposals_all_ungrounded_are_not_reported_as_agreement(repo, tmp_path):
    """HOLDING / VIOLATED / HOLDING proposed, every run's citations fabricated.

    Spec: 'any disagreement -> UNKNOWN with reason inconsistent across runs'. The gate turns
    every run into UNKNOWN/MISMATCH first, so the vote compares post-gate statuses and sees
    UNKNOWN x3: agreement=True, G6 VERIFIED, rate 1.0, and verdict.proposed_status shows only
    run 1's HOLDING; the VIOLATED proposal is visible only inside votes[1].proposed_status."""
    led = Ledger(tmp_path / "lg", run_id="s1")
    v, _, runner = run_one(
        repo, per_run("FAKE-HOLDING", "FAKE-VIOLATED", "FAKE-HOLDING"), ledger=led
    )
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")  # holds today
    assert [vt.proposed_status for vt in v.consistency.votes] == ["HOLDING", "VIOLATED", "HOLDING"]
    assert v.consistency.agreement is False
    assert any("inconsistent across runs" in r for r in v.reasons)
    assert g6_rows(led)[0]["status"] == "MISMATCH"
    assert runner.summary()["consistency_rate"] == 0.0


# ------------------------------------------------------------------ LLM errors


def _raise(exc):
    def f(_req, _n):
        raise exc

    return f


ERRORS = {
    "transport": lambda: TransportError("HTTP 500", status=500, retryable=False),
    "refusal": lambda: RefusalError("declined", category="policy"),
    "offline": lambda: OfflineModeError("no model here"),
}


@pytest.mark.parametrize("kind", sorted(ERRORS))
@pytest.mark.parametrize("pos", [0, 1, 2])
def test_llmerror_in_one_run_is_unknown_no_crash_not_dropped(repo, tmp_path, kind, pos):
    def fn(req, _n):
        seen = fn.seen = getattr(fn, "seen", 0) + 1
        if seen == pos + 1:
            raise ERRORS[kind]()
        return reply(req, "VIOLATED")

    led = Ledger(tmp_path / "lg", run_id=kind)
    v, model, runner = run_one(repo, fn, ledger=led)
    assert len(model.requests) == 3
    assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED")  # two VIOLATED runs must not win
    assert v.consistency.agreement is False and v.consistency.executed == 3
    errs = [vt for vt in v.consistency.votes if vt.error]
    assert [vt.run for vt in errs] == [pos + 1] and errs[0].status == "UNKNOWN"
    assert f"run {pos + 1} failed" in " ".join(v.reasons)
    assert (
        g6_rows(led)[0]["status"] == "MISMATCH"
        and f"run {pos + 1} failed" in g6_rows(led)[0]["reason"]
    )
    assert runner.summary()["disagreed"] == 1


def test_garbage_reply_is_a_contained_schema_error(repo):
    v, _, _ = run_one(repo, lambda _r, _n: "this is not json")
    assert v.status == "UNKNOWN" and all(vt.error for vt in v.consistency.votes)


def test_all_runs_erroring_with_an_agreeing_status_still_reports_the_errors(repo):
    v, model, _ = run_one(repo, _raise(TransportError("down", retryable=False)))
    assert v.status == "UNKNOWN" and len(model.requests) == 3
    assert sum("failed" in r for r in v.reasons) == 3


# ------------------------------------------------------------------ independence / statefulness


def test_no_reuse_of_a_reply_across_runs(repo):
    """A stateful provider whose answer is a function of the call index: every vote must be
    exactly that call's answer, in order, with the same prompt every time."""
    script = ["HOLDING", "DRIFTING", "HOLDING", "VIOLATED", "UNKNOWN"]
    v, model, _ = run_one(repo, lambda req, n: reply(req, script[n - 1]), runs=5)
    assert [vt.status for vt in v.consistency.votes] == script
    assert len({r.prompt for r in model.requests}) == 1
    assert len(model.cost_log.records) == 5


def test_leaky_provider_state_does_not_cross_claims_or_runs(repo):
    """The provider drifts after every call (e.g. conversation memory). Votes record the drift,
    verdicts become UNKNOWN, and nothing is attributed to the wrong claim."""
    order = ["HOLDING", "HOLDING", "HOLDING", "DRIFTING", "DRIFTING", "DRIFTING"]
    model = Model(lambda req, n: reply(req, order[n - 1]))
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=model))
    a, b = runner.run(free("L.a")), runner.run(free("L.b"))
    assert a.status == "HOLDING" and b.status == "DRIFTING"
    assert [claim_in(r.prompt)["id"] for r in model.requests] == ["L.a"] * 3 + ["L.b"] * 3
    assert a.consistency.votes[0].run == 1 and b.consistency.votes[0].run == 1


def test_provider_object_is_never_wrapped_into_the_judge(repo):
    model = Model(per_run("HOLDING"))
    judge = Judge(repo, mode="llm", provider=model)
    ConsistencyRunner(judge).run(free())
    assert judge.provider is model


def test_cost_log_labels_every_run(repo):
    v, model, _ = run_one(repo, per_run("HOLDING"))
    assert [r["purpose"] for r in model.cost_log.records] == [
        f"judge:S.c1#run{k}/3" for k in (1, 2, 3)
    ]


# ------------------------------------------------------------------ non-LLMError


@pytest.mark.parametrize(
    "exc", [RuntimeError("sdk bug"), KeyError("x"), ValueError("v"), OSError("net")]
)
@pytest.mark.xfail(strict=True, reason="superseded by the L008-S2 fix: contained per run now")
def test_non_llmerror_inside_a_run_today_propagates_from_run(repo, exc):
    """Documents current behaviour (and what S2 asks to change): the exception escapes run()."""
    with pytest.raises(type(exc)):
        run_one(repo, _raise(exc))


def test_s2_run_all_contains_a_non_llmerror_from_one_claim(repo, tmp_path):
    """Claim 2's provider call raises RuntimeError. Expected: 3 verdicts, claim 2 UNKNOWN with
    the error on record, claims 1 and 3 judged and their G6 rows written. Actual: RuntimeError
    escapes run_all, claim 1's verdict is lost to the caller."""

    def fn(req, _n):
        if claim_in(req.prompt)["id"] == "B.c2":
            raise RuntimeError("provider bug")
        return reply(req, "HOLDING")

    led = Ledger(tmp_path / "lg", run_id="s2")
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=Model(fn), ledger=led))
    out = runner.run_all([free("B.c1"), free("B.c2"), free("B.c3")])
    assert [v.claim_id for v in out] == ["B.c1", "B.c2", "B.c3"]
    assert out[1].status == "UNKNOWN" and any(vt.error for vt in out[1].consistency.votes)
    assert out[0].status == out[2].status == "HOLDING"


# ================================================================== design decisions


@pytest.fixture
def rule_gate_fails(monkeypatch):
    """Simulates 'the untested path': the rule verdict's evidence stops verifying (changed
    repository / verifier bug). Only rule-origin verdicts are affected; model verdicts and
    the runner's own final gate are real. (A real repo could not be made to fail it: the
    gate reads immutable git objects at the pinned commit.)"""
    real = judge_module.gate

    def g(verdict, repo_, **kw):
        if verdict.origin == "rule" and verdict.evidence and not kw.get("extra_reasons"):
            kw = {**kw, "extra_reasons": ["simulated: rule evidence no longer verifies"]}
        return real(verdict, repo_, **kw)

    monkeypatch.setattr(judge_module, "gate", g)


def violated_claim(repo):
    return claims_of(repo)["ADR-0001.c1"]  # 'only' claim: rules say VIOLATED (pymongo)


def test_rule_decided_verified_runs_once_and_keeps_the_rule_verdict(repo, tmp_path):
    led = Ledger(tmp_path / "lg", run_id="d")
    v, model, runner = run_one(repo, per_run("HOLDING"), claim=violated_claim(repo), ledger=led)
    assert v.status == "VIOLATED" and v.origin == "rule"
    assert v.consistency.basis == "deterministic" and v.consistency.executed == 1
    assert len(model.requests) == 1 and v.proposed_status == "HOLDING"
    assert g6_rows(led) == []  # nothing voted, no G6 row
    assert runner.summary()["consistency_rate"] is None


def test_rule_gate_failing_does_not_skip_the_vote(repo, rule_gate_fails):
    """Criterion (1): rule-decided but gate FAILS -> falls through to the full vote."""
    v, model, _ = run_one(repo, per_run("HOLDING"), claim=violated_claim(repo))
    assert (
        len(model.requests) == 3 and v.consistency.basis == "vote" and v.consistency.executed == 3
    )
    assert any("rule verdict could not be verified" in n for n in v.notes)


def test_rule_gate_failing_flaky_model_is_unknown(repo, rule_gate_fails):
    v, model, _ = run_one(
        repo, per_run("HOLDING", "VIOLATED", "HOLDING"), claim=violated_claim(repo)
    )
    assert len(model.requests) == 3
    assert (v.status, v.grounding) == ("UNKNOWN", "VERIFIED")
    assert v.reasons[0].startswith("inconsistent across runs:")


def test_rule_gate_failing_model_error_is_could_not_verify_not_a_violation(repo, rule_gate_fails):
    v, model, _ = run_one(repo, per_run("ERROR"), claim=violated_claim(repo))
    assert len(model.requests) == 3
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH") and v.could_not_verify
    assert v.consistency.basis == "vote"


def test_rule_gate_failing_fabricated_model_violation_is_could_not_verify(repo, rule_gate_fails):
    v, _, _ = run_one(repo, per_run("FAKE-VIOLATED"), claim=violated_claim(repo))
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")


def test_rule_gate_failing_stable_grounded_holding_replaces_the_rule_violation_with_a_note(
    repo, rule_gate_fails
):
    """Observation, L-007 area (not L-008): when the rule gate fails, a grounded model HOLDING
    becomes the verdict and the rules' VIOLATED survives only as a note. The runner passes it
    through faithfully (3/3 agree, note kept) - it does not add or remove anything."""
    v, _, _ = run_one(repo, per_run("HOLDING"), claim=violated_claim(repo))
    assert (v.status, v.grounding, v.origin) == ("HOLDING", "VERIFIED", "llm")
    assert any("rule verdict could not be verified" in n for n in v.notes)


def test_rule_decided_claim_with_flaky_model_is_stable_and_records_the_proposal(repo):
    """Criterion (2): the rules' verdict stands, whatever the model says (strict G6 holds
    because the verdict, not the proposal, is what must repeat)."""
    seqs = [("HOLDING",), ("VIOLATED",), ("UNKNOWN",), ("FAKE-HOLDING",), ("ERROR",)]
    verdicts = []
    for seq in seqs:
        v, model, _ = run_one(repo, per_run(*seq), claim=violated_claim(repo))
        verdicts.append((v.status, v.grounding, v.evidence))
        assert len(model.requests) == 1
    assert len(set(map(repr, verdicts))) == 1 and verdicts[0][:2] == ("VIOLATED", "VERIFIED")


def test_s3_deterministic_record_does_not_claim_agreement_over_an_errored_run(repo):
    """Voted records set agreement=False when any run errored; the deterministic path hard-codes
    agreement=True while votes[0].error is set. Same field, two meanings."""
    v, _, _ = run_one(repo, per_run("ERROR"), claim=violated_claim(repo))
    assert v.status == "VIOLATED" and v.consistency.votes[0].error
    assert v.consistency.agreement is False


@pytest.mark.xfail(
    strict=True,
    raises=ValueError,
    reason="L008-S4 decision: runs=1 is rejected (runs 2..25), so no runs=1 G6 row can exist",
)
def test_s4_single_run_does_not_inflate_the_consistency_rate(repo, tmp_path):
    led = Ledger(tmp_path / "lg", run_id="n1")
    v, _, runner = run_one(repo, per_run("VIOLATED"), runs=1, ledger=led)
    assert v.status == "VIOLATED" and v.consistency.executed == 1
    verified = [r for r in g6_rows(led) if r["status"] == "VERIFIED"]
    assert verified == [], f"nothing was cross-checked, yet: {verified[0]['reason']}"


def test_n2_never_reaches_a_majority(repo):
    v, _, _ = run_one(repo, per_run("VIOLATED", "HOLDING"), runs=2)
    assert v.status == "UNKNOWN"


# ------------------------------------------------------------------ evidence of the vote


def _by_run(sets):
    def fn(req, n):
        return reply(req, "HOLDING", idxs=sets[(n - 1) % len(sets)])

    return fn


def _ev_key(v):
    return [(e.id, e.ref.path, e.ref.line_start, e.ref.line_end, e.ref.quote) for e in v.evidence]


MULTI = free("E.c1", MULTI_TEXT)


@pytest.mark.parametrize(
    ("sets", "expect_ids"),
    [
        ([(0,), (1,), (0,)], ["e1", "e2"]),  # different but valid sets: union
        ([(0,), (0, 1), (0,)], ["e1", "e2"]),  # one run cites extra
        ([(0, 1), (1, 0), (0, 1)], ["e1", "e2"]),  # reordered
        ([(0, 0), (0,), (0, 0, 0)], ["e1"]),  # duplicates
        ([(0, 1, 2), (2, 1, 0), (1,)], ["e1", "e2", "e3"]),
    ],
)
def test_voted_evidence_is_the_deduplicated_union_and_regated(repo, sets, expect_ids):
    v, _, _ = run_one(repo, _by_run(sets), claim=MULTI)
    assert (v.status, v.grounding) == ("HOLDING", "VERIFIED")
    assert sorted({e.id for e in v.evidence}) == expect_ids
    assert len(_ev_key(v)) == len(set(_ev_key(v)))  # no duplicates
    assert len(v.checks) >= len(v.evidence) and all(c.status == "VERIFIED" for c in v.checks)
    # every voted item was cited by at least one run
    cited = {k for vt in v.consistency.votes for k in _ev_key(vt)}
    assert set(_ev_key(v)) <= cited


def test_voted_evidence_order_follows_first_appearance_so_reorders_only_permute(repo):
    a, _, _ = run_one(repo, _by_run([(0, 1)]), claim=MULTI)
    b, _, _ = run_one(repo, _by_run([(1, 0)]), claim=MULTI)
    assert a.status == b.status == "HOLDING"
    assert sorted(_ev_key(a)) == sorted(_ev_key(b))


def test_same_candidate_with_different_subranges_is_kept_distinct_and_valid(repo):
    def fn(req, n):
        return reply(req, "HOLDING", quote=None if n != 2 else "healthz")

    v, _, _ = run_one(repo, fn)
    assert v.status == "HOLDING" and len(v.evidence) == 2
    assert {e.id for e in v.evidence} == {"e1"}


def test_extra_ungrounded_citation_in_one_run_blocks_the_vote(repo):
    def fn(req, n):
        r = reply(req, "HOLDING", idxs=(0, 1))
        if n == 3:
            r["citations"][1]["quote"] = "not in the file"
        return r

    v, _, _ = run_one(repo, fn, claim=MULTI)
    assert (v.status, v.grounding) == ("UNKNOWN", "MISMATCH")
    assert all("run 3" in r for r in v.reasons if r.startswith("run "))


# ------------------------------------------------------------------ pinning


def test_voted_commit_is_pinned_while_the_repo_moves_between_runs(repo):
    judge_ref = {}

    def fn(req, n):
        if n == 2:
            (repo / "src/shop/health.py").write_text("changed = 1\n", encoding="utf-8")
            _commit(repo, "moves under the runner")
        return reply(req, "HOLDING")

    model = Model(fn)
    judge = Judge(repo, commit="HEAD", mode="llm", provider=model)
    judge_ref["c"] = judge.commit
    v = ConsistencyRunner(judge).run(free())
    assert v.commit == judge_ref["c"] and (v.status, v.grounding) == ("HOLDING", "VERIFIED")
    assert all(e.ref.commit == judge_ref["c"] for e in v.evidence)


# ================================================================== ledger / threads / scale


def test_ledger_summary_file_carries_g6_counts_and_rate(repo, tmp_path):
    led = Ledger(tmp_path / "lg", run_id="sum")
    seqs = {"G.a": ("HOLDING",), "G.b": ("HOLDING", "VIOLATED"), "G.c": ("ERROR",)}

    state: dict[str, int] = defaultdict(int)

    def fn(req, _n):
        cid = claim_in(req.prompt)["id"]
        s = seqs[cid][state[cid] % len(seqs[cid])]
        state[cid] += 1
        if s == "ERROR":
            raise TransportError("x", retryable=False)
        return reply(req, s)

    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=Model(fn), ledger=led))
    runner.run_all([free(c) for c in seqs])
    data = led.write_summary()
    assert data["by_check"]["G6"] == {"VERIFIED": 1, "MISMATCH": 2}
    assert (
        led.check_rate("G6")
        == pytest.approx(1 / 3)
        == pytest.approx(runner.summary()["consistency_rate"])
    )
    on_disk = json.loads(led.summary_path.read_text())
    assert on_disk["by_check"]["G6"] == {"VERIFIED": 1, "MISMATCH": 2}


def test_runner_ledger_may_differ_from_the_judges(repo, tmp_path):
    jl, rl = Ledger(tmp_path / "j", run_id="j"), Ledger(tmp_path / "r", run_id="r")
    runner = ConsistencyRunner(
        Judge(repo, mode="llm", provider=Model(per_run("HOLDING")), ledger=jl), ledger=rl
    )
    runner.run(free())
    assert len(g6_rows(rl)) == 1 and g6_rows(jl) == []


def test_no_ledger_is_fine(repo):
    v, _, runner = run_one(repo, per_run("HOLDING", "VIOLATED", "HOLDING"))
    assert v.status == "UNKNOWN" and runner.summary()["consistency_rate"] == 0.0


def test_threads_with_one_runner_each_share_a_ledger_without_corruption(repo, tmp_path):
    led = Ledger(tmp_path / "lg", run_id="thr")
    state: dict[str, int] = defaultdict(int)
    lock = threading.Lock()

    def fn(req, _n):
        cid = claim_in(req.prompt)["id"]
        with lock:
            k = state[cid] = state[cid] + 1
        stable = int(cid.split(".c")[1]) % 2 == 0
        return reply(req, "HOLDING" if stable or k != 2 else "VIOLATED", idxs=(0, 1))

    judge = Judge(repo, mode="llm", provider=Model(fn), ledger=led)
    claims = [free(f"T.c{i}", MULTI_TEXT) for i in range(48)]
    results: list[list[Verdict]] = [[] for _ in range(8)]

    def work(i):
        results[i] = ConsistencyRunner(judge, ledger=led).run_all(claims[i::8])

    ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    rows = [json.loads(x) for x in led.path.read_text().splitlines()]  # every line parses
    assert Counter((r["check_id"], r["status"]) for r in rows) == led._counts
    g6 = [r for r in rows if r["check_id"] == "G6"]
    assert len(g6) == 48 and Counter(r["status"] for r in g6) == {"VERIFIED": 24, "MISMATCH": 24}
    flat = [v for part in results for v in part]
    assert {v.claim_id for v in flat} == {c.id for c in claims}
    for v in flat:
        stable = int(v.claim_id.split(".c")[1]) % 2 == 0
        assert v.status == ("HOLDING" if stable else "UNKNOWN")


def test_run_all_500_claims_offline_performance(repo):
    base = list(claims_of(repo).values())
    claims = [c.model_copy(update={"id": f"P{i}.{c.id}"}) for i in range(72) for c in base][:500]
    runner = ConsistencyRunner(Judge(repo, mode="offline"))
    t = time.perf_counter()
    out = runner.run_all(claims)
    dt = time.perf_counter() - t
    assert len(out) == 500 and runner.summary()["runs_executed"] == 500
    assert dt < 90, f"500 offline claims took {dt:.1f}s"
    print(f"\nperf: 500 offline claims {dt:.1f}s ({dt / 500 * 1000:.0f} ms/claim)")


def test_run_all_500_voted_claims_with_fake_llm_performance(repo, tmp_path):
    claims = [free(f"Q.c{i}") for i in range(500)]
    led = Ledger(tmp_path / "lg", run_id="perf")
    runner = ConsistencyRunner(
        Judge(repo, mode="llm", provider=Model(per_run("HOLDING")), ledger=led)
    )
    t = time.perf_counter()
    out = runner.run_all(claims)
    dt = time.perf_counter() - t
    assert (
        len(out) == 500 and runner.summary()["model_calls"] == 1500 and led.check_rate("G6") == 1.0
    )
    assert dt < 180, f"took {dt:.1f}s"
    print(f"\nperf: 500 voted claims (1500 runs) {dt:.1f}s")


# ================================================================== G6 over >=200 claim runs


G6_TEXTS = [FREE_TEXT, MULTI_TEXT, "storage goes through adapters", "catalog legacy"]
STATUSES = ["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN"]


def build_g6(seed, n_claims):
    rng = random.Random(seed)
    plan = {}
    kinds = [
        "stable",
        "stable",
        "flaky",
        "flaky",
        "flaky_violated",
        "error",
        "ungrounded",
        "flaky_cite",
    ]
    for i in range(n_claims):
        cid = f"Z{seed}.c{i:03d}"
        kind = kinds[i % len(kinds)] if i < len(kinds) else rng.choice(kinds)
        if kind == "stable":
            seq = [rng.choice(STATUSES)] * 3
        elif kind == "flaky":
            seq = rng.sample(STATUSES, 2)
            seq = [seq[0], seq[1], rng.choice(seq)]
            rng.shuffle(seq)
        elif kind == "flaky_violated":
            seq = ["VIOLATED", "VIOLATED", rng.choice(["HOLDING", "DRIFTING", "UNKNOWN"])]
            rng.shuffle(seq)
        elif kind == "error":
            seq = ["VIOLATED"] * 3
            seq[rng.randrange(3)] = "ERROR"
        elif kind == "ungrounded":
            seq = ["FAKE-VIOLATED"] * 3
        else:  # same status, one run cites a different (valid) candidate: still agrees
            seq = ["HOLDING"] * 3
        plan[cid] = (kind, seq, rng.randrange(1000))
    claims = [free(cid, G6_TEXTS[plan[cid][2] % len(G6_TEXTS)]) for cid in plan]
    return plan, claims


@pytest.mark.parametrize("seed", [20261027, 7, 99])
def test_g6_seeded_flaky_provider_over_300_plus_claim_runs(repo, tmp_path, seed):
    plan, claims = build_g6(seed, 112)
    seen: dict[str, int] = defaultdict(int)

    def fn(req, _n):
        cid = claim_in(req.prompt)["id"]
        kind, seq, _ = plan[cid]
        k = seen[cid] = seen[cid] + 1
        s = seq[k - 1]
        if s == "ERROR":
            raise TransportError("fake outage", status=503, retryable=False)
        cands = candidates_in(req.prompt)
        idxs = (0,) if kind != "flaky_cite" or k != 2 or len(cands) < 2 else (1,)
        if s.startswith("FAKE-"):
            return reply(req, s[5:], fake=True)
        return reply(req, s, idxs=idxs)

    led = Ledger(tmp_path / "lg", run_id=f"g6-{seed}")
    runner = ConsistencyRunner(Judge(repo, mode="llm", provider=Model(fn), ledger=led))
    out = {v.claim_id: v for v in runner.run_all(claims)}
    assert len(out) == len(claims) and sum(seen.values()) >= 300  # >= 100 claims x 3 runs

    stable_total = disagree_total = 0
    for cid, (kind, seq, _) in plan.items():
        v = out[cid]
        assert v.consistency.basis == "vote" and v.consistency.executed == 3
        if kind in ("stable", "flaky_cite"):
            stable_total += 1
            assert (v.status, v.grounding) == (seq[0], "VERIFIED"), (cid, kind, seq, v.status)
            assert v.consistency.agreement
        elif kind in ("flaky", "flaky_violated", "error"):
            disagree_total += 1
            assert v.status == "UNKNOWN" and not v.could_not_verify, (cid, seq, v.status)
            assert v.reasons[0].startswith("inconsistent across runs: ")
            assert v.consistency.agreement is False
        else:  # ungrounded
            assert v.could_not_verify and v.status == "UNKNOWN"
        assert not (v.status == "VIOLATED" and kind not in ("stable",)), f"{cid} leaked VIOLATED"
    assert stable_total and disagree_total
    rows = g6_rows(led)
    assert len(rows) == len(claims)
    s = runner.summary()
    expected_agreed = sum(1 for v in out.values() if v.consistency.agreement)
    assert s["agreed"] == expected_agreed and s["voted"] == len(claims)
    assert led.check_rate("G6") == pytest.approx(expected_agreed / len(claims))
    assert led.check_rate("G6") == pytest.approx(s["consistency_rate"])
    led.write_summary()
    digest = hashlib.sha1(repr(sorted((k, v.status) for k, v in out.items())).encode())
    print(
        f"\nG6 seed={seed}: {len(claims)} claims, {sum(seen.values())} claim runs, "
        f"agreed {s['agreed']}, disagreed {s['disagreed']}, "
        f"consistency rate {s['consistency_rate']:.3f} (ledger {led.check_rate('G6'):.3f}); "
        f"stable kept {stable_total}/{stable_total}, "
        f"disagreeing->UNKNOWN {disagree_total}/{disagree_total}, VIOLATED leaks 0; "
        f"hash={digest.hexdigest()[:8]}"
    )


def test_g6_same_seed_gives_identical_numbers(repo, tmp_path):
    def once(tag):
        plan, claims = build_g6(5, 40)
        seen: dict[str, int] = defaultdict(int)

        def fn(req, _n):
            cid = claim_in(req.prompt)["id"]
            seq = plan[cid][1]
            s = seq[seen[cid]]
            seen[cid] += 1
            if s == "ERROR":
                raise TransportError("x", retryable=False)
            return reply(req, s[5:] if s.startswith("FAKE-") else s, fake=s.startswith("FAKE-"))

        r = ConsistencyRunner(
            Judge(repo, mode="llm", provider=Model(fn), ledger=Ledger(tmp_path / tag, run_id="a"))
        )
        return json.dumps([v.model_dump(mode="json") for v in r.run_all(claims)]), r.summary()

    assert once("x") == once("y")
