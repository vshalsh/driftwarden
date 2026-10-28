"""L-011: drift timeline (first violating commit per claim) and the G4 verifier.

Histories are built with real git in tmp_path. No network, no API key, no LLM: the
timeline judges offline only, and sockets are disabled for every test.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from conftest import GIT_ENV
from driftwarden.claims import structure_scan
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_first_violation
from driftwarden.judge import judge_claims
from driftwarden.models import Claim
from driftwarden.timeline import SnapshotCache, apply_grounding, build_timeline, first_violation
from driftwarden.timeline.bisect import sample_indices

ADR_FORBID = """# 1. No MongoDB

## Status

Accepted

## Context

One datastore keeps operations simple.

## Decision

We must not use MongoDB.

## Consequences

Everything lives in PostgreSQL.
"""

ADR_BOUNDARY = """# 2. Payments boundary

## Status

Accepted

## Context

Billing owns payments.

## Decision

The payments package may be imported only from billing/.

## Consequences

Other code calls billing.
"""

CLEAN_REQ = "requests==2.31.0\n"
MONGO_REQ = "requests==2.31.0\npymongo==4.6.0\n"
FIRST: dict[str, str | None] = {
    "docs/adr/0001-no-mongodb.md": ADR_FORBID,
    "requirements.txt": CLEAN_REQ,
}


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


# ------------------------------------------------------------------ history builder


class History:
    """A real git repository built commit by commit, with fixed, increasing dates."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.n = 0
        self.counter = "app/counter.py"  # per-branch counter files avoid merge conflicts
        path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str, cwd: Path | None = None) -> str:
        date = f"@{1767225600 + self.n * 3600} +0000"
        env = {**os.environ, **GIT_ENV, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        proc = subprocess.run(
            ["git", *args], cwd=cwd or self.path, capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    def commit(self, msg: str, files: dict[str, str | None] | None = None) -> str:
        self.n += 1
        for rel, content in (files or {}).items():
            p = self.path / rel
            if content is None:
                p.unlink()
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        # a counter file so every commit changes the tree
        (self.path / "app").mkdir(exist_ok=True)
        (self.path / self.counter).write_text(f"N = {self.n}\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD").strip()


def claims_at(repo: Path) -> list[Claim]:
    sets = structure_scan(scan_adrs(repo).decisions, repo, mode="offline")
    return [c for s in sets for c in s.claims]


def the_claim(repo: Path, kind: str) -> Claim:
    cs = [c for c in claims_at(repo) if c.kind == kind]
    assert len(cs) == 1, cs
    return cs[0]


def forbid_history(tmp_path: Path, n: int, violated: set[int], name: str = "h") -> tuple:
    """n commits; commit i (0-based) has pymongo in requirements.txt iff i in violated.
    The ADR is in commit 0."""
    h = History(tmp_path / name)
    shas = []
    for i in range(n):
        files: dict[str, str | None] = {
            "requirements.txt": MONGO_REQ if i in violated else CLEAN_REQ
        }
        if i == 0:
            files["docs/adr/0001-no-mongodb.md"] = ADR_FORBID
        shas.append(h.commit(f"commit {i}", files))
    return h, shas


FOUND_ENTRIES: list[tuple[Path, object, Claim]] = []


def found(
    repo: Path, entry, claim: Claim, sha: str, parent: str | None, collect: bool = True
) -> None:
    assert entry.status == "FOUND", (entry.status, entry.reasons, entry.notes)
    assert entry.grounding == "VERIFIED", entry.reasons
    assert entry.first_violating_commit == sha
    assert entry.parent == parent
    assert entry.evidence
    assert all(c.check_id == "G4" for c in entry.checks)
    assert all(c.status == "VERIFIED" for c in entry.checks)
    if collect:  # re-verified unpatched at the end of the file
        FOUND_ENTRIES.append((repo, entry, claim))


# ------------------------------------------------------------------ core fixtures


def test_linear_dependency_added_at_k(tmp_path):
    k = 17
    h, shas = forbid_history(tmp_path, 30, set(range(k, 30)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[k], shas[k - 1])
    assert e.subject == f"commit {k}"
    assert e.author_date.startswith("2026-01-01T")
    assert not e.non_monotonic
    assert e.commits_judged < 30  # sampled + bisected, not linear
    assert any(ev.dependency and ev.dependency.package == "pymongo" for ev in e.evidence)
    assert all(ev.ref.commit == shas[k] for ev in e.evidence)


@pytest.mark.parametrize("k", [1, 2, 5, 13, 28, 29])
def test_linear_every_position(tmp_path, k):
    h, shas = forbid_history(tmp_path, 30, set(range(k, 30)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[k], shas[k - 1])


def test_violated_since_root(tmp_path):
    h, shas = forbid_history(tmp_path, 12, set(range(12)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[0], None)
    assert any("violated since the first commit" in n for n in e.notes)


def test_add_remove_readd_is_non_monotonic(tmp_path):
    h, shas = forbid_history(tmp_path, 30, set(range(5, 15)) | set(range(25, 30)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[25], shas[24])
    assert e.non_monotonic
    assert e.earlier_transitions == [shas[5]]
    assert any("non-monotonic" in n and shas[5][:12] in n for n in e.notes)
    assert e.commits_judged == 30  # fell back to a linear scan


def test_two_earlier_transitions(tmp_path):
    v = {2, 3} | set(range(10, 14)) | set(range(22, 30))
    h, shas = forbid_history(tmp_path, 30, v)
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[22], shas[21])
    assert e.earlier_transitions == [shas[2], shas[10]]


def test_holding_at_head(tmp_path):
    h, shas = forbid_history(tmp_path, 10, {3, 4})
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    assert e.status == "NOT_VIOLATED_AT_HEAD"
    assert e.first_violating_commit is None
    assert e.grounding == "VERIFIED"
    assert e.commits_judged == 1


def test_merge_commit_from_side_branch_is_the_boundary(tmp_path):
    """First-parent history only: the side-branch commit that added pymongo is not on
    main's first-parent chain, so the boundary is the merge that brought it in."""
    h = History(tmp_path / "merge")
    main = [h.commit("c0", FIRST)]
    for i in range(1, 6):
        main.append(h.commit(f"main {i}"))
    h.git("checkout", "-q", "-b", "side", main[3])
    h.counter = "app/counter_side.py"
    side = h.commit("side: add mongo", {"requirements.txt": MONGO_REQ})
    h.commit("side: more")
    h.git("checkout", "-q", "main")
    h.counter = "app/counter.py"
    h.n += 1
    h.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
    merge = h.git("rev-parse", "HEAD").strip()
    after = h.commit("after merge")
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim, head=after)
    found(h.path, e, claim, merge, main[-1])
    assert e.first_violating_commit != side
    assert e.subject == "merge side"
    assert any("merge commit" in n and side[:12] not in n for n in e.notes)  # names parent 2


def test_shallow_clone_is_truncated(tmp_path):
    h, shas = forbid_history(tmp_path, 30, set(range(10, 30)))
    clone = tmp_path / "shallow"
    h.git("clone", "-q", "--depth", "5", f"file://{h.path}", str(clone), cwd=tmp_path)
    claim = the_claim(clone, "forbid")
    e = first_violation(clone, claim)
    assert e.status == "TRUNCATED", (e.status, e.reasons, e.notes)
    assert e.truncated_by == "shallow"
    assert e.oldest_available == shas[25]
    assert e.first_violating_commit is None
    assert e.grounding == "VERIFIED", e.reasons
    assert "history truncated" in e.first_seen


def test_shallow_clone_transition_inside_window_is_found(tmp_path):
    h, shas = forbid_history(tmp_path, 30, set(range(26, 30)))
    clone = tmp_path / "shallow2"
    h.git("clone", "-q", "--depth", "10", f"file://{h.path}", str(clone), cwd=tmp_path)
    claim = the_claim(clone, "forbid")
    e = first_violation(clone, claim)
    found(clone, e, claim, shas[26], shas[25])
    assert any("history truncated (shallow)" in n for n in e.notes)


def test_max_commits_cap_is_truncated(tmp_path):
    h, shas = forbid_history(tmp_path, 20, set(range(3, 20)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim, max_commits=8)
    assert e.status == "TRUNCATED"
    assert e.truncated_by == "max_commits"
    assert e.oldest_available == shas[12]
    assert e.grounding == "VERIFIED", e.reasons


def test_boundary_import_violation(tmp_path):
    h = History(tmp_path / "bnd")
    f = "import os\n\nVALUE = os.sep\n"
    shas = [
        h.commit(
            "c0",
            {
                "docs/adr/0002-payments.md": ADR_BOUNDARY,
                "payments/__init__.py": "",
                "payments/core.py": f,
                "billing/__init__.py": "",
                "billing/b.py": "import payments.core\n",
                "shop/__init__.py": "",
                "shop/a.py": f,
            },
        )
    ]
    for i in range(1, 20):
        files = {"shop/a.py": "import payments.core\n"} if i == 11 else None
        shas.append(h.commit(f"c{i}", files))
    claim = the_claim(h.path, "boundary")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[11], shas[10])
    assert any(ev.kind == "import" and ev.ref.path == "shop/a.py" for ev in e.evidence)


def test_violation_before_the_adr_starts_at_the_adr(tmp_path):
    """The decision did not exist before its ADR: those commits count as not violated."""
    h = History(tmp_path / "late-adr")
    shas = [h.commit("c0", {"requirements.txt": MONGO_REQ})]
    for i in range(1, 10):
        files = {"docs/adr/0001-no-mongodb.md": ADR_FORBID} if i == 6 else None
        shas.append(h.commit(f"c{i}", files))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    found(h.path, e, claim, shas[6], shas[5])
    assert any("not present (decision not taken yet)" in n for n in e.notes)


def test_unknown_commits_count_as_not_violated_with_note(tmp_path, monkeypatch):
    """A commit the judge cannot decide (UNKNOWN) is counted as not violated, with a
    note; the boundary is the first commit that is verifiably violated."""
    from driftwarden.judge.judge import Judge
    from driftwarden.models import Verdict

    h, shas = forbid_history(tmp_path, 12, set(range(4, 12)))
    claim = the_claim(h.path, "forbid")
    undecidable = {shas[4], shas[5]}
    real = Judge.judge

    def judge(self, c, es=None, *, provider=None):
        if self.commit in undecidable:
            return Verdict(claim_id=c.id, status="UNKNOWN", commit=self.commit, rationale="forced")
        return real(self, c, es, provider=provider)

    monkeypatch.setattr(Judge, "judge", judge)
    e = first_violation(h.path, claim, exhaustive=True)
    found(h.path, e, claim, shas[6], shas[5], collect=False)  # the patch is part of the truth
    assert any(shas[4][:12] in n and "could not be judged" in n for n in e.notes)


def test_exhaustive_agrees_with_sampled(tmp_path):
    for idx, v in enumerate([set(range(9, 25)), set(range(25)), set(range(1, 25))]):
        h, _ = forbid_history(tmp_path, 25, v, name=f"ex{idx}")
        claim = the_claim(h.path, "forbid")
        a = first_violation(h.path, claim)
        b = first_violation(h.path, claim, exhaustive=True)
        assert a.first_violating_commit == b.first_violating_commit
        assert a.parent == b.parent


def test_never_calls_an_llm(tmp_path, monkeypatch):
    import driftwarden.llm.base as base

    def boom(*_a, **_k):
        raise AssertionError("the timeline must never call an LLM")

    monkeypatch.setattr(base.Provider, "complete_json", boom, raising=False)
    h, shas = forbid_history(tmp_path, 10, set(range(4, 10)))
    claim = the_claim(h.path, "forbid")
    assert first_violation(h.path, claim).first_violating_commit == shas[4]


def test_bad_head_is_unknown_not_a_crash(tmp_path):
    h, _ = forbid_history(tmp_path, 3, {2})
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim, head="no-such-ref")
    assert e.status == "UNKNOWN" and e.grounding == "MISMATCH" and e.reasons
    assert e.first_seen.startswith("first seen: unknown")


def test_sample_indices():
    assert sample_indices(1) == [0]
    assert sample_indices(5) == [0, 1, 2, 3, 4]
    idx = sample_indices(300)
    assert idx[0] == 0 and idx[-1] == 299 and 15 <= len(idx) <= 20


# ------------------------------------------------------------------ build_timeline + ledger


def test_build_timeline_runs_for_verified_violated_only(tmp_path):
    h = History(tmp_path / "bt")
    f = "import os\n"
    shas = [
        h.commit(
            "c0",
            {
                "docs/adr/0001-no-mongodb.md": ADR_FORBID,
                "docs/adr/0002-payments.md": ADR_BOUNDARY,
                "requirements.txt": CLEAN_REQ,
                "payments/__init__.py": "",
                "payments/core.py": f,
                "billing/b.py": "import payments.core\n",
                "shop/a.py": f,
            },
        )
    ]
    for i in range(1, 15):
        files = {"requirements.txt": MONGO_REQ} if i == 7 else None
        shas.append(h.commit(f"c{i}", files))
    claims = claims_at(h.path)
    verdicts = judge_claims(h.path, claims, mode="offline")
    assert sorted(v.status for v in verdicts) == ["HOLDING", "VIOLATED"]
    ledger = Ledger(tmp_path / "out")
    entries = build_timeline(h.path, claims, verdicts, ledger=ledger)
    assert len(entries) == 1
    assert entries[0].first_violating_commit == shas[7]
    assert ledger.check_rate("G4") == 1.0
    assert ledger.summary()["by_check"]["G4"]["MISMATCH"] == 0


def test_build_timeline_missing_claim_is_reported(tmp_path):
    h, _ = forbid_history(tmp_path, 4, {3})
    claims = claims_at(h.path)
    verdicts = judge_claims(h.path, claims, mode="offline")
    entries = build_timeline(h.path, [], verdicts)
    assert len(entries) == 1 and entries[0].status == "UNKNOWN" and entries[0].reasons


# ------------------------------------------------------------------ G4 tamper


@pytest.fixture
def g4_case(tmp_path):
    k = 9
    h, shas = forbid_history(tmp_path, 16, set(range(k, 16)))
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    assert e.first_violating_commit == shas[k] and e.grounding == "VERIFIED"
    return h.path, e, claim, shas, k


def mismatches(repo, entry, claim) -> list[str]:
    return [r.reason for r in verify_first_violation(repo, entry, claim) if r.status != "VERIFIED"]


def test_g4_clean_entry_verifies(g4_case):
    repo, e, claim, _shas, _k = g4_case
    results = verify_first_violation(repo, e, claim)
    assert results and all(r.status == "VERIFIED" and r.check_id == "G4" for r in results)


def test_g4_wrong_commit(g4_case):
    repo, e, claim, shas, k = g4_case
    bad = e.model_copy(update={"first_violating_commit": shas[k + 2], "parent": shas[k + 1]})
    reasons = mismatches(repo, bad, claim)
    assert any("(c)" in r and "already violated" in r for r in reasons), reasons


def test_g4_wrong_parent(g4_case):
    repo, e, claim, shas, k = g4_case
    bad = e.model_copy(update={"parent": shas[k - 3]})
    reasons = mismatches(repo, bad, claim)
    assert any("(a)" in r and "not the first parent" in r for r in reasons), reasons


def test_g4_parent_none_on_non_root(g4_case):
    repo, e, claim, _shas, _k = g4_case
    reasons = mismatches(repo, e.model_copy(update={"parent": None}), claim)
    assert any("parent is None" in r for r in reasons), reasons


def test_g4_swapped_subject(g4_case):
    repo, e, claim, _shas, _k = g4_case
    reasons = mismatches(repo, e.model_copy(update={"subject": "commit 3"}), claim)
    assert any("(d)" in r and "subject" in r for r in reasons), reasons


def test_g4_wrong_date(g4_case):
    repo, e, claim, _shas, _k = g4_case
    reasons = mismatches(repo, e.model_copy(update={"author_date": "2020-01-01T00:00:00Z"}), claim)
    assert any("(d)" in r and "author_date" in r for r in reasons), reasons


def test_g4_commit_where_claim_holds(g4_case):
    repo, e, claim, shas, k = g4_case
    bad = e.model_copy(update={"first_violating_commit": shas[k - 2], "parent": shas[k - 3]})
    reasons = mismatches(repo, bad, claim)
    assert any("(b)" in r and "not VERIFIED VIOLATED" in r for r in reasons), reasons


def test_g4_evidence_edited(g4_case):
    repo, e, claim, _shas, _k = g4_case
    ev = e.evidence[0]
    forged = ev.model_copy(update={"ref": ev.ref.model_copy(update={"quote": "pymongo==9.9.9"})})
    bad = e.model_copy(update={"evidence": [forged, *e.evidence[1:]]})
    reasons = mismatches(repo, bad, claim)
    assert any("evidence" in r and "G2" in r for r in reasons), reasons


def test_g4_evidence_from_another_commit(g4_case):
    repo, e, claim, shas, _k = g4_case
    ev = e.evidence[0]
    moved = ev.model_copy(update={"ref": ev.ref.model_copy(update={"commit": shas[-1]})})
    reasons = mismatches(repo, e.model_copy(update={"evidence": [moved]}), claim)
    assert reasons


def test_g4_no_evidence(g4_case):
    repo, e, claim, _shas, _k = g4_case
    reasons = mismatches(repo, e.model_copy(update={"evidence": []}), claim)
    assert any("no evidence" in r for r in reasons), reasons


def test_g4_short_or_unknown_commit(g4_case):
    repo, e, claim, shas, k = g4_case
    for c in [shas[k][:12], "HEAD", "0" * 40, shas[k].upper()]:
        assert mismatches(repo, e.model_copy(update={"first_violating_commit": c}), claim), c


def test_g4_commit_off_first_parent_chain(tmp_path):
    h = History(tmp_path / "off")
    base = h.commit("c0", FIRST)
    h.commit("c1")
    h.git("checkout", "-q", "-b", "side", base)
    h.counter = "app/counter_side.py"
    side = h.commit("side mongo", {"requirements.txt": MONGO_REQ})
    h.git("checkout", "-q", "main")
    h.counter = "app/counter.py"
    h.n += 1
    h.git("merge", "-q", "--no-ff", "-m", "merge", "side")
    claim = the_claim(h.path, "forbid")
    e = first_violation(h.path, claim)
    assert e.status == "FOUND"
    bad = e.model_copy(update={"first_violating_commit": side, "parent": base})
    reasons = mismatches(h.path, bad, claim)
    assert any("not on the first-parent history" in r for r in reasons), reasons


def test_g4_wrong_claim(g4_case, tmp_path):
    repo, e, claim, _shas, _k = g4_case
    other = claim.model_copy(update={"id": "ADR-9999.c1"})
    assert mismatches(repo, e, other)


def test_g4_apply_grounding_makes_unknown(g4_case):
    repo, e, claim, _shas, _k = g4_case
    bad = e.model_copy(update={"subject": "forged"})
    g = apply_grounding(
        bad.model_copy(update={"checks": []}), verify_first_violation(repo, bad, claim)
    )
    assert g.status == "UNKNOWN" and g.grounding == "MISMATCH"
    assert g.proposed_status == "FOUND"
    assert g.first_seen.startswith("first seen: unknown (") and "subject" in g.first_seen


def test_g4_tampered_truncated_and_not_violated(tmp_path):
    h, shas = forbid_history(tmp_path, 20, set(range(3, 20)))
    claim = the_claim(h.path, "forbid")
    t = first_violation(h.path, claim, max_commits=8)
    assert t.status == "TRUNCATED" and t.grounding == "VERIFIED"
    assert mismatches(h.path, t.model_copy(update={"truncated_by": "shallow"}), claim)
    assert mismatches(h.path, t.model_copy(update={"oldest_available": shas[1]}), claim)
    assert mismatches(h.path, t.model_copy(update={"first_violating_commit": shas[3]}), claim)
    nv = t.model_copy(update={"status": "NOT_VIOLATED_AT_HEAD", "oldest_available": None})
    assert mismatches(h.path, nv, claim)


def test_g4_root_claimed_on_shallow_boundary(tmp_path):
    h, shas = forbid_history(tmp_path, 12, set(range(12)))
    clone = tmp_path / "sh"
    h.git("clone", "-q", "--depth", "3", f"file://{h.path}", str(clone), cwd=tmp_path)
    claim = the_claim(clone, "forbid")
    e = first_violation(clone, claim)
    assert e.status == "TRUNCATED"
    forged = e.model_copy(
        update={
            "status": "FOUND",
            "first_violating_commit": shas[9],
            "parent": None,
            "author_date": h.git("log", "-1", "--format=%aI", shas[9]).strip(),
            "subject": "commit 9",
        }
    )
    reasons = mismatches(clone, forged, claim)
    assert any("shallow-clone boundary, not a root" in r for r in reasons), reasons


# ------------------------------------------------------------------ G4 over every FOUND entry


def test_zz_g4_over_every_found_entry():
    """Re-runs G4 on every FOUND entry the tests above produced (runs last in file
    order; skipped when run in isolation)."""
    if not FOUND_ENTRIES:
        pytest.skip("no FOUND entries collected in this session")
    ok = 0
    for repo, entry, claim in FOUND_ENTRIES:
        results = verify_first_violation(repo, entry, claim)
        ok += all(r.status == "VERIFIED" for r in results)
    print(f"\nG4 over FOUND entries: {ok}/{len(FOUND_ENTRIES)} verified")
    assert ok == len(FOUND_ENTRIES)


# ------------------------------------------------------------------ performance


def test_perf_300_commits_one_claim_under_20s(tmp_path, perf_factor):
    h, shas = forbid_history(tmp_path, 300, set(range(211, 300)), name="perf")
    claim = the_claim(h.path, "forbid")
    cache = SnapshotCache(h.path)
    t = time.perf_counter()
    e = first_violation(h.path, claim, cache=cache)
    dt = time.perf_counter() - t
    assert e.first_violating_commit == shas[211] and e.grounding == "VERIFIED"
    print(f"\n300-commit timeline: {dt:.2f}s, {e.commits_judged} judged, {cache.loads} loads")
    assert cache.loads == e.commits_judged  # each commit's snapshot loaded once
    assert dt < 20.0 * perf_factor, dt
