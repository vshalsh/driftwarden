"""L-011 system tests (white-box tester: Sonnet). Independent of tests/test_l011_timeline.py.

Histories are built from scratch with ``git fast-import`` (real git objects, real
first-parent chains, merges, octopus merges, empty commits) in tmp_path. Ground
truth always comes from the generator (the per-commit violated flag it wrote), never
from the code under test.

What is covered: seeded random linear histories (exhaustive == last held->violated
transition; sampled == a real transition + honest non_monotonic flag), the measured
"sampled returns a non-latest transition" rate, violation kinds, history edge cases,
truncation, G4 tampering, offline-only judging, the ledger and performance.
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
from pydantic import ValidationError

from driftwarden import git as dwgit
from driftwarden.claims import structure_scan
from driftwarden.config import Config
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_first_violation
from driftwarden.judge import judge as judge_mod
from driftwarden.judge import judge_claims
from driftwarden.llm import base as llm_base
from driftwarden.models import Claim
from driftwarden.timeline import (
    SnapshotCache,
    TimelineEntry,
    apply_grounding,
    build_timeline,
    first_violation,
)

T0 = 1767225600  # 2026-01-01T00:00:00Z

# ------------------------------------------------------------------------ fixtures


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    """No sockets, no HTTP, no provider, no LLM call: any of them fails the test."""

    def boom(*_a, **_k):
        raise AssertionError("network / LLM touched by timeline code")

    class NoSocket(socket.socket):
        def connect(self, *_a, **_k):
            boom()

    monkeypatch.setattr(socket, "socket", NoSocket)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(llm_base.BaseProvider, "complete", boom)
    monkeypatch.setattr(llm_base.BaseProvider, "complete_json", boom)


# ----------------------------------------------------------------- history builder


def fast_import(path: Path, commits: list[dict]) -> list[str]:
    """Build a repo. Commit i is ``commits[i]``: ``set`` {path: text}, ``delete`` [paths],
    ``parents`` [indexes] (default: the previous commit), ``ref`` (branch, default main),
    ``msg``. A merge commit's tree is its first parent's tree plus its own delta.
    Returns the SHA of every commit, in input order."""
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    out: list[str] = []
    for i, c in enumerate(commits):
        parents = c.get("parents", [i - 1] if i else [])
        msg = c.get("msg", f"commit {i}").encode()
        out.append(
            f"commit refs/heads/{c.get('ref', 'main')}\nmark :{i + 1}\n"
            f"committer Tester <t@example.invalid> {T0 + i * 60} +0000\n"
            f"data {len(msg)}\n{msg.decode()}\n"
        )
        if parents:
            out.append(f"from :{parents[0] + 1}\n")
            out.extend(f"merge :{p + 1}\n" for p in parents[1:])
        out.extend(f"D {d}\n" for d in c.get("delete", []))
        for p, body in c.get("set", {}).items():
            b = body.encode()
            out.append(f"M 100644 inline {p}\ndata {len(b)}\n{body}\n")
        out.append("\n")
    subprocess.run(
        ["git", "fast-import", "--quiet", "--export-marks=.git/marks"],
        cwd=path,
        input="".join(out).encode(),
        check=True,
    )
    subprocess.run(["git", "checkout", "-q", "-f", "main"], cwd=path, check=True)
    marks = {}
    for line in (path / ".git" / "marks").read_text().splitlines():
        m, sha = line.split()
        marks[int(m[1:])] = sha
    return [marks[i + 1] for i in range(len(commits))]


def run_git(path: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    p = subprocess.run(["git", *args], cwd=path, capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
    return p.stdout


def adr(decision: str, title: str = "Decision") -> str:
    return (
        f"# 1. {title}\n\n## Status\n\nAccepted\n\n## Context\n\nOur context.\n\n"
        f"## Decision\n\n{decision}\n\n## Consequences\n\nNoted.\n"
    )


ADR_PATH = "docs/adr/0001-decision.md"
NO_MONGO = adr("We must not use MongoDB.", "No MongoDB")
BOUNDARY = adr("The payments package may be imported only from billing/.", "Payments boundary")


def claim_of(repo: Path, kind: str | None = None) -> Claim:
    sets = structure_scan(scan_adrs(repo).decisions, repo, mode="offline")
    cs = [c for s in sets for c in s.claims if kind is None or c.kind == kind]
    assert len(cs) == 1, cs
    return cs[0]


# Violation kinds: (file, clean text, violating text). All judged by the rule library.
KINDS: dict[str, tuple[str, str, str]] = {
    "requirements": (
        "requirements.txt",
        "requests==2.31.0\n",
        "requests==2.31.0\npymongo==4.6.0\n",
    ),
    "pyproject": (
        "pyproject.toml",
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["requests>=2"]\n',
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["requests>=2", "pymongo>=4"]\n',
    ),
    "package_json": (
        "package.json",
        '{"name": "x", "dependencies": {"express": "^4.0.0"}}\n',
        '{"name": "x", "dependencies": {"express": "^4.0.0", "mongoose": "^8.0.0"}}\n',
    ),
    "import": ("app/db.py", "import os\n", "import os\nimport pymongo\n"),
    "compose": (
        "docker-compose.yml",
        "services:\n  web:\n    image: nginx:1.25\n",
        "services:\n  web:\n    image: nginx:1.25\n  db:\n    image: mongo:6\n",
    ),
    "terraform": (
        "infra/main.tf",
        'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n'
        '      version = "5.0.0"\n    }\n  }\n}\n',
        'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n'
        '      version = "5.0.0"\n    }\n    mongodbatlas = {\n'
        '      source = "mongodb/mongodbatlas"\n'
        '      version = "1.14.0"\n    }\n  }\n}\n',
    ),
}


def linear(n: int, violated: list[bool], kind: str = "requirements", extra=None) -> list[dict]:
    """n commits; the kind's file is violating at commit i iff violated[i]. The ADR is in
    commit 0. Every commit changes app/tick.py so no commit is tree-identical."""
    fname, clean, bad = KINDS[kind]
    cs = []
    for i in range(n):
        s = {fname: bad if violated[i] else clean, "app/tick.py": f"TICK = {i}\n"}
        if i == 0:
            s[ADR_PATH] = NO_MONGO
        if extra and i in extra:
            s.update(extra[i])
        cs.append({"set": s})
    return cs


def make(tmp_path: Path, name: str, commits: list[dict]) -> tuple[Path, list[str]]:
    repo = tmp_path / name
    return repo, fast_import(repo, commits)


# ------------------------------------------------------------------- G4 accounting

_COUNT = os.environ.get("SONNET_G4_COUNT_FILE")


def g4_ok(repo: Path, entry: TimelineEntry, claim: Claim, config=None) -> None:
    """Independent re-verification of a FOUND/TRUNCATED/NOT_VIOLATED entry with G4."""
    results = verify_first_violation(repo, entry, claim, config)
    assert results, "G4 returned no results"
    bad = [r for r in results if r.status != "VERIFIED"]
    assert not bad, [r.reason for r in bad]
    assert all(r.check_id == "G4" for r in results)
    assert entry.grounding == "VERIFIED", entry.reasons
    assert entry.checks and all(c.check_id == "G4" and c.status == "VERIFIED" for c in entry.checks)
    if _COUNT:
        with open(_COUNT, "a") as fh:
            fh.write(f"{entry.status}\n")


def assert_found(repo, e, claim, shas, idx):
    assert e.status == "FOUND", (e.status, e.reasons, e.notes[:3])
    assert e.first_violating_commit == shas[idx], (
        shas.index(e.first_violating_commit) if e.first_violating_commit in shas else "?",
        idx,
    )
    assert e.parent == (shas[idx - 1] if idx > 0 else None)
    g4_ok(repo, e, claim)


# ---------------------------------------------------------- property: random linear


def gen_history(rng: random.Random) -> list[bool]:
    n = rng.randint(20, 200)
    k = rng.randint(0, n - 1)
    v = [i >= k for i in range(n)]
    pos = k
    for _ in range(rng.choice([0, 0, 1, 1, 1, 2])):  # remove at j > pos, re-add at m > j
        if pos >= n - 2:
            break
        j = rng.randint(pos + 1, n - 2)
        m = rng.randint(j + 1, min(n - 1, j + rng.choice([1, 2, 3, 8, n])))
        for i in range(j, m):
            v[i] = False
        pos = m
    return v


def transitions(v: list[bool]) -> list[int]:
    return [i for i in range(len(v)) if v[i] and (i == 0 or not v[i - 1])]


def check_sampled(repo, shas, v, claim, e):
    t = transitions(v)
    idx = shas.index(e.first_violating_commit)
    assert e.status == "FOUND", (e.status, e.reasons)
    assert v[idx] and (idx == 0 or not v[idx - 1]), "reported boundary is not a real transition"
    assert e.parent == (shas[idx - 1] if idx else None)
    if len(t) == 1:  # monotonic truth: must be exact, no false alarm
        assert idx == t[0] and not e.non_monotonic and e.earlier_transitions == []
    if e.non_monotonic:  # linear scan: latest transition, truthful list of earlier ones
        assert idx == t[-1] and len(t) > 1
        assert e.earlier_transitions == [shas[x] for x in t[:-1]]
    assert e.commits_judged <= len(v)
    return idx != t[-1]


@pytest.mark.parametrize("seed", range(40))
def test_property_random_history(tmp_path, seed):
    rng = random.Random(1000 + seed)
    v = gen_history(rng)
    repo, shas = make(tmp_path, "r", linear(len(v), v))
    claim = claim_of(repo)
    t = transitions(v)

    ex = first_violation(repo, claim, exhaustive=True)
    assert_found(repo, ex, claim, shas, t[-1])
    assert ex.commits_judged == len(v)
    assert ex.non_monotonic == (len(t) > 1)
    assert ex.earlier_transitions == [shas[x] for x in t[:-1]]

    sa = first_violation(repo, claim)
    check_sampled(repo, shas, v, claim, sa)
    g4_ok(repo, sa, claim)
    if len(t) == 1 and len(v) >= 100:
        assert sa.commits_judged <= 3 * (len(v) ** 0.5) + 12  # ~sqrt(n) + log2(n), not n


def test_sampled_non_latest_rate(tmp_path_factory):
    """>= 200 random histories, sampled mode only. A non-latest answer is a documented
    limit; a boundary that is not a real transition, or a lying flag, is a failure."""
    total = nonlatest = nm_truth = flagged = 0
    nonlatest_unflagged = 0
    for seed in range(240):
        rng = random.Random(7000 + seed)
        v = gen_history(rng)
        repo, shas = make(tmp_path_factory.mktemp(f"rate{seed}"), "r", linear(len(v), v))
        claim = claim_of(repo)
        e = first_violation(repo, claim)
        non_latest = check_sampled(repo, shas, v, claim, e)
        total += 1
        nm_truth += len(transitions(v)) > 1
        flagged += e.non_monotonic
        nonlatest += non_latest
        nonlatest_unflagged += non_latest and not e.non_monotonic
        assert non_latest <= (len(transitions(v)) > 1)
    report = {
        "histories": total,
        "truth_non_monotonic": nm_truth,
        "flagged_non_monotonic": flagged,
        "non_latest": nonlatest,
        "non_latest_rate_all": round(nonlatest / total, 4),
        "non_latest_rate_among_non_monotonic": round(nonlatest / max(1, nm_truth), 4),
        "non_latest_and_unflagged": nonlatest_unflagged,
    }
    print("\nSAMPLED_RATE " + json.dumps(report))
    out = os.environ.get("SONNET_RATE_FILE")
    if out:
        Path(out).write_text(json.dumps(report))
    assert total >= 200


# --------------------------------------------------------------- violation kinds


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize("k", [0, 1, 13, 23])
def test_kind_boundary(tmp_path, kind, k):
    n = 24
    repo, shas = make(tmp_path, "r", linear(n, [i >= k for i in range(n)], kind))
    claim = claim_of(repo, "forbid")
    for ex in (False, True):
        e = first_violation(repo, claim, exhaustive=ex)
        assert_found(repo, e, claim, shas, k)
        assert e.evidence and all(ev.ref.commit == shas[k] for ev in e.evidence)


@pytest.mark.parametrize("kind", ["package_json", "compose", "terraform", "pyproject", "import"])
def test_kind_remove_and_readd(tmp_path, kind):
    v = [False] * 4 + [True] * 6 + [False] * 5 + [True] * 9
    repo, shas = make(tmp_path, "r", linear(len(v), v, kind))
    claim = claim_of(repo, "forbid")
    e = first_violation(repo, claim)
    assert_found(repo, e, claim, shas, 15)
    assert e.non_monotonic and e.earlier_transitions == [shas[4]]


def test_import_boundary_claim(tmp_path):
    cs = []
    for i in range(30):
        s = {"app/tick.py": f"TICK = {i}\n"}
        if i == 0:
            s |= {
                ADR_PATH: BOUNDARY,
                "payments/__init__.py": "",
                "payments/api.py": "VALUE = 1\n",
                "billing/__init__.py": "",
                "billing/use.py": "import payments.api\n",
                "web/__init__.py": "",
                "web/view.py": "import os\n",
            }
        if i == 19:
            s["web/view.py"] = "import os\nimport payments.api\n"
        cs.append({"set": s})
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo, "boundary")
    e = first_violation(repo, claim)
    assert_found(repo, e, claim, shas, 19)
    assert any(ev.kind == "import" and ev.ref.path == "web/view.py" for ev in e.evidence)


# ------------------------------------------------------------- history edge cases


def test_unknown_commits_count_as_not_violated_naturally(tmp_path):
    """'Handlers must not ...' is UNKNOWN until a handlers/ directory exists."""
    cs = []
    for i in range(14):
        s = {"app/tick.py": f"TICK = {i}\n"}
        if i == 0:
            s[ADR_PATH] = adr("Handlers must not use MongoDB.")
        if i == 2:
            s["requirements.txt"] = "pymongo==4.6.0\n"
        if i == 9:
            s["handlers/h.py"] = "import pymongo\n"
        cs.append({"set": s})
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    e = first_violation(repo, claim, exhaustive=True)
    assert_found(repo, e, claim, shas, 9)
    assert any("could not be judged" in n and "UNKNOWN" in n for n in e.notes)
    assert not e.non_monotonic


def test_unknown_gap_between_violations_is_non_monotonic(tmp_path):
    cs = []
    for i in range(16):
        s = {"app/tick.py": f"TICK = {i}\n"}
        if i == 0:
            s[ADR_PATH] = adr("Handlers must not use MongoDB.")
            s["requirements.txt"] = "pymongo\n"
        if i == 3:
            s["handlers/h.py"] = "x = 1\n"
        if i == 6:
            s["handlers/h.py"] = "import pymongo\n"
        if i == 8:
            cs.append({"set": s, "delete": ["handlers/h.py"]})
            continue
        if i == 12:
            s["handlers/h.py"] = "import pymongo\n"
        cs.append({"set": s})
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    e = first_violation(repo, claim, exhaustive=True)
    assert_found(repo, e, claim, shas, 12)
    assert e.non_monotonic and e.earlier_transitions == [shas[6]]


def test_renamed_violating_file_boundary_is_introduction_not_rename(tmp_path):
    v = [i >= 6 for i in range(20)]
    cs = linear(20, v)
    cs[13] = {
        "set": {"backend/requirements.txt": KINDS["requirements"][2], "app/tick.py": "TICK = 13\n"},
        "delete": ["requirements.txt"],
    }
    for i in range(14, 20):
        cs[i]["set"]["backend/requirements.txt"] = KINDS["requirements"][2]
        cs[i]["set"].pop("requirements.txt")
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    for ex in (False, True):
        assert_found(repo, first_violation(repo, claim, exhaustive=ex), claim, shas, 6)


def test_rename_just_before_violation(tmp_path):
    cs = linear(18, [False] * 18)
    cs[5] = {
        "set": {"deps/requirements.txt": KINDS["requirements"][1], "app/tick.py": "TICK = 5\n"},
        "delete": ["requirements.txt"],
    }
    for i in range(6, 18):
        cs[i]["set"].pop("requirements.txt")
        cs[i]["set"]["deps/requirements.txt"] = (
            KINDS["requirements"][2] if i >= 11 else KINDS["requirements"][1]
        )
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    assert_found(repo, first_violation(repo, claim), claim, shas, 11)


def test_renamed_adr_boundary_is_the_rename_commit(tmp_path):
    """Documented limit: before the rename the ADR path does not exist."""
    cs = linear(16, [True] * 16)
    cs[9] = {
        "set": {
            "docs/decisions/0001-decision.md": NO_MONGO,
            "app/tick.py": "TICK = 9\n",
            "requirements.txt": KINDS["requirements"][2],
        },
        "delete": [ADR_PATH],
    }
    for i in range(10, 16):
        cs[i]["set"].pop(ADR_PATH, None)
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    assert claim.source.path == "docs/decisions/0001-decision.md"
    e = first_violation(repo, claim)
    assert_found(repo, e, claim, shas, 9)
    assert any("not present" in n for n in e.notes)


def test_adr_added_after_the_violation(tmp_path):
    cs = linear(20, [True] * 20)
    cs[0]["set"].pop(ADR_PATH)
    cs[11]["set"][ADR_PATH] = NO_MONGO
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    for ex in (False, True):
        e = first_violation(repo, claim, exhaustive=ex)
        assert_found(repo, e, claim, shas, 11)
        assert any("decision not taken yet" in n for n in e.notes)


def test_adr_only_commit_and_empty_commits_are_never_boundaries(tmp_path):
    k = 10
    cs = linear(24, [i >= k for i in range(24)])
    cs[k + 1] = {"set": {ADR_PATH: NO_MONGO + "\nAddendum.\n"}}  # touches only the ADR
    cs[k + 2] = {}  # empty commit
    cs[k - 1] = {}  # empty commit right before the boundary
    cs[k - 2] = {"set": {ADR_PATH: NO_MONGO + "\nEdit.\n"}}
    for i in range(k + 3, 24):  # keep content identical afterwards
        cs[i]["set"].pop("requirements.txt", None)
    cs[k]["set"]["requirements.txt"] = KINDS["requirements"][2]
    repo, shas = make(tmp_path, "r", cs)
    claim = claim_of(repo)
    for ex in (False, True):
        assert_found(repo, first_violation(repo, claim, exhaustive=ex), claim, shas, k)


def test_empty_commit_is_head(tmp_path):
    cs = linear(12, [i >= 7 for i in range(12)])
    cs.append({})
    repo, shas = make(tmp_path, "r", cs)
    assert_found(repo, first_violation(repo, claim_of(repo)), claim_of(repo), shas, 7)


def merge_history(octopus: bool, side_reverts: bool = False) -> list[dict]:
    clean, bad = KINDS["requirements"][1], KINDS["requirements"][2]
    cs = [{"set": {ADR_PATH: NO_MONGO, "requirements.txt": clean, "app/m0.py": "A = 0\n"}}]
    for i in range(1, 5):
        cs.append({"set": {f"app/m{i}.py": f"A = {i}\n"}})  # 1..4 main
    cs.append(
        {"set": {"side/s1.py": "S = 1\n", "requirements.txt": bad}, "ref": "side", "parents": [2]}
    )  # 5
    cs.append(
        {
            "set": {
                "side/s2.py": "S = 2\n",
                **({"requirements.txt": clean} if side_reverts else {}),
            },
            "ref": "side",
            "parents": [5],
        }
    )  # 6
    cs.append({"set": {"other/o1.py": "O = 1\n"}, "ref": "other", "parents": [3]})  # 7
    parents = [4, 6, 7] if octopus else [4, 6]
    delta = {"requirements.txt": clean if side_reverts else bad, "app/merged.py": "M = 1\n"}
    cs.append({"set": delta, "parents": parents, "msg": "the merge"})  # 8
    cs.append({"set": {"app/after.py": "Z = 1\n"}})  # 9
    return cs


@pytest.mark.parametrize("octopus", [False, True])
def test_merge_boundary_is_the_merge_commit(tmp_path, octopus):
    repo, shas = make(tmp_path, "r", merge_history(octopus))
    claim = claim_of(repo)
    chain = run_git(repo, "rev-list", "--first-parent", "--reverse", "HEAD").split()
    assert shas[5] not in chain and shas[6] not in chain
    for ex in (False, True):
        e = first_violation(repo, claim, exhaustive=ex)
        assert e.first_violating_commit == shas[8]
        assert e.parent == shas[4]
        assert e.subject == "the merge"
        assert any("merge commit" in n for n in e.notes)
        g4_ok(repo, e, claim)


def test_merge_that_drops_the_side_change_is_not_a_violation(tmp_path):
    repo, shas = make(tmp_path, "r", merge_history(False, side_reverts=True))
    claim = claim_of(repo, "forbid")
    e = first_violation(repo, claim)
    assert e.status == "NOT_VIOLATED_AT_HEAD"
    g4_ok(repo, e, claim)


def test_walk_from_an_older_head_and_from_a_side_branch_tip(tmp_path):
    repo, shas = make(tmp_path, "r", merge_history(False))
    claim = claim_of(repo)
    e = first_violation(repo, claim, head=shas[8])
    assert e.first_violating_commit == shas[8] and e.head == shas[8]
    e = first_violation(repo, claim, head=shas[4])
    assert e.status == "NOT_VIOLATED_AT_HEAD"
    e = first_violation(repo, claim, head=shas[6])  # side branch tip: its own first-parent chain
    assert e.first_violating_commit == shas[5] and e.parent == shas[2]
    g4_ok(repo, e, claim)


def test_head_given_as_abbreviation_branch_and_tag(tmp_path):
    repo, shas = make(tmp_path, "r", linear(15, [i >= 4 for i in range(15)]))
    claim = claim_of(repo)
    run_git(repo, "tag", "v1", shas[10])
    for ref in (shas[10][:10], "v1", "main~4"):
        e = first_violation(repo, claim, head=ref)
        assert e.head == shas[10] and e.first_violating_commit == shas[4]
        g4_ok(repo, e, claim)


def test_bad_inputs_are_unknown_not_crashes(tmp_path):
    repo, shas = make(tmp_path, "r", linear(10, [i >= 4 for i in range(10)]))
    claim = claim_of(repo)
    for kw in ({"head": "no-such-ref"}, {"max_commits": 0}, {"max_commits": -3}):
        e = first_violation(repo, claim, **kw)
        assert e.status == "UNKNOWN" and e.grounding == "MISMATCH" and e.reasons
        assert e.first_violating_commit is None and "unknown" in e.first_seen
    with pytest.raises(dwgit.NotAGitRepoError):
        first_violation(tmp_path / "nope", claim)


def test_uncommitted_adr_skips_presence_check_with_note(tmp_path):
    cs = linear(12, [i >= 5 for i in range(12)])
    cs[0]["set"].pop(ADR_PATH)
    repo, shas = make(tmp_path, "r", cs)
    (repo / ADR_PATH).parent.mkdir(parents=True, exist_ok=True)
    (repo / ADR_PATH).write_text(NO_MONGO)  # worktree only
    claim = claim_of(repo)
    e = first_violation(repo, claim)
    assert_found(repo, e, claim, shas, 5)
    assert any("ADR-presence check skipped" in n for n in e.notes)


# ------------------------------------------------------------------- truncation


@pytest.mark.parametrize("k", [0, 15, 29])
@pytest.mark.parametrize("exhaustive", [False, True])
def test_max_commits_every_cap(tmp_path, k, exhaustive):
    n = 30
    repo, shas = make(tmp_path, "r", linear(n, [i >= k for i in range(n)]))
    claim = claim_of(repo)
    for cap in range(1, n + 2):
        e = first_violation(repo, claim, max_commits=cap, exhaustive=exhaustive)
        w = max(0, n - cap)  # oldest commit of the window
        if w >= 1 and w >= k:  # whole window violated and older history exists
            assert e.status == "TRUNCATED", (cap, e.status)
            assert e.truncated_by == "max_commits" and e.oldest_available == shas[w]
            assert e.first_violating_commit is None and e.parent is None
            assert "unknown" not in e.first_seen and "truncated" in e.first_seen
        else:  # transition (or root) is inside the window
            assert e.status == "FOUND", (cap, e.status, e.notes[:2])
            assert e.first_violating_commit == shas[k], cap
        g4_ok(repo, e, claim)


def test_shallow_clone_never_guesses(tmp_path):
    repo, shas = make(tmp_path, "src", linear(30, [i >= 10 for i in range(30)]))
    claim_src = claim_of(repo)
    assert claim_src
    for depth, expect in ((1, "TRUNCATED"), (5, "TRUNCATED"), (20, "TRUNCATED"), (21, "FOUND")):
        clone = tmp_path / f"c{depth}"
        run_git(tmp_path, "clone", "-q", "--depth", str(depth), f"file://{repo}", str(clone))
        claim = claim_of(clone)
        for ex in (False, True):
            e = first_violation(clone, claim, exhaustive=ex)
            assert e.status == expect, (depth, ex, e.status, e.notes[:3])
            if expect == "TRUNCATED":
                assert e.truncated_by == "shallow"
                assert e.oldest_available == shas[30 - depth]
                assert e.first_violating_commit is None
            else:
                assert e.first_violating_commit == shas[10] and e.parent == shas[9]
            g4_ok(clone, e, claim)


def test_shallow_root_like_commit_is_not_called_root(tmp_path):
    """A shallow boundary commit has no visible parent but is not a root commit."""
    repo, shas = make(tmp_path, "src", linear(12, [True] * 12))
    clone = tmp_path / "c"
    run_git(tmp_path, "clone", "-q", "--depth", "3", f"file://{repo}", str(clone))
    claim = claim_of(clone)
    e = first_violation(clone, claim)
    assert e.status == "TRUNCATED" and e.parent is None and e.first_violating_commit is None
    forged = TimelineEntry(
        claim_id=claim.id,
        status="FOUND",
        head=e.head,
        first_violating_commit=e.oldest_available,
        parent=None,
        author_date="2026-01-01T00:00:00+00:00",
        subject="x",
        evidence=e.evidence,
    )
    assert any(r.status == "MISMATCH" for r in verify_first_violation(clone, forged, claim))


def test_truncated_window_with_missed_dip_is_not_called_all_violated(tmp_path):
    """TRUNCATED says 'violated over the whole window'. Count how often sampled mode
    says that although a held commit exists inside the window."""
    wrong = 0
    runs = 0
    for seed in range(30):
        rng = random.Random(500 + seed)
        n = rng.randint(60, 160)
        dip = rng.randint(n // 3, n - 3)
        v = [True] * n
        v[dip] = False  # a single held commit inside a violated history
        repo, shas = make(tmp_path / str(seed), "r", linear(n, v))
        claim = claim_of(repo)
        cap = n - rng.randint(0, dip - 1)  # window starts before the dip
        e = first_violation(repo, claim, max_commits=min(cap, n - 1))
        runs += 1
        if e.status == "TRUNCATED":
            wrong += 1
        else:
            assert e.status == "FOUND" and e.first_violating_commit == shas[dip + 1]
    print(f"\nTRUNCATED_WITH_HELD_COMMIT_IN_WINDOW {wrong}/{runs}")
    assert wrong == 0, f"{wrong}/{runs} windows with a held commit reported as TRUNCATED"


# ------------------------------------------------------------------ build_timeline


def test_build_timeline_two_claims_shared_cache_and_missing_claim(tmp_path):
    cs = []
    for i in range(26):
        s = {"app/tick.py": f"TICK = {i}\n"}
        if i == 0:
            s |= {
                ADR_PATH: NO_MONGO,
                "docs/adr/0002-payments.md": BOUNDARY.replace("# 1.", "# 2."),
                "requirements.txt": KINDS["requirements"][1],
                "payments/__init__.py": "",
                "payments/api.py": "V = 1\n",
                "billing/__init__.py": "",
                "billing/b.py": "import payments.api\n",
                "web/__init__.py": "",
                "web/v.py": "import os\n",
            }
        if i == 8:
            s["requirements.txt"] = KINDS["requirements"][2]
        if i == 17:
            s["web/v.py"] = "import payments.api\n"
        cs.append({"set": s})
    repo, shas = make(tmp_path, "r", cs)
    sets = structure_scan(scan_adrs(repo).decisions, repo, mode="offline")
    claims = [c for s in sets for c in s.claims]
    assert len(claims) == 2
    verdicts = judge_claims(repo, claims, mode="offline")
    assert all(v.status == "VIOLATED" for v in verdicts)
    ledger = Ledger(tmp_path / "led")
    out = build_timeline(repo, claims, verdicts, ledger=ledger)
    by_kind = {c.id: c.kind for c in claims}
    got = {by_kind[e.claim_id]: shas.index(e.first_violating_commit) for e in out}
    assert got == {"forbid": 8, "boundary": 17}
    for e in out:
        g4_ok(repo, e, next(x for x in claims if x.id == e.claim_id))
    # a verdict whose claim is missing is a visible UNKNOWN, not a gap
    out2 = build_timeline(repo, claims[:1], verdicts, ledger=ledger)
    assert len(out2) == 2 and sorted(e.status for e in out2) == ["FOUND", "UNKNOWN"]
    # holding verdicts are skipped
    held = [v.model_copy(update={"status": "HOLDING"}) for v in verdicts]
    assert build_timeline(repo, claims, held) == []


# ----------------------------------------------------------------------- tampering


def _entries_for_tamper(tmp_path):
    out = []
    # 1: plain monotonic dependency
    repo, shas = make(tmp_path, "t1", linear(22, [i >= 9 for i in range(22)]))
    c = claim_of(repo)
    out.append((repo, shas, c, first_violation(repo, c)))
    # 2: root violation (parent None)
    repo, shas = make(tmp_path, "t2", linear(12, [True] * 12, "package_json"))
    c = claim_of(repo)
    out.append((repo, shas, c, first_violation(repo, c)))
    # 3: merge boundary
    repo, shas = make(tmp_path, "t3", merge_history(False))
    c = claim_of(repo)
    out.append((repo, shas, c, first_violation(repo, c)))
    # 4: non-monotonic with earlier transitions
    v = [False] * 3 + [True] * 4 + [False] * 4 + [True] * 11
    repo, shas = make(tmp_path, "t4", linear(len(v), v, "compose"))
    c = claim_of(repo)
    out.append((repo, shas, c, first_violation(repo, c)))
    # 5: two evidence items
    cs = linear(18, [False] * 18)
    for i in range(7, 18):
        cs[i]["set"]["requirements.txt"] = "requests\npymongo==4.6.0\n"
        cs[i]["set"]["package.json"] = '{"name": "x", "dependencies": {"mongoose": "^8"}}\n'
    repo, shas = make(tmp_path, "t5", cs)
    c = claim_of(repo)
    out.append((repo, shas, c, first_violation(repo, c)))
    for _, _, _, e in out:
        assert e.status == "FOUND" and e.grounding == "VERIFIED"
    return out


_SHA = re.compile(r"^[0-9a-f]{40}$")


def _leaf_mutations(key: str, val, pool: list[str]):
    """Yield (label, new_value) for one leaf. Own operators."""
    if isinstance(val, bool):
        yield "flip", not val
    elif isinstance(val, int):
        for d in (1, -1, 1000, -1000):
            yield f"add{d}", val + d
        yield "zero", 0
    elif isinstance(val, str):
        yield "append", val + "x"
        yield "prepend_space", " " + val
        yield "trailing_nl", val + "\n"
        yield "zero_width", "​" + val
        yield "empty", ""
        if val:
            yield "drop_last", val[:-1]
            yield "drop_first", val[1:]
            yield "reverse", val[::-1]
            yield "swap_case", val.swapcase()
            mid = len(val) // 2
            yield "mid_char", val[:mid] + ("~" if val[mid] != "~" else "!") + val[mid + 1 :]
            yield "cyrillic", val.replace("a", "а", 1).replace("e", "е", 1)
        if _SHA.match(val):
            yield "flip_nibble", val[:-1] + ("0" if val[-1] != "0" else "1")
            yield "abbrev12", val[:12]
            yield "upper", val.upper()
            for j, other in enumerate(pool[:6]):
                if other != val:
                    yield f"swap_commit{j}", other
            yield "nonexistent", "f" * 40
    elif val is None:
        yield "str", "bogus"
        yield "sha", pool[0] if pool else "a" * 40
        yield "int", 7
    elif isinstance(val, list):
        yield "clear", []
        yield (
            "append_bogus",
            [*val, "bogus"] if all(isinstance(x, str) for x in val) else [*val, {}],
        )
        if val:
            yield "dup_first", [*val, val[0]]
            yield "reverse", val[::-1]
            for i in range(len(val)):
                yield f"drop{i}", val[:i] + val[i + 1 :]


def _walk(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, (*path, k))
        yield path, obj
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        for i, v in enumerate(obj):
            yield from _walk(v, (*path, i))
        yield path, obj
    else:
        yield path, obj


def _set(d, path, val):
    cur = d
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = val


def all_mutations(entry: TimelineEntry, pool: list[str]):
    base = entry.model_dump()
    for path, val in _walk(base):
        if not path or isinstance(val, dict):
            continue
        for label, new in _leaf_mutations(str(path[-1]), val, pool):
            if new == val:
                continue
            m = json.loads(json.dumps(base))
            _set(m, path, new)
            yield ".".join(map(str, path)), label, m
    for ev_i in range(len(base["evidence"])):  # structural: swap in a foreign evidence item
        m = json.loads(json.dumps(base))
        m["evidence"][ev_i]["id"] = "e999"
        yield f"evidence.{ev_i}", "foreign_id", m
    for status in ("NOT_VIOLATED_AT_HEAD", "TRUNCATED", "UNKNOWN", "BOGUS"):
        m = json.loads(json.dumps(base))
        m["status"] = status
        yield "status", f"to_{status}", m


def classify(repo, claim, mutated: dict) -> str:
    try:
        entry = TimelineEntry.model_validate(mutated)
    except ValidationError:
        return "rejected_by_model"
    results = verify_first_violation(repo, entry, claim)
    assert results and all(r.check_id == "G4" for r in results)
    if any(r.status != "VERIFIED" for r in results):
        graded = apply_grounding(entry, results)
        assert graded.status == "UNKNOWN" and graded.grounding == "MISMATCH" and graded.reasons
        return "mismatch"
    return "UNDETECTED"


DESCRIPTIVE = {
    "notes",
    "commits_judged",
    "commits_in_window",
    "non_monotonic",
    "earlier_transitions",
    "reasons",
    "proposed_status",
    "oldest_available",
    "head",
    "evidence",
}


def test_g4_tamper_every_field(tmp_path):
    uncaught: dict[str, list[str]] = {}
    total = caught = 0
    kinds: dict[str, int] = {}
    for repo, shas, claim, entry in _entries_for_tamper(tmp_path):
        pool = [entry.head, entry.parent or "", shas[0], shas[len(shas) // 2], shas[-1]]
        pool = [p for p in pool if p and p != entry.first_violating_commit]
        for field_path, label, m in all_mutations(entry, pool):
            total += 1
            res = classify(repo, claim, m)
            kinds[res] = kinds.get(res, 0) + 1
            if res == "UNDETECTED":
                uncaught.setdefault(field_path, []).append(label)
            else:
                caught += 1
    print(f"\nTAMPER total={total} caught={caught} kinds={kinds}")
    print("TAMPER_UNDETECTED " + json.dumps({k: len(v) for k, v in sorted(uncaught.items())}))
    out = os.environ.get("SONNET_TAMPER_FILE")
    if out:
        Path(out).write_text(
            json.dumps({"total": total, "caught": caught, "kinds": kinds, "undetected": uncaught})
        )
    assert total >= 500
    # `checks.*` are G4's own recorded output (re-derived on every verify), not assertions
    # about the repository; descriptive fields are reported by the next test.
    fact = {
        k: v for k, v in uncaught.items() if not k.startswith("checks") and k not in DESCRIPTIVE
    }
    assert not fact, fact
    descr = {k: len(v) for k, v in uncaught.items() if k in DESCRIPTIVE}
    print("TAMPER_DESCRIPTIVE_UNDETECTED " + json.dumps(descr))
    assert not descr, f"G4 verifies none of these descriptive fields: {descr}"


def test_g4_unverified_metadata_is_not_a_fact_claim(tmp_path):
    """Fields G4 does not check (notes, counters, flags) must at least not be able to change
    the boundary: report them here so the gap is explicit rather than silent."""
    repo, shas = make(tmp_path, "r", linear(20, [i >= 5 for i in range(20)]))
    claim = claim_of(repo)
    e = first_violation(repo, claim)
    lie = e.model_copy(update={"non_monotonic": True, "earlier_transitions": [shas[1]]})
    results = verify_first_violation(repo, lie, claim)
    assert any(r.status == "MISMATCH" for r in results), "G4 accepts a forged earlier_transitions"


def test_g4_tamper_truncated_and_not_violated(tmp_path):
    repo, shas = make(tmp_path, "r", linear(20, [i >= 4 for i in range(20)]))
    claim = claim_of(repo)
    tr = first_violation(repo, claim, max_commits=6)
    assert tr.status == "TRUNCATED"
    nv = first_violation(repo, claim, head=shas[2])
    assert nv.status == "NOT_VIOLATED_AT_HEAD"
    bad = []
    for entry in (tr, nv):
        for fld, label, m in all_mutations(entry, [shas[0], shas[10], shas[-1]]):
            if fld in {"notes", "commits_judged", "commits_in_window", "checks"} or fld.startswith(
                "notes"
            ):
                continue
            if classify(repo, claim, m) == "UNDETECTED":
                bad.append((entry.status, fld, label))
    # Fields that are not assertions about the repo may legitimately survive (head moved to
    # another commit that is still violated/not violated is a different but true statement).
    print("\nTRUNC/NV_UNDETECTED", sorted({(b[0], b[1]) for b in bad}))
    assert not [b for b in bad if b[1] not in {"head", "oldest_available", "evidence"}], bad


def test_g4_cross_claim_and_repo_substitution(tmp_path):
    repo, shas = make(tmp_path, "a", linear(20, [i >= 5 for i in range(20)]))
    repo2, shas2 = make(tmp_path, "b", linear(20, [i >= 12 for i in range(20)]))
    claim, claim2 = claim_of(repo), claim_of(repo2)
    e = first_violation(repo, claim)
    # same claim id on a different repo: the commits do not exist there
    assert any(r.status == "MISMATCH" for r in verify_first_violation(repo2, e, claim2))
    # entry for a different claim
    other = claim.model_copy(update={"id": "ADR-9999.c1"})
    assert any(r.status == "MISMATCH" for r in verify_first_violation(repo, e, other))
    with pytest.raises(dwgit.NotAGitRepoError):
        verify_first_violation(tmp_path / "nowhere", e, claim)


# ------------------------------------------------------------------ never an LLM


def test_judging_never_calls_a_provider_or_llm(tmp_path, monkeypatch):
    import driftwarden.llm as llm

    calls: list[str] = []

    def factory(*_a, **_k):
        calls.append("get_provider")
        raise AssertionError("provider factory called")

    monkeypatch.setattr(llm, "get_provider", factory)
    for mod in ("driftwarden.cli", "driftwarden.timeline.bisect", "driftwarden.judge.judge"):
        m = __import__(mod, fromlist=["x"])
        if hasattr(m, "get_provider"):
            monkeypatch.setattr(m, "get_provider", factory)
    modes: list[str] = []
    real_init = judge_mod.Judge.__init__

    def spy(self, *a, **k):
        real_init(self, *a, **k)
        modes.append(self.mode)
        assert self.provider is None or getattr(self.provider, "offline", False)

    monkeypatch.setattr(judge_mod.Judge, "__init__", spy)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    cfg = Config(mode="llm", provider="anthropic")

    v = [False] * 5 + [True] * 4 + [False] * 3 + [True] * 20
    repo, shas = make(tmp_path, "r", linear(len(v), v))
    claim = claim_of(repo)
    for ex in (False, True):
        e = first_violation(repo, claim, config=cfg, exhaustive=ex)
        assert e.status == "FOUND" and e.grounding == "VERIFIED"
        # exhaustive is exact; sampled may legitimately return the older real transition (5)
        assert e.first_violating_commit == shas[12 if ex else 12] or (
            not ex and e.first_violating_commit == shas[5]
        )
    verdicts = judge_claims(repo, [claim], mode="offline")
    out = build_timeline(repo, [claim], verdicts, config=cfg)
    assert out and out[0].status == "FOUND"
    assert calls == [] and modes and set(modes) == {"offline"}


# -------------------------------------------------------------------------- ledger


def test_ledger_every_result_is_g4_and_jsonl_is_valid(tmp_path):
    ledger = Ledger(tmp_path / "ledger", run_id="sonnet-l011")
    repo, shas = make(tmp_path, "r", linear(25, [i >= 9 for i in range(25)]))
    claim = claim_of(repo)
    entries = [
        first_violation(repo, claim, ledger=ledger),
        first_violation(repo, claim, head=shas[3], ledger=ledger),  # NOT_VIOLATED_AT_HEAD
        first_violation(repo, claim, max_commits=5, ledger=ledger),  # TRUNCATED
        first_violation(repo, claim, head="nope", ledger=ledger),  # UNKNOWN (MISMATCH row)
    ]
    assert [e.status for e in entries] == ["FOUND", "NOT_VIOLATED_AT_HEAD", "TRUNCATED", "UNKNOWN"]
    lines = ledger.path.read_text().splitlines()
    rows = [json.loads(x) for x in lines]  # every line is valid JSON
    assert len(rows) == sum(len(e.checks) for e in entries) > 4
    assert {r["check_id"] for r in rows} == {"G4"}
    assert all(
        r["run_id"] == "sonnet-l011" and r["status"] in ("VERIFIED", "MISMATCH") for r in rows
    )
    assert sum(r["status"] == "MISMATCH" for r in rows) == 1
    summary = ledger.summary()
    assert summary["total"] == len(rows)
    assert set(summary["by_check"]) == {"G4"}


# ------------------------------------------------------------------------ performance


def test_perf_500_commits(tmp_path):
    n = 500
    k = 337
    repo, shas = make(tmp_path, "r", linear(n, [i >= k for i in range(n)]))
    claim = claim_of(repo)
    t0 = time.perf_counter()
    e = first_violation(repo, claim)  # default max_commits == 500
    dt = time.perf_counter() - t0
    assert_found(repo, e, claim, shas, k)
    assert e.commits_in_window == 500 and not e.non_monotonic
    assert e.commits_judged <= 45, e.commits_judged  # ~sqrt(500)+log2(500), nowhere near 500
    assert dt < 30, dt
    print(f"\nPERF n=500 judged={e.commits_judged} seconds={dt:.2f}")
    # a smaller cap on the same repo is still fast, and TRUNCATED when the window is all bad
    t0 = time.perf_counter()
    e2 = first_violation(repo, claim, max_commits=100)
    assert e2.status == "TRUNCATED" and time.perf_counter() - t0 < 30
    # a cache reused across claims is a cache: second run loads nothing new
    cache = SnapshotCache(repo)
    first_violation(repo, claim, cache=cache)
    loads = cache.loads
    first_violation(repo, claim, cache=cache)
    assert cache.loads == loads and cache.hits > 0
