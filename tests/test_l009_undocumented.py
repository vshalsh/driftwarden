"""L-009: undocumented-decision detector (pipeline step 8), G3/G2/G5 grounding.

Fixtures live in ``tests/fixtures/undocumented_repos/<name>/``: each numbered
sub-directory is one commit (its files are written over the previous state), and
``expected.json`` lists the seeded undocumented choices (with the step that
introduced them), the documented controls and the dev/test-only controls.

Offline: sockets are disabled for every test.
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from conftest import git
from driftwarden.claims import structure_scan
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_commits_exist, verify_dependency
from driftwarden.judge import catalog, verify_evidence
from driftwarden.models import WORKTREE, Claim, Provenance, UndocumentedDecision
from driftwarden.undocumented import (
    DETECTED_CATEGORIES,
    adr_mentions,
    detect_undocumented,
    technology_terms,
    verify_undocumented,
)
from driftwarden.undocumented import detect as detect_mod

FIXTURES = Path(__file__).parent / "fixtures" / "undocumented_repos"
NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
SHA40 = re.compile(r"[0-9a-f]{40}")


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


# ------------------------------------------------------------------ fixture building


def _init(repo: Path) -> None:
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")


def _commit(repo: Path, files: dict[str, str | None], msg: str) -> str:
    """Write ``files`` (None deletes) fresh -- never copy with preserved mtimes, or git
    can miss a same-size edit -- and commit them."""
    for rel, content in files.items():
        p = repo / rel
        if content is None:
            git(repo, "rm", "-q", "--", rel)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode("utf-8"))
        git(repo, "add", "--", rel)
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD").strip()


def build_fixture(tmp_path: Path, name: str) -> tuple[Path, dict[str, str], dict]:
    """The fixture as a real git repo: (repo, step name -> commit SHA, expected)."""
    src = FIXTURES / name
    repo = tmp_path / f"ud-{name}"
    _init(repo)
    steps: dict[str, str] = {}
    for step in sorted(d.name for d in src.iterdir() if d.is_dir()):
        files = {
            f.relative_to(src / step).as_posix(): f.read_text(encoding="utf-8")
            for f in sorted((src / step).rglob("*"))
            if f.is_file()
        }
        steps[step] = _commit(repo, files, step)
    expected = json.loads((src / "expected.json").read_text(encoding="utf-8"))
    return repo, steps, expected


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """Every fixture built and scanned once: name -> (repo, steps, expected, scan)."""
    base = tmp_path_factory.mktemp("l009")
    out = {}
    for name in NAMES:
        repo, steps, expected = build_fixture(base, name)
        out[name] = (repo, steps, expected, detect_undocumented(repo))
    return out


def _label(rec) -> str:
    return f"{rec.category}/{rec.technology}"


# ------------------------------------------------------------------ acceptance


def test_at_least_four_fixtures():
    assert len(NAMES) >= 4
    seeded = sum(
        len(json.loads((FIXTURES / n / "expected.json").read_text())["undocumented"]) for n in NAMES
    )
    assert seeded >= 8


@pytest.mark.parametrize("name", NAMES)
def test_finds_every_seeded_choice_and_nothing_else(built, name):
    repo, steps, expected, scan = built[name]
    want = {f"{u['category']}/{u['technology']}" for u in expected["undocumented"]}
    got = {_label(r) for r in scan.findings}
    assert got == want, (got, want, [r.reasons for r in scan.could_not_verify])
    assert scan.could_not_verify == []
    by = {_label(r): r for r in scan.findings}
    for u in expected["undocumented"]:
        rec = by[f"{u['category']}/{u['technology']}"]
        assert rec.introducing_commits == [steps[s] for s in u["introduced_in"]], rec.id
        assert rec.status == "UNDOCUMENTED" and rec.grounding == "VERIFIED"
        assert rec.display_status == "Undocumented"


@pytest.mark.parametrize("name", NAMES)
def test_documented_controls_are_never_flagged(built, name):
    _, _, expected, scan = built[name]
    flagged = {_label(r) for r in scan.records}
    for label in expected["documented"]:
        assert label in scan.documented, (label, scan.documented)
        assert label not in flagged
    for label in expected["nonproduction"]:
        assert label in scan.nonproduction, (label, scan.nonproduction)
        assert label not in flagged


def test_zero_flags_on_documented_controls_across_fixtures(built):
    documented = flags = 0
    for name in NAMES:
        _, _, expected, scan = built[name]
        labels = {_label(r) for r in scan.records}
        for label in expected["documented"] + expected["nonproduction"]:
            documented += 1
            flags += label in labels
    assert documented >= 10
    assert flags == 0


@pytest.mark.parametrize("name", NAMES)
def test_every_record_is_pinned_and_its_evidence_verifies(built, name):
    repo, _, _, scan = built[name]
    head = git(repo, "rev-parse", "HEAD").strip()
    for rec in scan.findings:
        assert rec.commit == head and SHA40.fullmatch(rec.commit)
        assert rec.evidence and rec.introducing_commits
        assert all(SHA40.fullmatch(c) for c in rec.introducing_commits)
        assert {i.evidence_id for i in rec.introductions} == {e.id for e in rec.evidence}
        for ev in rec.evidence:
            assert ev.production and ev.technology == rec.technology
            assert ev.ref.commit == head
            results = verify_evidence(repo, ev, commit=head)
            assert all(r.status == "VERIFIED" for r in results), [r.reason for r in results]
            if ev.kind in ("dependency", "infra"):
                assert ev.dependency is not None
                assert verify_dependency(repo, ev.dependency).status == "VERIFIED"
            else:
                assert ev.kind == "import" and ev.dependency is None
        for intro in rec.introductions:
            assert SHA40.fullmatch(intro.commit) and intro.ref.commit == intro.commit
        assert all(c.status == "VERIFIED" for c in rec.checks)
        assert {c.check_id for c in rec.checks} >= {"G2", "G5"}


def test_grounding_numbers(built, capsys):
    """Every check behind every finding is VERIFIED (G2, G3, G5); counts are printed."""
    by_check: dict[str, list[int]] = {}
    for name in NAMES:
        for c in built[name][3].checks:
            ok, total = by_check.setdefault(c.check_id, [0, 0])
            by_check[c.check_id] = [ok + (c.status == "VERIFIED"), total + 1]
    assert {"G2", "G3", "G5"} <= set(by_check)
    for cid, (ok, total) in by_check.items():
        assert ok == total, cid
    with capsys.disabled():
        shown = ", ".join(f"{k} {ok}/{t}" for k, (ok, t) in sorted(by_check.items()))
        print(f"\nL-009 grounding: {shown}")


def test_version_bump_does_not_move_the_introduction(built):
    repo, steps, _, scan = built["pyservice"]
    rec = next(r for r in scan.findings if r.technology == "redis")
    dep = next(e for e in rec.evidence if e.kind == "dependency")
    assert dep.ref.quote == "redis==5.0.1"  # bumped in step 04 ...
    assert rec.introducing_commits == [steps["02-add-redis"]]  # ... introduced in step 02
    blame = git(repo, "blame", "-l", "-L", f"{dep.ref.line_start},+1", "--", dep.ref.path)
    assert blame.split()[0].lstrip("^") == steps["04-dev-tools-and-bump"]


def test_import_only_choice_is_found(built):
    rec = next(r for r in built["aliases"][3].findings if r.technology == "mongodb")
    assert [e.kind for e in rec.evidence] == ["import"]
    assert rec.evidence[0].ref.quote == "from pymongo import MongoClient"


def test_root_commit_introduction(built):
    repo, steps, _, scan = built["aliases"]
    rec = next(r for r in scan.findings if r.technology == "flask")
    assert rec.introducing_commits == [steps["01-initial"]]
    assert all(i.parents == [] for i in rec.introductions)


def test_records_are_json_round_trippable(built):
    for name in NAMES:
        repo = built[name][0]
        for rec in built[name][3].findings:
            again = UndocumentedDecision.model_validate_json(rec.model_dump_json())
            assert again == rec
            assert verify_undocumented(repo, again).grounding == "VERIFIED"


# ------------------------------------------------------------------ tamper mutations


def _parent(repo: Path, commit: str) -> str | None:
    out = git(repo, "rev-list", "--parents", "-n", "1", commit).split()
    return out[1] if len(out) > 1 else None


def _other_tech(tech: str, category: str) -> str:
    if category == "iac-provider":
        return "azure-sdk" if tech != "azure-sdk" else "gcp-sdk"
    return next(t.id for t in catalog.members(category) if t.id != tech)


def _mutations(repo: Path, rec: UndocumentedDecision) -> dict[str, dict]:
    """name -> mutated record data. Each one must make the record fail verification."""
    base = rec.model_dump()
    head = rec.commit
    parent_of_head = _parent(repo, head)
    out: dict[str, dict] = {}

    def mut(name, fn):
        d = json.loads(json.dumps(base))
        if fn(d) is not False:
            assert d != base, name
            out[name] = d

    def ev0(d):
        return d["evidence"][0]

    def dep_ev(d):
        return next((e for e in d["evidence"] if e["dependency"] is not None), None)

    def intro0(d):
        return d["introductions"][0]

    # --- evidence at the scanned commit (G2 / G3 / semantics)
    mut("ev.quote", lambda d: ev0(d)["ref"].update(quote="import nothing_here"))
    mut(
        "ev.line+1",
        lambda d: ev0(d)["ref"].update(
            line_start=ev0(d)["ref"]["line_start"] + 1, line_end=ev0(d)["ref"]["line_end"] + 1
        ),
    )
    mut("ev.line=0", lambda d: ev0(d)["ref"].update(line_start=0))
    mut("ev.path", lambda d: ev0(d)["ref"].update(path=ev0(d)["ref"]["path"] + ".bak"))
    mut("ev.path.abs", lambda d: ev0(d)["ref"].update(path="/" + ev0(d)["ref"]["path"]))
    mut("ev.commit.short", lambda d: ev0(d)["ref"].update(commit=head[:12]))
    mut("ev.commit.HEAD", lambda d: ev0(d)["ref"].update(commit="HEAD"))
    mut("ev.commit.upper", lambda d: ev0(d)["ref"].update(commit=head.upper()))
    mut("ev.commit.worktree", lambda d: ev0(d)["ref"].update(commit=WORKTREE))
    if parent_of_head:

        def to_parent(d):
            ev0(d)["ref"]["commit"] = parent_of_head
            if ev0(d)["dependency"] is not None:
                ev0(d)["dependency"]["commit"] = parent_of_head

        mut("ev.commit.parent", to_parent)
    mut("ev.technology", lambda d: ev0(d).update(technology="left-pad"))
    mut("ev.kind", lambda d: ev0(d).update(kind="code"))
    mut(
        "ev.kind.swap",
        lambda d: ev0(d).update(kind="import" if ev0(d)["kind"] != "import" else "dependency"),
    )
    mut("ev.none", lambda d: d.update(evidence=[]))
    mut("ev.dup-id", lambda d: d["evidence"].append(json.loads(json.dumps(ev0(d)))))

    def dep_field(field, value):
        def fn(d):
            e = dep_ev(d)
            if e is None:
                return False
            e["dependency"][field] = value

        return fn

    def dep_line_both(d):
        e = dep_ev(d)
        if e is None:
            return False
        e["dependency"]["line"] += 1
        e["ref"]["line_start"] += 1
        e["ref"]["line_end"] += 1

    def dep_swap_line(d):  # shift the cited line onto a real neighbouring declaration
        e = dep_ev(d)
        if e is None or e["ref"]["line_start"] < 2:
            return False
        lines = git(repo, "show", f"{head}:{e['ref']['path']}").splitlines()
        n = e["ref"]["line_start"] - 1
        e["ref"].update(line_start=n, line_end=n, quote=lines[n - 1])
        e["dependency"]["line"] = n

    mut("dep.package", dep_field("package", "left-pad"))
    mut("dep.version", dep_field("version_spec", "==9.9.9"))
    mut("dep.scope", dep_field("scope", "dev"))
    mut("dep.ecosystem", dep_field("ecosystem", "nuget"))
    mut("dep.path", dep_field("manifest_path", "other/requirements.txt"))
    mut("dep.line", dep_field("line", 999))
    mut("dep.line+ref", dep_line_both)
    mut("dep.neighbour", dep_swap_line)

    # --- what the record says
    mut("rec.technology", lambda d: d.update(technology=_other_tech(rec.technology, rec.category)))
    mut(
        "rec.technology+ev",
        lambda d: (
            d.update(technology=_other_tech(rec.technology, rec.category)),
            [e.update(technology=d["technology"]) for e in d["evidence"]],
        ),
    )
    mut("rec.category.orm", lambda d: d.update(category="orm"))
    mut(
        "rec.category.other",
        lambda d: d.update(category=next(c for c in DETECTED_CATEGORIES if c != rec.category)),
    )
    mut("rec.commit.short", lambda d: d.update(commit=head[:7]))
    if parent_of_head:
        mut("rec.commit.parent", lambda d: d.update(commit=parent_of_head))

    # --- introducing commits (G5)
    ic = rec.introductions[0].commit
    ic_parent = _parent(repo, ic)

    def set_intro(c):
        def fn(d):
            old = intro0(d)["commit"]
            intro0(d)["commit"] = c
            intro0(d)["ref"]["commit"] = c
            d["introducing_commits"] = [c if x == old else x for x in d["introducing_commits"]]

        return fn

    mut("intro.fake", set_intro("0" * 40))
    mut("intro.short", set_intro(ic[:7]))
    mut("intro.HEAD", set_intro("HEAD"))
    if ic_parent:
        mut("intro.parent", set_intro(ic_parent))
    if ic != head:
        mut("intro.later", set_intro(head))

    def unrelated(d):
        side = git(repo, "commit-tree", f"{head}^{{tree}}", "-m", "orphan").strip()
        set_intro(side)(d)

    mut("intro.not-ancestor", unrelated)
    mut("intro.list-only", lambda d: d.update(introducing_commits=["0" * 40]))
    mut("intro.list-empty", lambda d: d.update(introducing_commits=[]))
    mut("intro.list-dup", lambda d: d["introducing_commits"].append(d["introducing_commits"][0]))
    mut("intro.none", lambda d: d.update(introductions=[]))
    mut("intro.quote", lambda d: intro0(d)["ref"].update(quote="something else entirely"))
    mut(
        "intro.line+1",
        lambda d: intro0(d)["ref"].update(
            line_start=intro0(d)["ref"]["line_start"] + 1, line_end=intro0(d)["ref"]["line_end"] + 1
        ),
    )
    mut("intro.path", lambda d: intro0(d)["ref"].update(path="README.md"))
    mut(
        "intro.ref-commit",
        lambda d: (
            intro0(d)["ref"].update(commit=head)
            if head != ic
            else intro0(d)["ref"].update(commit="0" * 40)
        ),
    )
    mut("intro.evidence-id", lambda d: intro0(d).update(evidence_id="e99"))
    mut(
        "intro.parents",
        lambda d: intro0(d).update(parents=["f" * 40] if intro0(d)["parents"] == [] else []),
    )
    return out


def _caught(repo: Path, data: dict) -> bool:
    try:
        rec = UndocumentedDecision.model_validate(data)
    except ValidationError:
        return True  # the record cannot even be loaded as a finding
    out = verify_undocumented(repo, rec)
    return out.could_not_verify and out.status == "UNKNOWN" and bool(out.reasons)


def test_tamper_mutations_are_caught_100_percent(built, capsys):
    total = caught = 0
    missed: list[str] = []
    for name in NAMES:
        repo, _, _, scan = built[name]
        for rec in scan.findings:
            for mname, data in _mutations(repo, rec).items():
                total += 1
                if _caught(repo, data):
                    caught += 1
                else:
                    missed.append(f"{name}/{rec.id}/{mname}")
    with capsys.disabled():
        print(f"\nL-009 tamper: {caught}/{total} mutations caught")
    assert total >= 300
    assert missed == []


def test_unmutated_records_still_verify(built):
    for name in NAMES:
        repo, _, _, scan = built[name]
        for rec in scan.findings:
            assert verify_undocumented(repo, rec).grounding == "VERIFIED"


def test_documented_since_detection_is_caught(built):
    repo, _, _, scan = built["pyservice"]
    rec = next(r for r in scan.findings if r.technology == "redis")
    decisions = scan_adrs(repo).decisions
    assert verify_undocumented(repo, rec, decisions=decisions).grounding == "VERIFIED"
    adr = decisions[0].model_copy(update={"decision_text": "Sessions live in Redis."})
    out = verify_undocumented(repo, rec, decisions=[adr])
    assert out.could_not_verify and any("documented" in r for r in out.reasons)


# ------------------------------------------------------------------ fail closed


def test_wrong_introduction_is_could_not_verify_not_a_finding(tmp_path, monkeypatch):
    repo, steps, _ = build_fixture(tmp_path, "pyservice")
    real = detect_mod._introduction

    def wrong(hist, scan_commit, ev, key):
        intro, why = real(hist, scan_commit, ev, key)
        if intro is None or key[0] != "redis":
            return intro, why
        parent = hist.parents(intro.commit)[0]  # one commit too early
        ref = intro.ref.model_copy(update={"commit": parent})
        return intro.model_copy(update={"commit": parent, "ref": ref}), why

    monkeypatch.setattr(detect_mod, "_introduction", wrong)
    scan = detect_undocumented(repo)
    assert "cache/redis" not in {_label(r) for r in scan.findings}
    bad = next(r for r in scan.could_not_verify if r.technology == "redis")
    assert bad.status == "UNKNOWN" and bad.grounding == "MISMATCH" and bad.reasons
    assert bad.display_status == "Could not verify"
    assert "cloud-sdk/aws-sdk" in {_label(r) for r in scan.findings}


def test_missing_introduction_is_could_not_verify(tmp_path, monkeypatch):
    repo, _, _ = build_fixture(tmp_path, "nodeapp")
    monkeypatch.setattr(detect_mod, "_introduction", lambda *a: (None, "history unavailable"))
    scan = detect_undocumented(repo)
    assert scan.findings == []
    assert {_label(r) for r in scan.could_not_verify} == {"queue/kafka", "http-client/axios"}
    for r in scan.could_not_verify:
        assert any("no introducing commit" in x for x in r.reasons)
        assert any("history unavailable" in n for n in r.notes)


def test_model_invariants():
    prov = Provenance(path="a", line_start=1, line_end=1, commit="a" * 40, quote="x")
    with pytest.raises(ValidationError):
        UndocumentedDecision(
            id="x",
            technology="redis",
            category="cache",
            commit="a" * 40,
            grounding="MISMATCH",
            reasons=["r"],
        )  # still UNDOCUMENTED
    with pytest.raises(ValidationError):
        UndocumentedDecision(
            id="x",
            technology="redis",
            category="cache",
            commit="a" * 40,
            status="UNKNOWN",
            grounding="MISMATCH",
        )  # no reasons
    with pytest.raises(ValidationError):
        UndocumentedDecision(id="x", technology="redis", category="cache", commit="a" * 40)
    assert prov.commit == "a" * 40


def test_worktree_is_refused(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "aliases")
    with pytest.raises(ValueError):
        detect_undocumented(repo, WORKTREE)


# ------------------------------------------------------------------ history shapes


def _adr(text: str) -> str:
    return f"# 1. Decision\n\n## Status\n\nAccepted\n\n## Decision\n\n{text}\n"


def test_removed_and_readded_is_introduced_by_the_readd(tmp_path):
    repo = tmp_path / "readd"
    _init(repo)
    _commit(repo, {"docs/adr/0001-x.md": _adr("We use Flask."), "requirements.txt": "flask\n"}, "a")
    _commit(repo, {"requirements.txt": "flask\npika==1.3.2\n", "w.py": "import pika\n"}, "b")
    _commit(repo, {"requirements.txt": "flask\n", "w.py": None}, "c")
    d = _commit(repo, {"requirements.txt": "flask\npika==1.3.2\n"}, "d")
    scan = detect_undocumented(repo)
    rec = next(r for r in scan.findings if r.technology == "rabbitmq")
    assert rec.introducing_commits == [d]


def test_merge_introduction_is_the_branch_commit(tmp_path):
    repo = tmp_path / "merge"
    _init(repo)
    _commit(repo, {"docs/adr/0001-x.md": _adr("We use Flask."), "requirements.txt": "flask\n"}, "a")
    git(repo, "checkout", "-q", "-b", "feature")
    feat = _commit(repo, {"requirements.txt": "flask\nkafka-python==2.0.2\n"}, "kafka")
    git(repo, "checkout", "-q", "main")
    _commit(repo, {"README.md": "hello\n"}, "readme")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")
    scan = detect_undocumented(repo)
    rec = next(r for r in scan.findings if r.technology == "kafka")
    assert rec.introducing_commits == [feat]
    assert rec.grounding == "VERIFIED"


def test_older_commit_can_be_scanned(tmp_path):
    repo, steps, _ = build_fixture(tmp_path, "pyservice")
    scan = detect_undocumented(repo, steps["02-add-redis"])
    assert {_label(r) for r in scan.findings} == {"cache/redis"}
    assert scan.findings[0].commit == steps["02-add-redis"]


# ------------------------------------------------------------------ documentation matching


def test_adr_mentions_is_case_insensitive_and_word_bounded(tmp_path):
    repo = tmp_path / "m"
    _init(repo)
    _commit(
        repo, {"docs/adr/0001-a.md": _adr("We redistribute load; see REDIS-backed cache.")}, "a"
    )
    _commit(repo, {"docs/adr/0002-b.md": _adr("We redistribute events.")}, "b")
    decisions = scan_adrs(repo).decisions
    assert [d.id for d in decisions if adr_mentions(["redis"], [d])] == ["ADR-0001"]
    assert adr_mentions(["redis"], decisions[1:]) == []
    assert adr_mentions(["amazon web services"], decisions) == []
    terms = technology_terms("aws-sdk", "cloud-sdk", ["boto3"])
    assert {"aws-sdk", "aws", "boto3"} <= set(terms)
    assert (
        technology_terms("cloudflare", "iac-provider", ["cloudflare/cloudflare"])[0] == "cloudflare"
    )


def test_a_claim_documents_a_technology(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "pyservice")
    decisions = scan_adrs(repo).decisions
    base = detect_undocumented(repo, decisions=decisions)
    assert "cache/redis" in {_label(r) for r in base.findings}
    claim = Claim(
        id="ADR-0001.c9",
        kind="forbid",
        subject="cache",
        rule={"forbid": ["memcached", "valkey"]},
        source=decisions[0].source,
        decision_id="ADR-0001",
    )
    scan = detect_undocumented(repo, decisions=decisions, claims=[claim])
    assert "cache/redis" not in {_label(r) for r in scan.records}
    assert scan.documented["cache/redis"] == ["ADR-0001"]


def test_claims_from_the_rule_library_can_be_passed(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "pyservice")
    adrs = scan_adrs(repo)
    claims = [c for cs in structure_scan(adrs.decisions, repo, mode="offline") for c in cs.claims]
    assert claims
    scan = detect_undocumented(repo, decisions=adrs.decisions, claims=claims)
    assert {_label(r) for r in scan.findings} == {"cache/redis", "cloud-sdk/aws-sdk"}


def test_ledger_rows(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "goinfra")
    ledger = Ledger(tmp_path / "out", run_id="l009")
    scan = detect_undocumented(repo, ledger=ledger)
    summary = ledger.write_summary()
    assert summary["total"] == len(scan.checks) > 0
    assert summary["pass_rate"] == 1.0
    assert {"G2", "G3", "G5"} <= set(summary["by_check"])


# ------------------------------------------------------------------ G5 verifier


def test_verify_commits_exist(tmp_path):
    repo, steps, _ = build_fixture(tmp_path, "aliases")
    first, second = steps["01-initial"], steps["02-more"]
    ok = verify_commits_exist(repo, [first, second], ancestor_of=second)
    assert [r.status for r in ok] == ["VERIFIED", "VERIFIED"]
    assert all(r.check_id == "G5" for r in ok)
    bad = [
        first[:7],
        "HEAD",
        "main",
        first.upper(),
        "0" * 40,
        WORKTREE,
        "",
        "x" * 40,
    ]
    for c in bad:
        (r,) = verify_commits_exist(repo, [c])
        assert r.status == "MISMATCH", c
    (r,) = verify_commits_exist(repo, [second], ancestor_of=first)
    assert r.status == "MISMATCH" and "not an ancestor" in r.reason
    (r,) = verify_commits_exist(repo, [])
    assert r.status == "MISMATCH"
