"""L-010: ADR drafter (MADR) for undocumented decisions, and its G5 gate.

Every seeded L-009 fixture is built, scanned, and each finding drafted. The
drafts must verify, parse back through the repository's own ADR parser, and
every tamper mutation of a draft must be caught. Offline: sockets are disabled.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

import pytest

from conftest import git
from driftwarden.discover.adr import parse_adr, scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.llm.base import BaseProvider, LLMResponse, TransportError, Usage
from driftwarden.llm.offline import OfflineProvider
from driftwarden.models import UndocumentedDecision
from driftwarden.undocumented import (
    DraftADR,
    detect_undocumented,
    draft_adr,
    verify_draft,
    verify_undocumented,
)
from driftwarden.undocumented.draft import (
    draft_filename,
    draft_title,
    next_adr_number,
    polish_problems,
    sanitise_subject,
    technology_name,
)
from test_l009_undocumented import NAMES, build_fixture

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


@pytest.fixture(scope="module")
def drafted(tmp_path_factory):
    """name -> (repo, steps, [(record, draft)]) for every fixture."""
    base = tmp_path_factory.mktemp("l010")
    out = {}
    for name in NAMES:
        repo, steps, _ = build_fixture(base, name)
        scan = detect_undocumented(repo)
        assert scan.findings and not scan.could_not_verify
        out[name] = (repo, steps, [(r, draft_adr(repo, r)) for r in scan.findings])
    return out


def _all(drafted):
    for name in NAMES:
        repo, steps, pairs = drafted[name]
        for rec, d in pairs:
            yield name, repo, steps, rec, d


# ------------------------------------------------------------------ acceptance


def test_every_seeded_finding_drafts_and_verifies(drafted):
    n = 0
    for _, repo, _, rec, d in _all(drafted):
        n += 1
        assert d.status == "DRAFT" and d.grounding == "VERIFIED", (rec.id, d.reasons)
        assert d.display_status == "Draft" and d.origin == "template"
        assert d.markdown and d.written_path is None
        assert all(c.status == "VERIFIED" for c in d.checks), rec.id
        assert {"G2", "G5"} <= {c.check_id for c in d.checks}
        # Cites only the record's commits, every one of them pinned and existing.
        allowed = {*rec.introducing_commits, rec.commit}
        assert set(d.cited_commits) <= allowed
        assert set(rec.introducing_commits) <= set(d.cited_commits)
        assert all(SHA40.fullmatch(c) for c in d.cited_commits)
        # Every hex run in the text abbreviates one of those commits.
        for tok in re.findall(r"(?<![0-9a-z])[0-9a-f]{7,40}(?![0-9a-z])", d.markdown):
            if any(ch.isdigit() for ch in tok):
                assert any(c.startswith(tok) for c in allowed), (rec.id, tok)
        # Re-running the gate on the returned draft is stable.
        again = verify_draft(repo, d)
        assert again.grounding == "VERIFIED", again.reasons
    assert n >= 10


def test_draft_content_is_madr_and_invents_nothing(drafted):
    repo, steps, pairs = drafted["pyservice"]
    rec, d = next((r, d) for r, d in pairs if r.technology == "redis")
    md = d.markdown
    assert d.title == "Use Redis for cache"
    assert md.startswith("---\nstatus: proposed (draft)\n")
    assert "\n# Use Redis for cache\n" in md
    sections = ("Context and Problem Statement", "Considered Options", "Decision Outcome")
    for section in (*sections, "More Information"):
        assert f"\n## {section}\n" in md
    assert md.count("TODO: confirm") >= 3
    assert f"- Commit `{steps['02-add-redis']}`" in md
    assert "02-add-redis" in md  # the subject line
    assert "Test" not in md and "example.invalid" not in md  # no author identity
    assert f"`{steps['02-add-redis'][:12]}`" in md
    assert "redis==5.0.0" in md and "redis==5.0.1" in md  # introduced, then bumped
    assert "because TODO: confirm" in md


def test_round_trip_through_the_adr_parser(drafted):
    for _, _, _, rec, d in _all(drafted):
        dec = parse_adr(d.markdown, d.path, rec.commit)
        assert dec.title == d.title == draft_title(rec.technology, rec.category)
        assert dec.status == "proposed"
        assert dec.format == "madr"
        assert dec.chosen_option == technology_name(rec.technology)
        assert dec.context and "No ADR in this repository" in dec.context


def test_written_draft_is_discovered_and_documents_the_choice(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "pyservice")
    rec = next(r for r in detect_undocumented(repo).findings if r.technology == "redis")
    before = git(repo, "status", "--porcelain")
    d = draft_adr(repo, rec)
    assert d.written_path is None and git(repo, "status", "--porcelain") == before
    assert not (repo / d.path).exists()
    w = draft_adr(repo, rec, write=True)
    assert w.written_path == w.path == d.path
    assert (repo / w.path).read_text(encoding="utf-8") == w.markdown
    found = {x.source.path: x for x in scan_adrs(repo).decisions}
    dec = found[w.path]
    assert dec.title == "Use Redis for cache" and dec.status == "proposed"
    assert dec.id == f"ADR-{w.number:04d}"
    git(repo, "add", "--", w.path)
    git(repo, "commit", "-q", "-m", "adr")
    after = detect_undocumented(repo)
    assert "cache/redis" in after.documented
    assert all(r.technology != "redis" for r in after.findings)


def test_write_never_overwrites(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "nodeapp")
    rec = detect_undocumented(repo).findings[0]
    target = repo / "docs/adr" / draft_filename(1, rec.technology, rec.category)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("mine\n", encoding="utf-8")
    d = draft_adr(repo, rec, existing_adrs=[], write=True)
    assert d.number == 1 and d.written_path is None
    assert any("not overwritten" in n for n in d.notes)
    assert target.read_text(encoding="utf-8") == "mine\n"


def test_date_prefixed_adr_names_are_not_numbers():
    assert next_adr_number(["docs/adr/2026-01-11-a.md", "docs/adr/20260111-b.md"]) == 1
    assert next_adr_number(["docs/adr/2026-01-11-a.md", "docs/adr/0003-c.md"]) == 4


def test_subjects_are_sanitised():
    assert sanitise_subject("revert 1a2b3c4d5e6f") == "revert [ref removed]"
    assert sanitise_subject("fix deadbeef") == "fix [ref removed]"
    assert sanitise_subject("see src/app.py:12 and Makefile:3-4") == (
        "see [ref removed] and [ref removed]"
    )
    assert sanitise_subject("a\u2028b\x85c\u202ed") == "a b c d"
    assert sanitise_subject("plain 2026-01-01 at 10:30") == "plain 2026-01-01 at 10:30"


def test_polish_checks_are_token_based(drafted):
    _, _, pairs = drafted["pyservice"]
    rec, d = next((r, d) for r, d in pairs if r.technology == "redis")
    ctx = d.markdown.split("## Context and Problem Statement\n\n", 1)[1].split("\n\n", 1)[0]
    assert polish_problems(ctx, ctx, rec) == []
    # digits that only occur inside a SHA are not allowed as numbers
    sha_digits = [r for r in re.findall(r"[0-9]+", rec.commit[:12]) if r not in ctx.replace(
        rec.commit[:12], "")]  # fmt: skip
    for run in sha_digits:
        assert polish_problems(ctx + f" It has {run} users.", ctx, rec)
    for bad in (
        " See deadbeef.",
        " See Makefile:1.",
        " status: accepted",
        " <b>x</b>",
        " See http://x.y.",
        " | a |",
        " 1. because",
        " Used in \u0665\u0660 places.",
    ):
        assert polish_problems(ctx + bad, ctx, rec), bad  # fmt: skip


def test_numbering_follows_discovered_adrs(drafted):
    repo, _, pairs = drafted["aliases"]
    nums = [d.number for _, d in pairs]
    assert nums == [4] * len(pairs)  # 0001..0003 exist
    assert all(d.path.startswith("docs/adr/0004-use-") for _, d in pairs)
    assert next_adr_number(["docs/adr/0009-x.md", "docs/adr/adr-0012-y.md", "README.md"]) == 13
    assert next_adr_number([]) == 1
    d = draft_adr(repo, pairs[0][0], existing_adrs=["adrs/0041-a.md"])
    assert d.path == f"adrs/0042-use-{pairs[0][0].technology}-for-web-framework.md"


def test_drafting_is_deterministic(drafted):
    repo, _, pairs = drafted["goinfra"]
    for rec, d in pairs:
        assert draft_adr(repo, rec).markdown == d.markdown


# ------------------------------------------------------------------ could not verify


def _broken(repo: Path, rec: UndocumentedDecision) -> UndocumentedDecision:
    data = rec.model_dump()
    data["evidence"][0]["ref"]["quote"] = "not in the file"
    return verify_undocumented(repo, UndocumentedDecision.model_validate(data))


def test_could_not_verify_record_yields_no_draft(drafted):
    repo, _, pairs = drafted["javacompose"]
    rec = _broken(repo, pairs[0][0])
    assert rec.could_not_verify
    d = draft_adr(repo, rec, write=True)
    assert d.status == "UNKNOWN" and d.grounding == "MISMATCH"
    assert d.display_status == "Could not verify"
    assert d.markdown is None and d.path is None and d.written_path is None
    assert d.reasons and all(r.startswith("record is Could not verify") for r in d.reasons)


def test_record_claiming_verified_is_rechecked(drafted):
    repo, _, pairs = drafted["javacompose"]
    rec = pairs[0][0]
    data = rec.model_dump()
    data["evidence"][0]["ref"]["line_start"] += 1
    data["evidence"][0]["ref"]["line_end"] += 1
    valid = UndocumentedDecision.model_validate(data)
    forged = UndocumentedDecision.model_construct(**valid.__dict__)
    assert not forged.could_not_verify
    d = draft_adr(repo, forged)
    assert d.status == "UNKNOWN" and d.markdown is None
    assert any(r.startswith("record:") for r in d.reasons)


def test_draft_model_invariants(drafted):
    _, _, pairs = drafted["nodeapp"]
    rec = pairs[0][0]
    with pytest.raises(ValueError):
        DraftADR(record_id=rec.id, technology="x", category="y", record=rec)  # DRAFT, no text
    with pytest.raises(ValueError):
        DraftADR(
            record_id=rec.id,
            technology="x",
            category="y",
            record=rec,
            markdown="x",
            grounding="MISMATCH",
            reasons=["r"],
        )


# ------------------------------------------------------------------ tamper mutations


def _flip(sha: str, i: int = 5) -> str:
    return sha[:i] + ("0" if sha[i] != "0" else "1") + sha[i + 1 :]


def _first_quote_line(md: str) -> tuple[int, str]:
    lines = md.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("```text"):
            return i + 1, lines[i + 1]
    raise AssertionError("no quote block")


def _mutations(repo: Path, rec: UndocumentedDecision, d: DraftADR) -> dict[str, str]:
    """name -> tampered markdown. Every one must fail the gate."""
    md = d.markdown
    intro = rec.introducing_commits[0]
    all_commits = git(repo, "rev-list", "HEAD").split()
    foreign = [c for c in all_commits if c not in {*rec.introducing_commits, rec.commit}]
    out: dict[str, str] = {}

    def put(name: str, new: str) -> None:
        if new != md:  # not applicable (e.g. the scanned commit is the introducing one)
            out[name] = new

    # Swap / alter SHAs.
    put("swap-intro-sha-for-scanned", md.replace(f"- Commit `{intro}`", f"- Commit `{rec.commit}`"))
    put("alter-intro-sha-everywhere", md.replace(intro, _flip(intro)))
    put("alter-short-sha-in-prose", md.replace(f"`{intro[:12]}`", f"`{_flip(intro[:12], 3)}`", 1))
    scanned, flipped = rec.commit, _flip(rec.commit)
    put("alter-scanned-sha-in-citations", md.replace(f"at `{scanned}`", f"at `{flipped}`"))
    fm_old, fm_new = f"driftwarden-commit: {scanned}", f"driftwarden-commit: {flipped}"
    put("alter-front-matter-commit", md.replace(fm_old, fm_new))
    if foreign:
        f = foreign[0]
        put("swap-intro-sha-for-foreign", md.replace(intro, f))
        put("add-foreign-short-sha", md.replace("No ADR in", f"See `{f[:10]}`. No ADR in"))
        put("add-foreign-full-sha", md + f"\nAlso see {f}.\n")
        h3 = "### Where it was introduced"
        put("add-foreign-commit-line", md.replace(h3, f"- Commit `{f}`, 2026-01-01: x\n\n{h3}"))
    put("add-fake-sha", md.replace("No ADR in this", "See commit 1234abcd. No ADR in this"))
    # Quotes.
    i, line = _first_quote_line(md)
    lines = md.split("\n")
    lines[i] = line + " # changed"
    put("alter-quote", "\n".join(lines))
    lines = md.split("\n")
    lines[i] = line[:-1] + ("X" if line[-1] != "X" else "Y")
    put("alter-quote-char", "\n".join(lines))
    # Line ranges.
    ev = rec.evidence[0].ref
    old = f"`{ev.path}` lines {ev.line_start}-{ev.line_end} at `{rec.commit}`"
    a, b = ev.line_start, ev.line_end
    shifted = f"`{ev.path}` lines {a + 1}-{b + 1} at `{rec.commit}`"
    widened = f"`{ev.path}` lines {a}-{b + 1} at `{rec.commit}`"
    put("shift-line-range", md.replace(old, shifted))
    put("widen-line-range", md.replace(old, widened))
    put("prose-foreign-ref", md.replace("No ADR in", f"See {ev.path}:{b + 7}. No ADR in"))
    # Commit facts.
    info_line = next(x for x in md.split("\n") if x.startswith(f"- Commit `{intro}`"))
    put("alter-commit-date", md.replace(info_line, re.sub(r", \d{4}-", ", 1999-", info_line)))
    put("alter-commit-subject", md.replace(info_line, info_line + " (hotfix)"))
    # Dropped / duplicated citations.
    put("drop-commit-line", md.replace(info_line + "\n", ""))
    cite = next(x for x in md.split("\n") if x.startswith("- [e1]") and rec.commit in x)
    put("alter-citation-detail", md.replace(cite, cite[:-1] + " (main):"))
    h2 = "## Considered Options"
    put("orphan-code-block", md.replace(h2, f"```\nfoo\n```\n\n{h2}"))
    # Dates and counts in the prose.
    date = re.search(r"^date: (\S+)$", md, re.M).group(1)
    put("alter-front-matter-date", md.replace(f"date: {date}", "date: 2001-02-03"))
    put(
        "swap-front-matter-date-parts",
        md.replace(f"date: {date}", f"date: {date[:5]}{date[8:]}-{date[5:7]}"),
    )
    put("alter-prose-date", md.replace(f"({date})", "(2001-02-03)", 1))
    put("alter-prose-count", re.sub(r": \d+ production", ": 97 production", md, count=1))
    # Title / status round trip.
    put("alter-title", md.replace(f"# {d.title}\n", "# Use Something Else\n"))
    put("alter-status", md.replace("status: proposed (draft)", "status: accepted"))
    return out


def test_tamper_mutations_are_caught(drafted, capsys):
    total = caught = 0
    missed: list[str] = []
    for name, repo, _, rec, d in _all(drafted):
        cases = {k: {"markdown": v} for k, v in _mutations(repo, rec, d).items()}
        cases["alter-title-field"] = {"title": "Use Something Else"}
        cases["alter-record-id-field"] = {"record_id": "UD-other"}
        for mname, update in cases.items():
            total += 1
            res = verify_draft(repo, d.model_copy(update=update))
            if res.could_not_verify and res.status == "UNKNOWN" and res.reasons:
                caught += 1
            else:
                missed.append(f"{name}/{rec.id}/{mname}")
    assert total >= 200
    assert missed == []
    with capsys.disabled():
        print(f"\nL-010 tamper mutations caught: {caught}/{total}")


def test_tampered_record_inside_a_draft_is_caught(drafted):
    repo, steps, pairs = drafted["pyservice"]
    rec, d = next((r, d) for r, d in pairs if r.technology == "redis")
    # Add a foreign introducing commit to the record and the text consistently.
    foreign = steps["01-initial"]
    data = rec.model_dump()
    data["introducing_commits"] = [foreign, *data["introducing_commits"]]
    bad = UndocumentedDecision.model_validate(data)
    md = d.markdown.replace("- Commit ", f"- Commit `{foreign}`, x: y\n- Commit ", 1)
    res = verify_draft(repo, d.model_copy(update={"record": bad, "markdown": md}))
    assert res.could_not_verify
    assert any(r.startswith("record:") for r in res.reasons)


# ------------------------------------------------------------------ LLM path


class FakeProvider(BaseProvider):
    name = "fake"
    offline = False

    def __init__(self, reply):
        super().__init__("fake-model")
        self.reply = reply
        self.calls = 0

    def _send(self, request):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        text = self.reply(request) if callable(self.reply) else self.reply
        return LLMResponse(text=text, model="fake-model", provider="fake", usage=Usage())


def _json(s: str) -> str:
    import json

    return json.dumps({"context": s})


def _template_context(md: str) -> str:
    body = md.split("## Context and Problem Statement\n\n", 1)[1]
    return body.split("\n\n", 1)[0]


@pytest.fixture
def redis(drafted):
    repo, steps, pairs = drafted["pyservice"]
    rec, d = next((r, d) for r, d in pairs if r.technology == "redis")
    return repo, steps, rec, d


def test_llm_polish_is_used_when_it_passes_the_gate(redis):
    repo, _, rec, d = redis
    ctx = _template_context(d.markdown)
    polished = "In short: " + ctx.replace("No ADR in this repository", "No ADR here")
    p = FakeProvider(_json(polished))
    out = draft_adr(repo, rec, provider=p)
    assert p.calls == 1
    assert out.origin == "llm" and out.grounding == "VERIFIED", out.reasons
    assert "In short: " in out.markdown and "No ADR here records" in out.markdown
    assert parse_adr(out.markdown, out.path, rec.commit).title == "Use Redis for cache"


@pytest.mark.parametrize(
    "mutate,why",
    [
        (lambda c, s: c + " See commit `" + s["01-initial"][:12] + "`.", "gate"),
        (lambda c, s: c.replace("No ADR", "Chosen in 2019 for speed. No ADR"), "numbers"),
        (lambda c, s: "## Heading\n" + c, "structure"),
        (lambda c, s: c + "\n```\ncode\n```", "structure"),
        (lambda c, s: c + " See requirements.txt:5-5 and app.py:9.", "gate"),
    ],
)
def test_llm_text_is_never_trusted_for_facts(redis, mutate, why):
    repo, steps, rec, d = redis
    p = FakeProvider(_json(mutate(_template_context(d.markdown), steps)))
    out = draft_adr(repo, rec, provider=p)
    assert out.origin == "template" and out.grounding == "VERIFIED"
    assert out.markdown == d.markdown  # the template draft, unchanged
    assert any("template text kept" in n for n in out.notes), out.notes


def test_llm_errors_fall_back_to_template(redis):
    repo, _, rec, d = redis
    p = FakeProvider(TransportError("boom", status=400))
    out = draft_adr(repo, rec, provider=p)
    assert out.origin == "template" and out.markdown == d.markdown
    assert any("LLM polish failed" in n for n in out.notes)


def test_offline_provider_is_never_called(redis):
    repo, _, rec, d = redis
    calls = []
    p = OfflineProvider(responder=lambda req: calls.append(req) or _json("x"))
    out = draft_adr(repo, rec, provider=p)
    assert calls == [] and out.origin == "template" and out.markdown == d.markdown


# ------------------------------------------------------------------ grounding numbers


def test_grounding_numbers(drafted, tmp_path, capsys):
    ledger = Ledger(tmp_path)
    by: dict[str, list[int]] = {}
    for _, repo, _, _, d in _all(drafted):
        res = verify_draft(repo, d, ledger=ledger)
        for c in res.checks:
            ok, tot = by.setdefault(c.check_id, [0, 0])
            by[c.check_id] = [ok + (c.status == "VERIFIED"), tot + 1]
    assert {"G2", "G3", "G5"} <= set(by)
    assert all(ok == tot for ok, tot in by.values())
    with capsys.disabled():
        shown = ", ".join(f"{k} {ok}/{t}" for k, (ok, t) in sorted(by.items()))
        print(f"\nL-010 draft grounding: {shown}")


# ------------------------------------------------------------------ Codex round 1 (PR #22)


def _shadowed_redis_repo(tmp_path: Path) -> Path:
    """`import redis` resolves to the local redis.py unless that file is excluded."""
    repo = tmp_path / "shadow"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("x\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-q", "-m", "init")
    (repo / "app.py").write_text("import redis\n", encoding="utf-8")
    (repo / "redis.py").write_text("X = 1\n", encoding="utf-8")
    git(repo, "add", "app.py", "redis.py")
    git(repo, "commit", "-q", "-m", "use redis")
    return repo


def test_config_reaches_every_gate_call(tmp_path):
    from driftwarden.config import Config

    repo = _shadowed_redis_repo(tmp_path)
    cfg = Config(exclude=["redis.py"])
    (rec,) = detect_undocumented(repo, config=cfg).findings
    assert detect_undocumented(repo).findings == []  # without the exclusion: a local module
    d = draft_adr(repo, rec, config=cfg, write=True)
    assert d.status == "DRAFT" and d.grounding == "VERIFIED", d.reasons
    assert d.written_path is not None
    assert verify_draft(repo, d, config=cfg).grounding == "VERIFIED"
    # The same draft checked with another configuration does not verify.
    assert verify_draft(repo, d).could_not_verify


def _covering_decision(rec: UndocumentedDecision):
    text = "# Use Redis\n\n## Decision\n\nWe use redis for caching.\n"
    return parse_adr(text, "docs/adr/0042-redis.md", rec.commit)


def test_decision_generator_is_read_once_and_coverage_cannot_be_bypassed(tmp_path):
    repo, _, _ = build_fixture(tmp_path, "pyservice")
    rec = next(r for r in detect_undocumented(repo).findings if r.technology == "redis")
    good = draft_adr(repo, rec)
    assert good.status == "DRAFT"
    dec = _covering_decision(rec)
    before = git(repo, "status", "--porcelain")
    replies = (
        _json(_template_context(good.markdown)),  # LLM draft is built, then fails coverage
        _json("## not a paragraph"),  # LLM text rejected, straight to the template
    )
    for reply in replies:
        p = FakeProvider(reply)
        d = draft_adr(repo, rec, provider=p, decisions=iter([dec]), write=True)
        assert d.status == "UNKNOWN" and d.markdown is None and d.written_path is None, reply
        assert any("documented" in r for r in d.reasons), d.reasons
    d = draft_adr(repo, rec, decisions=iter([dec]), claims=iter(()), write=True)
    assert d.could_not_verify and d.written_path is None
    assert git(repo, "status", "--porcelain") == before
    res = verify_draft(repo, good, decisions=iter([dec]))
    assert res.could_not_verify and any("documented" in r for r in res.reasons)
    assert verify_draft(repo, good, decisions=iter([])).grounding == "VERIFIED"


# ------------------------------------------------------------------ Codex round 2 (PR #22)


def _mkrepo(tmp_path: Path, name: str, steps: list[tuple[dict[str, str], str]]) -> list[str]:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    shas = []
    for files, msg in steps:
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
            git(repo, "add", "--", rel)
        git(repo, "commit", "-q", "--allow-empty", "-m", msg)
        shas.append(git(repo, "rev-parse", "HEAD").strip())
    return shas


def _unfenced(md: str) -> list[str]:
    out, fence = [], None
    for line in md.split("\n"):
        m = re.match(r"^(`{3,})", line)
        if fence is None and m:
            fence = m.group(1)
            continue
        if fence is not None:
            if line == fence:
                fence = None
            continue
        out.append(line)
    return out


EXPECTED_HEADINGS = [
    "## Context and Problem Statement",
    "## Considered Options",
    "## Decision Outcome",
    "### Consequences",
    "## More Information",
    "### Introducing commits",
    "### Where it was introduced",
]


def test_truncated_evidence_keeps_the_oldest_introduction(tmp_path):
    a, b = _mkrepo(
        tmp_path,
        "trunc",
        [
            ({"z.py": "import redis\n"}, "A: redis in z"),
            ({f"a{i}.py": "import redis\n" for i in range(10)}, "B: redis everywhere"),
        ],
    )
    repo = tmp_path / "trunc"
    (rec,) = detect_undocumented(repo).findings
    assert len(rec.evidence) == 10 and any("further occurrence" in n for n in rec.notes)
    assert rec.introducing_commits == [a, b]
    assert "z.py" in {e.ref.path for e in rec.evidence}
    d = draft_adr(repo, rec)
    assert d.grounding == "VERIFIED", d.reasons
    assert f"`{a[:12]}`" in d.markdown and f"- Commit `{a}`" in d.markdown
    assert "The cited occurrences were introduced by 2 commits" in d.markdown
    assert "Further occurrences exist in the code and are not cited." in d.markdown
    # The caveat is pinned: dropping it fails the gate.
    bad = d.markdown.replace(" Further occurrences exist in the code and are not cited.", "")
    assert verify_draft(repo, d.model_copy(update={"markdown": bad})).could_not_verify


INJECT = "^5.0.0\n\n## Security Policy\n- [click](http://evil.example) <script>x</script>\n# H"


def test_manifest_version_injection_cannot_add_structure(tmp_path):
    import json

    pkg = {"name": "w", "version": "1.0.0", "dependencies": {"redis": INJECT}}
    _mkrepo(tmp_path, "inj", [({"package.json": json.dumps(pkg, indent=2) + "\n"}, "web")])
    repo = tmp_path / "inj"
    recs = [r for r in detect_undocumented(repo).findings if r.technology == "redis"]
    assert recs, "the injected manifest must still be detected"
    d = draft_adr(repo, recs[0])
    assert d.grounding == "VERIFIED", d.reasons
    lines = _unfenced(d.markdown)
    assert [x for x in lines if x.startswith("#")][1:-1] == EXPECTED_HEADINGS
    assert not any(x.startswith(("## Security", "<", "# H")) for x in lines)
    assert "\\n\\n## Security Policy\\n" in d.markdown  # visible, escaped, one line
    raw = d.markdown.replace("\\n\\n## Security Policy\\n", "\n\n## Security Policy\n", 1)
    assert verify_draft(repo, d.model_copy(update={"markdown": raw})).could_not_verify


@pytest.mark.parametrize(
    "field,value",
    [
        ("version_spec", INJECT),
        ("package", "redis\n## Pwned\n- item"),
        ("scope", "dev\n<img src=x>"),
        ("ecosystem", "npm\n# Heading"),
        ("path", "src/app.py\n## Injected\nhttp://evil.example"),
        ("kind", "import\n## Kind"),
    ],
)
def test_untrusted_fields_render_as_single_line_spans(drafted, field, value):
    from driftwarden.undocumented.draft import _commit_info, _evidence_detail, render_markdown

    _, _, pairs = drafted["pyservice"]
    rec = next(r for r, _ in pairs if r.technology == "redis")
    ev = next(e for e in rec.evidence if e.dependency is not None)
    if field == "path":
        ev = ev.model_copy(update={"ref": ev.ref.model_copy(update={"path": value})})
    elif field == "kind":
        ev = ev.model_copy(update={"kind": value})
    else:
        ev = ev.model_copy(update={"dependency": ev.dependency.model_copy(update={field: value})})
    assert "\n" not in _evidence_detail(ev)
    forged = rec.model_copy(update={"evidence": [ev, *rec.evidence[1:]]})
    infos = {c: _commit_info(drafted["pyservice"][0], c) for c in rec.introducing_commits}
    md = render_markdown(forged, infos)
    lines = _unfenced(md)
    assert [x for x in lines if x.startswith("#")][1:-1] == EXPECTED_HEADINGS
    assert not any(x.startswith(("<", "http", "- item")) for x in lines)
    # and a forged record never verifies as a draft
    d = next(d for r, d in pairs if r.technology == "redis")
    res = verify_draft(
        drafted["pyservice"][0], d.model_copy(update={"record": forged, "markdown": md})
    )
    assert res.could_not_verify


def test_failed_write_leaves_nothing_and_retry_works(tmp_path, monkeypatch):
    from driftwarden.undocumented import draft as draft_mod

    _mkrepo(
        tmp_path, "w", [({"README.md": "x\n"}, "init"), ({"requirements.txt": "redis==5\n"}, "r")]
    )
    repo = tmp_path / "w"
    (rec,) = detect_undocumented(repo).findings

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(draft_mod.os, "fsync", boom)
    d = draft_adr(repo, rec, write=True)
    assert d.grounding == "VERIFIED" and d.written_path is None
    assert any("not written" in n for n in d.notes), d.notes
    adr_dir = repo / "docs/adr"
    assert not adr_dir.exists() or list(adr_dir.iterdir()) == []
    monkeypatch.undo()
    d2 = draft_adr(repo, rec, write=True)
    assert d2.written_path == d.path
    assert (repo / d2.written_path).read_text(encoding="utf-8") == d2.markdown
    assert [p.name for p in adr_dir.iterdir()] == [Path(d2.written_path).name]


def test_partial_draft_is_not_treated_as_already_drafted(tmp_path):
    _mkrepo(
        tmp_path, "p", [({"README.md": "x\n"}, "init"), ({"requirements.txt": "redis==5\n"}, "r")]
    )
    repo = tmp_path / "p"
    (rec,) = detect_undocumented(repo).findings
    good = draft_adr(repo, rec)
    stale = repo / "docs/adr" / Path(good.path).name
    stale.parent.mkdir(parents=True)
    stale.write_text(good.markdown[: len(good.markdown) // 2], encoding="utf-8")  # truncated
    d = draft_adr(repo, rec, write=True)
    assert d.written_path is not None and d.written_path != f"docs/adr/{stale.name}"
    assert any("does not verify" in n for n in d.notes), d.notes
    assert (repo / d.written_path).read_text(encoding="utf-8") == d.markdown
    again = draft_adr(repo, rec, write=True)  # now idempotent on the verified file
    assert again.written_path == d.written_path
    assert sorted(p.name for p in stale.parent.iterdir()) == sorted(
        [stale.name, Path(d.written_path).name]
    )
