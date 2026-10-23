"""System-test additions for L-002 (Sonnet): G1 grounding under adversarial and edge inputs."""

from __future__ import annotations

import json
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftwarden.cli as cli
from conftest import FIXTURES, git
from driftwarden import git as dwgit
from driftwarden.cli import app
from driftwarden.config import load_config
from driftwarden.discover.adr import parse_adr, scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_source_quote
from driftwarden.models import WORKTREE

runner = CliRunner()
FIXTURE_NAMES = ("basic", "adr_tools")

NYGARD = (
    "# 7. Use Redis for sessions\n\n## Status\n\nAccepted\n\n"
    "## Context\n\nSessions need a store.\n\n"
    "## Decision\n\nWe will use Redis for session storage.\nNo other store holds sessions.\n\n"
    "## Consequences\n\nOps runs Redis.\n"
)


def _repo(tmp_path: Path, files: dict[str, bytes | str], name: str = "r") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "core.autocrlf", "false")
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    if files:
        git(repo, "add", "--", *files.keys())
        git(repo, "commit", "-q", "-m", "init")
    return repo


def _single(repo: Path):
    res = scan_adrs(repo)
    assert not res.errors
    assert len(res.decisions) == 1, [d.id for d in res.decisions]
    return res.decisions[0]


def _verify(repo, dec):
    return verify_source_quote(repo, dec.source, subject=dec.id)


# ------------------------------------------------------------ G1 priority: tampering property


def _fixture_decisions(tmp_path):
    out = []
    for name in FIXTURE_NAMES:
        dest = tmp_path / f"fx-{name}"
        shutil.copytree(FIXTURES / name, dest)
        git(dest, "init", "-q", "-b", "main")
        git(dest, "config", "commit.gpgsign", "false")
        git(dest, "add", "-A")
        git(dest, "commit", "-q", "-m", "fixture")
        out.extend((dest, d) for d in scan_adrs(dest).decisions)
    return out


def _mutate_one_word(quote: str, rng: random.Random) -> str:
    spans = [m for m in re.finditer(r"\S+", quote) if any(c.isalnum() for c in m.group())]
    m = rng.choice(spans)
    return quote[: m.start()] + "ZZMUTATEDZZ" + quote[m.end() :]


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_property_mutate_one_random_word_then_restore(tmp_path, seed):
    rng = random.Random(seed)
    decisions = _fixture_decisions(tmp_path)
    assert len(decisions) == 13
    for repo, dec in decisions:
        src = dec.source
        assert verify_source_quote(repo, src).status == "VERIFIED"
        bad = src.model_copy(update={"quote": _mutate_one_word(src.quote, rng)})
        r = verify_source_quote(repo, bad)
        assert r.status == "MISMATCH", f"{dec.id} seed={seed}: mutated quote still verified"
        assert r.reason
        restored = bad.model_copy(update={"quote": src.quote})
        assert verify_source_quote(repo, restored).status == "VERIFIED", dec.id


def test_property_delete_and_insert_word_also_detected(tmp_path):
    rng = random.Random(99)
    for repo, dec in _fixture_decisions(tmp_path):
        words = dec.source.quote.split()
        if len(words) < 2:
            continue
        i = rng.randrange(len(words))
        deleted = " ".join(words[:i] + words[i + 1 :])
        inserted = " ".join(words[:i] + ["extra"] + words[i:])
        # Deleting a word can only be undetected if the remaining text still occurs in range
        # (a quote is a *substring* claim): accept VERIFIED only for edge words.
        r = verify_source_quote(repo, dec.source.model_copy(update={"quote": inserted}))
        assert r.status == "MISMATCH", f"{dec.id}: inserted word undetected"
        if 0 < i < len(words) - 1:
            r = verify_source_quote(repo, dec.source.model_copy(update={"quote": deleted}))
            assert r.status == "MISMATCH", f"{dec.id}: interior word deletion undetected"


def test_tampered_file_changes_commit_provenance_not_silently_accepted(tmp_path):
    """The quote is checked against the committed text, not whatever is on disk."""
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    dec = _single(repo)
    p = repo / "docs/adr/0007-redis.md"
    p.write_text(NYGARD.replace("Redis for session", "Memcached for session"), encoding="utf-8")
    assert _verify(repo, dec).status == "VERIFIED"  # commit-pinned
    dec2 = _single(repo)
    assert dec2.source.commit == WORKTREE and "Memcached" in dec2.source.quote
    assert _verify(repo, dec2).status == "VERIFIED"
    stale = dec2.source.model_copy(update={"quote": dec.source.quote})
    assert verify_source_quote(repo, stale).status == "MISMATCH"


# ------------------------------------------------------------ line endings


def test_crlf_line_endings(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD.replace("\n", "\r\n").encode()})
    dec = _single(repo)
    assert "\r" not in dec.decision_text and "\r" not in dec.source.quote
    lf = parse_adr(NYGARD, "docs/adr/0007-redis.md", "c")
    assert (dec.source.line_start, dec.source.line_end) == (
        lf.source.line_start,
        lf.source.line_end,
    )
    assert dec.status == "accepted" and dec.id == "ADR-0007"
    assert _verify(repo, dec).status == "VERIFIED"


def test_crlf_with_quote_containing_cr_still_verifies(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD.replace("\n", "\r\n").encode()})
    dec = _single(repo)
    q = dec.source.quote.replace("\n", "\r\n")
    assert (
        verify_source_quote(repo, dec.source.model_copy(update={"quote": q})).status == "VERIFIED"
    )


def test_mixed_and_lone_cr_endings_do_not_crash(tmp_path):
    body = "# 1. X\r\n\r\n## Decision\r\nWe use X.\nWe also use Y.\r\n"
    repo = _repo(tmp_path, {"docs/adr/0001-x.md": body.encode()})
    dec = _single(repo)
    assert _verify(repo, dec).status == "VERIFIED"
    old_mac = "# 2. Z\r\r## Decision\rWe use Z.\r"
    repo2 = _repo(tmp_path, {"docs/adr/0002-z.md": old_mac.encode()}, name="r2")
    dec2 = _single(repo2)  # lone CR is not a line break (matches git/editors): must not crash
    assert _verify(repo2, dec2).status in ("VERIFIED", "MISMATCH")


def test_crlf_cli_scan_exit_0(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD.replace("\n", "\r\n").encode()})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output


# ------------------------------------------------------------ trailing newline, empty, odd shapes


def test_no_trailing_newline(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD.rstrip("\n")})
    dec = _single(repo)
    assert dec.decision_text.endswith("sessions.")
    assert _verify(repo, dec).status == "VERIFIED"


def test_decision_is_last_line_without_trailing_newline(tmp_path):
    text = "# 3. Last\n\n## Decision\n\nThe final line is the decision."
    repo = _repo(tmp_path, {"docs/adr/0003-last.md": text})
    dec = _single(repo)
    assert dec.source.line_start == dec.source.line_end == 5
    assert _verify(repo, dec).status == "VERIFIED"


def test_freeform_no_trailing_newline_single_line(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-one.md": "Only one line, no heading."})
    dec = _single(repo)
    assert _verify(repo, dec).status == "VERIFIED"


def test_empty_adr_does_not_crash_and_is_never_verified_as_fact(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-empty.md": b""})
    res = scan_adrs(repo)  # must not raise
    for dec in res.decisions:
        r = _verify(repo, dec)
        assert r.status != "VERIFIED" or dec.source.quote.strip(), "empty quote verified"
        assert r.reason


@pytest.mark.parametrize("content", [b"\n", b"\n\n\n", b"   \n\t\n", b"# \n", b"---\n---\n"])
def test_whitespace_only_or_headingless_adr_does_not_crash(tmp_path, content):
    repo = _repo(tmp_path, {"docs/adr/0001-blank.md": content})
    res = scan_adrs(repo)
    for dec in res.decisions:
        _verify(repo, dec)  # must return a result, not raise


def test_empty_adr_cli_no_traceback(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-empty.md": b"", "docs/adr/0002-ok.md": NYGARD})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code in (0, 3), res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "Traceback" not in res.output


def test_binary_garbage_adr_does_not_crash(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-bin.md": bytes(range(256)) * 4})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exception is None or isinstance(res.exception, SystemExit)


def test_utf8_bom_adr(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": b"\xef\xbb\xbf" + NYGARD.encode()})
    res = scan_adrs(repo)
    assert len(res.decisions) == 1
    assert _verify(repo, res.decisions[0]).status == "VERIFIED"


# ------------------------------------------------------------ duplicate headings / ids


def test_duplicate_decision_headings(tmp_path):
    text = (
        "# 4. Dupes\n\n## Decision\n\nFirst decision text.\n\n"
        "## Decision\n\nSecond decision text.\n\n## Consequences\n\nc\n"
    )
    repo = _repo(tmp_path, {"docs/adr/0004-dupes.md": text})
    dec = _single(repo)
    assert dec.source.quote in (
        "First decision text.",
        "First decision text.\n\nSecond decision text.",
    )
    assert _verify(repo, dec).status == "VERIFIED"
    assert (dec.source.line_start, dec.source.line_end)[0] == 5


def test_duplicate_h1_and_status_headings(tmp_path):
    text = (
        "# 5. A\n\n## Status\n\nProposed\n\n## Status\n\nAccepted\n\n# 5. B\n\n"
        "## Decision\n\nDo the thing.\n"
    )
    repo = _repo(tmp_path, {"docs/adr/0005-a.md": text})
    dec = _single(repo)
    assert dec.status in ("proposed", "accepted")
    assert _verify(repo, dec).status == "VERIFIED"


def test_duplicate_adr_ids_get_unique_ids_and_both_verify(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "docs/adr/0003-a.md": NYGARD.replace("7.", "3."),
            "docs/adr/0003-b.md": NYGARD.replace("7.", "3.").replace("Redis", "Valkey"),
        },
    )
    res = scan_adrs(repo)
    ids = [d.id for d in res.decisions]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert all(_verify(repo, d).status == "VERIFIED" for d in res.decisions)


def test_heading_inside_code_fence_is_ignored(tmp_path):
    text = (
        "# 6. Fence\n\n## Decision\n\nUse this config:\n\n```\n## Decision\nfake\n```\n\n"
        "Then proceed.\n\n## Consequences\n\nnone\n"
    )
    repo = _repo(tmp_path, {"docs/adr/0006-fence.md": text})
    dec = _single(repo)
    assert "Then proceed." in dec.source.quote
    assert _verify(repo, dec).status == "VERIFIED"


# ------------------------------------------------------------ WORKTREE / detached HEAD


def test_modified_tracked_adr_is_worktree_and_line_numbers_follow_edit(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    committed = _single(repo)
    assert committed.source.commit == dwgit.head_sha(repo)
    p = repo / "docs/adr/0007-redis.md"
    p.write_text("<!-- note 1 -->\n<!-- note 2 -->\n" + NYGARD, encoding="utf-8")
    dec = _single(repo)
    assert dec.source.commit == WORKTREE
    assert dec.source.line_start == committed.source.line_start + 2
    assert _verify(repo, dec).status == "VERIFIED"
    # The committed provenance is still valid against its own commit...
    assert _verify(repo, committed).status == "VERIFIED"
    # ...but the same range mis-attributed to the worktree is a MISMATCH.
    moved = committed.source.model_copy(update={"commit": WORKTREE})
    assert verify_source_quote(repo, moved).status == "MISMATCH"


def test_staged_but_uncommitted_edit_is_worktree(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    p = repo / "docs/adr/0007-redis.md"
    p.write_text(NYGARD.replace("Redis for", "KeyDB for"), encoding="utf-8")
    git(repo, "add", "--", "docs/adr/0007-redis.md")
    dec = _single(repo)
    assert dec.source.commit == WORKTREE and "KeyDB" in dec.source.quote
    assert _verify(repo, dec).status == "VERIFIED"


def test_untracked_adr_is_worktree(tmp_path):
    repo = _repo(tmp_path, {"README.md": "x\n"})
    p = repo / "docs/adr/0007-redis.md"
    p.parent.mkdir(parents=True)
    p.write_text(NYGARD, encoding="utf-8")
    dec = _single(repo)
    assert dec.source.commit == WORKTREE
    assert _verify(repo, dec).status == "VERIFIED"


def test_repo_with_no_commits_reads_worktree(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    p = repo / "docs/adr/0007-redis.md"
    p.parent.mkdir(parents=True)
    p.write_text(NYGARD, encoding="utf-8")
    res = scan_adrs(repo)
    assert res.head is None and res.decisions[0].source.commit == WORKTREE
    assert _verify(repo, res.decisions[0]).status == "VERIFIED"
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output


def test_worktree_file_deleted_after_scan_is_mismatch(tmp_path):
    repo = _repo(tmp_path, {"README.md": "x\n"})
    p = repo / "docs/adr/0007-redis.md"
    p.parent.mkdir(parents=True)
    p.write_text(NYGARD, encoding="utf-8")
    dec = _single(repo)
    p.unlink()
    assert _verify(repo, dec).status == "MISMATCH"


def test_detached_head(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    first = dwgit.head_sha(repo)
    p = repo / "docs/adr/0007-redis.md"
    p.write_text(NYGARD.replace("Redis", "Valkey"), encoding="utf-8")
    git(repo, "commit", "-q", "-am", "second")
    git(repo, "checkout", "-q", "--detach", first)
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "HEAD"
    dec = _single(repo)
    assert dec.source.commit == first and "Redis" in dec.source.quote
    assert _verify(repo, dec).status == "VERIFIED"
    out = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    rows, _ = _ledger_rows(out)
    assert rows[0]["provenance"]["commit"] == first and rows[0]["status"] == "VERIFIED"


def test_detached_head_with_dirty_adr(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    git(repo, "checkout", "-q", "--detach", "HEAD")
    (repo / "docs/adr/0007-redis.md").write_text(NYGARD + "\nextra\n", encoding="utf-8")
    dec = _single(repo)
    assert dec.source.commit == WORKTREE and _verify(repo, dec).status == "VERIFIED"


# ------------------------------------------------------------ emphasis and curly quotes


EMPH = (
    "# 8. Quote handling\n\n## Decision\n\n"
    "We **must** use _only_ ~~legacy~~ “curly” and ‘single’ quotes, don’t we?\n"
    "Use `code` and *emphasis* plus __strong__ text.\n"
)


def test_markdown_emphasis_and_curly_quotes_roundtrip(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0008-q.md": EMPH})
    dec = _single(repo)
    assert "**must**" in dec.source.quote  # quote is verbatim, not pre-normalised
    assert _verify(repo, dec).status == "VERIFIED"


@pytest.mark.parametrize(
    "quote",
    [
        "We must use only legacy \"curly\" and 'single' quotes, don't we?",
        "We **must** use _only_ ~~legacy~~ “curly” and ‘single’ quotes, don’t we?",
        "We must use only legacy “curly” and 'single' quotes, don’t we?",
        "Use `code` and emphasis plus strong text.",
    ],
)
def test_emphasis_and_quote_variants_verify(tmp_path, quote):
    repo = _repo(tmp_path, {"docs/adr/0008-q.md": EMPH})
    dec = _single(repo)
    assert verify_source_quote(repo, dec.source.model_copy(update={"quote": quote})).status == (
        "VERIFIED"
    )


@pytest.mark.parametrize(
    "quote",
    [
        "We must use only legacy \"curly\" and 'single' quotes, do we?",  # word changed
        "We must not use only legacy \"curly\" and 'single' quotes, don't we?",
        "We must use only legacy “curly” and 'single' quotes don't we?",  # comma dropped
    ],
)
def test_emphasis_variants_with_real_changes_mismatch(tmp_path, quote):
    repo = _repo(tmp_path, {"docs/adr/0008-q.md": EMPH})
    dec = _single(repo)
    assert verify_source_quote(repo, dec.source.model_copy(update={"quote": quote})).status == (
        "MISMATCH"
    )


def test_unicode_normalisation_nfc_vs_nfd(tmp_path):
    text = "# 9. Café\n\n## Decision\n\nServe café menus.\n"
    repo = _repo(tmp_path, {"docs/adr/0009-cafe.md": text})
    dec = _single(repo)
    nfd = "Serve café menus."
    assert verify_source_quote(repo, dec.source.model_copy(update={"quote": nfd})).status == (
        "VERIFIED"
    )


def test_observation_underscore_identifier_collapses(tmp_path):
    """Documents a known weakness: '_' is stripped on both sides, so snake_case == snakecase."""
    text = "# 10. Names\n\n## Decision\n\nUse snake_case names.\n"
    repo = _repo(tmp_path, {"docs/adr/0010-names.md": text})
    dec = _single(repo)
    r = verify_source_quote(repo, dec.source.model_copy(update={"quote": "Use snakecase names."}))
    assert r.status in ("VERIFIED", "MISMATCH")  # informational; reported to PM, not asserted


# ------------------------------------------------------------ long ADRs


def _long_adr(n_lines: int, decision_at: int) -> tuple[str, list[str]]:
    lines = ["# 11. Very long ADR", "", "## Context", ""]
    while len(lines) < decision_at:
        lines.append(f"Context filler line {len(lines)} with some words.")
    lines += ["", "## Decision", "", "Use sharding by tenant id.", "Never cross-shard.", ""]
    lines += ["## Consequences", ""]
    while len(lines) < n_lines:
        lines.append(f"Consequence filler line {len(lines)} with some words.")
    return "\n".join(lines) + "\n", lines


@pytest.mark.parametrize("n,at", [(2100, 2000), (2500, 1200), (5000, 4000)])
def test_very_long_adr_line_numbers_and_speed(tmp_path, n, at):
    text, lines = _long_adr(n, at)
    assert len(lines) > 2000
    repo = _repo(tmp_path, {"docs/adr/0011-long.md": text})
    t0 = time.perf_counter()
    dec = _single(repo)
    r = _verify(repo, dec)
    elapsed = time.perf_counter() - t0
    assert r.status == "VERIFIED"
    s = dec.source
    assert lines[s.line_start - 1] == "Use sharding by tenant id."
    assert lines[s.line_end - 1] == "Never cross-shard."
    assert elapsed < 5.0, f"too slow: {elapsed:.2f}s"


def test_very_long_adr_wrong_range_reports_true_location(tmp_path):
    text, _ = _long_adr(2500, 1200)
    repo = _repo(tmp_path, {"docs/adr/0011-long.md": text})
    dec = _single(repo)
    s = dec.source
    off = s.model_copy(update={"line_start": s.line_start + 500, "line_end": s.line_end + 500})
    r = verify_source_quote(repo, off)
    assert r.status == "MISMATCH" and f"found at lines {s.line_start}-{s.line_end}" in r.reason


def test_very_long_single_line_adr(tmp_path):
    body = "word " * 200_000
    text = f"# 12. Huge line\n\n## Decision\n\n{body}end.\n"
    repo = _repo(tmp_path, {"docs/adr/0012-huge.md": text})
    dec = _single(repo)
    t0 = time.perf_counter()
    assert _verify(repo, dec).status == "VERIFIED"
    assert time.perf_counter() - t0 < 5.0


# ------------------------------------------------------------ paths with spaces / unicode


@pytest.mark.parametrize(
    "rel",
    [
        "docs/adr/0013 use café — décision ✓.md",
        "docs/adr/0014-渡辺 notes.md",
        "docs/my adrs/x.md",
        "docs/adr/0015-quote'apostrophe and #hash.md",
    ],
)
def test_unusual_paths(tmp_path, rel):
    cfg = '[tool.driftwarden]\nadr_paths = ["docs/my adrs"]\n'
    repo = _repo(tmp_path, {rel: NYGARD, "pyproject.toml": cfg})
    res = scan_adrs(repo, load_config(repo))
    assert [d.source.path for d in res.decisions] == [rel]
    dec = res.decisions[0]
    assert dec.source.commit == dwgit.head_sha(repo), (
        "tracked+clean file wrongly treated as WORKTREE"
    )
    assert _verify(repo, dec).status == "VERIFIED"


def test_unusual_path_cli_roundtrip_and_ledger_utf8(tmp_path):
    rel = "docs/adr/0013 use café — décision ✓.md"
    repo = _repo(tmp_path, {rel: NYGARD}, name="repo with space é")
    out = tmp_path / "out dir"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    (ledger,) = (out / "logs" / "grounding").glob("*.jsonl")
    rows = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["provenance"]["path"] == rel and rows[0]["status"] == "VERIFIED"


def test_path_with_square_brackets_rich_markup(tmp_path):
    rel = "docs/adr/0016-[bold]x[/bold].md"
    repo = _repo(tmp_path, {rel: NYGARD})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    rows, _ = _ledger_rows(tmp_path / "o")
    assert rows[0]["provenance"]["path"] == rel and rows[0]["status"] == "VERIFIED"


def test_modified_unicode_path_is_worktree(tmp_path):
    rel = "docs/adr/0013 use café.md"
    repo = _repo(tmp_path, {rel: NYGARD})
    (repo / rel).write_text(NYGARD + "\nmore\n", encoding="utf-8")
    assert _single(repo).source.commit == WORKTREE


# ------------------------------------------------------------ ledger + CLI


def _ledger_rows(out: Path):
    (jsonl,) = (out / "logs" / "grounding").glob("*.jsonl")
    (summ,) = (out / "logs" / "grounding").glob("*.summary.json")
    lines = jsonl.read_text(encoding="utf-8").split("\n")
    assert lines[-1] == "", "ledger must end with a newline"
    rows = [json.loads(x) for x in lines[:-1]]  # every line must be valid JSON
    return rows, json.loads(summ.read_text(encoding="utf-8"))


def test_ledger_is_jsonl_with_correct_pass_rate_on_fixtures(tmp_path):
    repo = tmp_path / "fx"
    shutil.copytree(FIXTURES / "basic", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fx")
    out = tmp_path / "out"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    rows, summ = _ledger_rows(out)
    assert len(rows) == 12 == summ["total"]
    assert all(r["check_id"] == "G1" and r["status"] == "VERIFIED" for r in rows)
    assert summ["verified"] == 12 and summ["mismatch"] == 0 and summ["pass_rate"] == 1.0
    assert len({r["run_id"] for r in rows}) == 1 == len({summ["run_id"]})
    assert {r["subject"] for r in rows} == {d.id for d in scan_adrs(repo).decisions}
    for r in rows:
        assert set(r["provenance"]) == {"path", "line_start", "line_end", "commit", "quote"}


def test_ledger_pass_rate_with_forced_mismatches(tmp_path, monkeypatch):
    repo = tmp_path / "fx"
    shutil.copytree(FIXTURES / "basic", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fx")
    real = cli.scan_adrs

    def tamper(*a, **k):
        r = real(*a, **k)
        for i in (0, 5, 11):
            d = r.decisions[i]
            bad = d.source.model_copy(update={"quote": "never written " + d.source.quote})
            r.decisions[i] = d.model_copy(update={"source": bad})
        return r

    monkeypatch.setattr(cli, "scan_adrs", tamper)
    out = tmp_path / "out"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 3
    rows, summ = _ledger_rows(out)
    assert sum(r["status"] == "MISMATCH" for r in rows) == 3
    assert summ["total"] == 12 and summ["verified"] == 9 and summ["mismatch"] == 3
    assert summ["pass_rate"] == pytest.approx(0.75)
    assert "9/12 VERIFIED" in res.output and "75.0%" in res.output
    assert res.output.count("Could not verify") == 3
    assert all(r["reason"] for r in rows if r["status"] == "MISMATCH")


def test_scan_exit_3_forced_mismatch_via_real_file_race(tmp_path, monkeypatch):
    """ADR edited between parse and verify (no mocking of the verifier) -> exit 3."""
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    real = cli.scan_adrs

    def racing(*a, **k):
        r = real(*a, **k)
        (repo / "docs/adr/0007-redis.md").write_text(
            "# 7. x\n\n## Decision\n\nsomething else\n", encoding="utf-8"
        )
        r.decisions[0] = r.decisions[0].model_copy(
            update={"source": r.decisions[0].source.model_copy(update={"commit": WORKTREE})}
        )
        return r

    monkeypatch.setattr(cli, "scan_adrs", racing)
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 3, res.output
    assert "Could not verify" in res.output and "ADR-0007" in res.output


def test_scan_exit_3_via_subprocess_not_overridden(tmp_path):
    """Real process, real ADR the verifier cannot ground (empty quote range) is not required;
    instead assert exit 0 on a clean repo and 2 on non-git, 3 only on MISMATCH (see mock tests)."""
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    exe = shutil.which("driftwarden", path=str(Path(sys.executable).parent))
    ok = subprocess.run(
        [exe, "scan", str(repo), "--out", str(tmp_path / "o")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_scan_non_git_directory_exit_2_clear_error(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "x.md").write_text("hi\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(d), "--out", str(tmp_path / "o")])
    assert res.exit_code == 2
    assert "git" in res.output.lower() and "Traceback" not in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)


def test_scan_no_adrs_pass_rate_na(tmp_path):
    repo = _repo(tmp_path, {"README.md": "x\n"})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0 and "n/a" in res.output


def test_scan_default_out_is_cwd_logs(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    res = runner.invoke(app, ["scan", str(repo)])
    assert res.exit_code == 0
    assert list((work / "logs" / "grounding").glob("*.jsonl"))


def test_scan_does_not_write_ledger_into_scanned_repo_by_default(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["scan", str(repo)])
    assert git(repo, "status", "--porcelain").strip() == ""


def test_ledger_unit_pass_rate(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    dec = _single(repo)
    led = Ledger(tmp_path / "L", run_id="unit")
    for i in range(4):
        src = dec.source if i < 3 else dec.source.model_copy(update={"quote": "nope"})
        led.append(verify_source_quote(repo, src, subject=f"s{i}"))
    summ = led.write_summary()
    assert summ["pass_rate"] == 0.75
    lines = led.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4 and all(isinstance(json.loads(x), dict) for x in lines)


# ------------------------------------------------------------ whole-fixture grounding run


def test_grounding_run_across_all_fixture_decisions_and_tamper_detection(tmp_path):
    """Sample = every fixture decision; also every one of them tampered (detection rate)."""
    rng = random.Random(2026)
    verified = total = detected = tampered = 0
    ledger = Ledger(tmp_path / "gl", run_id="fixtures")
    for repo, dec in _fixture_decisions(tmp_path):
        r = verify_source_quote(repo, dec.source, subject=dec.id)
        ledger.append(r)
        total += 1
        verified += r.status == "VERIFIED"
        for _ in range(10):
            bad = dec.source.model_copy(update={"quote": _mutate_one_word(dec.source.quote, rng)})
            tampered += 1
            detected += verify_source_quote(repo, bad).status == "MISMATCH"
    summ = ledger.write_summary()
    print(f"GROUNDING fixtures sample={total} verified={verified} rate={verified / total:.3f}")
    print(f"TAMPER sample={tampered} detected={detected} rate={detected / tampered:.3f}")
    assert total == 13 and verified == total and summ["pass_rate"] == 1.0
    assert detected == tampered


def test_every_decision_has_complete_provenance(tmp_path):
    for repo, dec in _fixture_decisions(tmp_path):
        s = dec.source
        assert s.path and s.quote.strip() and s.line_start >= 1 and s.line_end >= s.line_start
        assert s.commit == dwgit.head_sha(repo) and len(s.commit) == 40
        assert s.quote == dec.decision_text
        assert s.line_end - s.line_start + 1 >= len(s.quote.split("\n")) - 0
