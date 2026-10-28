"""L-020 system tests (tester seat): empty ADRs and D-002 config-before-git ordering."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import git
from driftwarden.cli import app
from driftwarden.discover.adr import scan_adrs

runner = CliRunner()

NYGARD = (
    b"# 7. Use Redis for sessions\n\n## Status\n\nAccepted\n\n"
    b"## Decision\n\nWe will use Redis for session storage.\n"
)


def _repo(tmp_path: Path, files: dict[str, bytes], name: str = "r") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    git(repo, "add", "--", *files.keys())
    git(repo, "commit", "-q", "-m", "init")
    return repo


def _summary(out: Path) -> dict:
    # L-028: the ledger now also holds claim/evidence rows from the full pipeline; these
    # tests are about the decision-level G1 rows (subject = decision id, no ".cN").
    (summ,) = (out / "logs" / "grounding").glob("*.summary.json")
    rows = [
        json.loads(line)
        for p in (out / "logs" / "grounding").glob("*.jsonl")
        for line in p.read_text(encoding="utf-8").splitlines()
    ]
    rows = [r for r in rows if r["check_id"] == "G1" and "." not in (r["subject"] or "")]
    ok = sum(r["status"] == "VERIFIED" for r in rows)
    data = json.loads(summ.read_text(encoding="utf-8"))
    data.update(total=len(rows), verified=ok, mismatch=len(rows) - ok)
    return data


@pytest.mark.parametrize(
    "content",
    [b" ", b"\n\n\n", b"\r\n", b"\r\n\r\n  \r\n", b"\t", b" \n \n \n", b"\x0b\x0c", b"\xc2\xa0\n"],
    ids=["space", "newlines", "crlf", "crlf-ws", "tab", "mixed", "vt-ff", "nbsp"],
)
def test_whitespace_only_variants_skipped(tmp_path, content):
    repo = _repo(tmp_path, {"docs/adr/0001-ws.md": content})
    res = scan_adrs(repo)
    assert res.decisions == [] and res.errors == []
    assert [r for r, _ in res.skipped] == ["docs/adr/0001-ws.md"]
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output
    assert "MISMATCH" not in out.output


def test_bom_only_adr_is_treated_as_empty(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-bom.md": b"\xef\xbb\xbf"})
    res = scan_adrs(repo)
    assert res.decisions == [], "BOM-only file must not produce a decision"
    assert [r for r, _ in res.skipped] == ["docs/adr/0001-bom.md"]
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output
    assert "MISMATCH" not in out.output


def test_bom_plus_whitespace_only_is_empty(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-bom.md": b"\xef\xbb\xbf\n\n"})
    res = scan_adrs(repo)
    assert res.decisions == [] and res.errors == []
    assert [r for r, _ in res.skipped] == ["docs/adr/0001-bom.md"]
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output
    assert "MISMATCH" not in out.output


def test_bom_prefixed_real_adr_verifies(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-bom.md": b"\xef\xbb\xbf" + NYGARD})
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output
    assert _summary(tmp_path / "o")["mismatch"] == 0


def test_empty_among_many_valid(tmp_path):
    files = {f"docs/adr/000{i}-d.md": NYGARD.replace(b"7.", f"{i}.".encode()) for i in (1, 2, 4, 5)}
    files["docs/adr/0003-empty.md"] = b""
    repo = _repo(tmp_path, files)
    o = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(o)])
    assert res.exit_code == 0, res.output
    s = _summary(o)
    assert s["total"] == 4 and s["verified"] == 4 and s["mismatch"] == 0
    assert res.output.count("skipped") >= 1 and "0003-empty.md" in res.output


def test_multiple_empties_counted(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-a.md": b"", "docs/adr/0002-b.md": b"\n"})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "2 empty" in res.output
    assert "0001-a.md" in res.output and "0002-b.md" in res.output


def test_only_empty_repo_exit_0_and_no_mismatch(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-a.md": b""})
    o = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(o)])
    assert res.exit_code == 0, res.output
    assert "Traceback" not in res.output
    s = _summary(o)
    assert s["total"] == 0 and s["mismatch"] == 0


@pytest.mark.parametrize(
    "rel",
    [
        "docs/adr/sub/deep/0001-e.md",
        "doc/adr/team/0002-e.md",
        "adr/a/b/c/d/0003-e.md",
        "docs/decisions/x/0004-e.md",
    ],
)
def test_empty_adr_in_nested_dirs(tmp_path, rel):
    repo = _repo(tmp_path, {rel: b"", "README.md": b"hi\n"})
    res = scan_adrs(repo)
    assert res.decisions == []
    assert [r for r, _ in res.skipped] == [rel]
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output


def test_empty_adr_with_rich_markup_in_filename(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-[red]x[/red].md": b""})
    out = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0, out.output
    assert "[red]x[/red]" in out.output


def test_crlf_valid_adr_alongside_empty(tmp_path):
    crlf = NYGARD.replace(b"\n", b"\r\n")
    repo = _repo(tmp_path, {"docs/adr/0001-crlf.md": crlf, "docs/adr/0002-e.md": b"\r\n"})
    o = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(o)])
    assert res.exit_code == 0, res.output
    s = _summary(o)
    assert s["total"] == 1 and s["verified"] == 1


def test_truncated_tracked_adr_in_worktree_is_skipped(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-a.md": NYGARD})
    (repo / "docs/adr/0001-a.md").write_bytes(b"")  # truncated, uncommitted
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "skipped" in res.output


def test_committed_empty_then_filled_in_worktree(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-a.md": b""})
    (repo / "docs/adr/0001-a.md").write_bytes(NYGARD)
    o = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(o)])
    assert res.exit_code == 0, res.output
    assert _summary(o)["verified"] == 1


def test_empty_adr_in_repo_without_commits(tmp_path):
    repo = tmp_path / "fresh"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "docs/adr").mkdir(parents=True)
    (repo / "docs/adr/0001-a.md").write_bytes(b"")
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "skipped" in res.output


def test_ledger_has_no_row_for_empty(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-a.md": b"", "docs/adr/0002-r.md": NYGARD})
    o = tmp_path / "o"
    runner.invoke(app, ["scan", str(repo), "--out", str(o)])
    blob = "".join(p.read_text(encoding="utf-8") for p in (o / "logs" / "grounding").glob("*"))
    assert "0001-a.md" not in blob


# ------------------------------------------------------------------ D-002


def test_d002_bad_config_in_non_git_dir_is_config_error(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "driftwarden.toml").write_text("this is = = not toml\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(d)])
    assert res.exit_code == 2
    assert "config error" in res.output
    assert "not a git repository" not in res.output


def test_d002_explicit_bad_config_non_git(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[[[\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(d), "--config", str(cfg)])
    assert res.exit_code == 2 and "config error" in res.output


def test_d002_valid_config_non_git_still_git_error(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "driftwarden.toml").write_text("", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(d)])
    assert res.exit_code == 2
    assert "not a git repository" in res.output and "config error" not in res.output


def test_d002_nonexistent_path_wins_over_bad_config(tmp_path):
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[[[\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path / "nope"), "--config", str(cfg)])
    assert res.exit_code == 2 and "does not exist" in res.output


def test_d002_path_is_file_non_git_bad_config(tmp_path):
    f = tmp_path / "x.md"
    f.write_text("hi", encoding="utf-8")
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[[[\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(f), "--config", str(cfg)])
    assert res.exit_code == 2 and "Traceback" not in res.output
    assert "config error" in res.output


def test_d002_config_path_with_markup_chars(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    cfg = tmp_path / "[bold]weird[/bold].toml"
    res = runner.invoke(app, ["scan", str(d), "--config", str(cfg)])
    assert res.exit_code == 2 and "config error" in res.output
    assert "Traceback" not in res.output


def test_d002_bad_config_does_not_write_ledger(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "driftwarden.toml").write_text("[[[\n", encoding="utf-8")
    o = tmp_path / "o"
    runner.invoke(app, ["scan", str(d), "--out", str(o)])
    assert not (o / "logs").exists()


# ------------------------------------------------------------ real subprocess


def _run(args, cwd):
    env = {**os.environ, "NO_COLOR": "1", "COLUMNS": "200"}
    return subprocess.run(
        [sys.executable, "-m", "driftwarden.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_subprocess_empty_adr_exit_0(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-e.md": b"", "docs/adr/0002-r.md": NYGARD})
    p = _run(["scan", str(repo), "--out", str(tmp_path / "o")], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "0001-e.md" in p.stdout and "skipped" in p.stdout
    assert "MISMATCH" not in p.stdout + p.stderr
    assert "Traceback" not in p.stderr


def test_subprocess_only_empty_exit_0(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-e.md": b""})
    p = _run(["scan", str(repo), "--out", str(tmp_path / "o")], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr


def test_subprocess_bad_config_non_git_exit_2_config_error_on_stderr(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "driftwarden.toml").write_text("[[[\n", encoding="utf-8")
    p = _run(["scan", str(d)], tmp_path)
    assert p.returncode == 2
    assert "config error" in p.stderr
    assert "not a git repository" not in p.stderr + p.stdout
    assert "Traceback" not in p.stderr


def test_subprocess_non_git_good_config_exit_2(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    p = _run(["scan", str(d)], tmp_path)
    assert p.returncode == 2 and "not a git repository" in p.stderr


def test_subprocess_no_crash_with_empty_plus_valid(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-r.md": NYGARD, "docs/adr/0002-e.md": b""})
    p = _run(["scan", str(repo), "--out", str(tmp_path / "o")], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
