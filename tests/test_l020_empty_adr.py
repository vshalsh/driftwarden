"""L-020: empty ADR files are skipped with a note, not reported as MISMATCH.

Also D-002: config errors are reported (exit 2, "config error") before the
non-git check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import git
from driftwarden.cli import app
from driftwarden.discover.adr import EMPTY_NOTE, scan_adrs

runner = CliRunner()

NYGARD = (
    "# 7. Use Redis for sessions\n\n## Status\n\nAccepted\n\n"
    "## Decision\n\nWe will use Redis for session storage.\n"
)


def _repo(tmp_path: Path, files: dict[str, bytes]) -> Path:
    repo = tmp_path / "r"
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
    (summ,) = (out / "logs" / "grounding").glob("*.summary.json")
    return json.loads(summ.read_text(encoding="utf-8"))


@pytest.mark.parametrize("content", [b"", b"\n", b"  \n\t\n"])
def test_empty_adr_is_skipped_not_parsed(tmp_path, content):
    repo = _repo(tmp_path, {"docs/adr/0001-empty.md": content})
    res = scan_adrs(repo)
    assert res.decisions == []
    assert res.errors == []
    assert res.skipped == [("docs/adr/0001-empty.md", EMPTY_NOTE)]


def test_empty_adr_alongside_real_adr_exit_0(tmp_path):
    repo = _repo(
        tmp_path,
        {"docs/adr/0001-empty.md": b"", "docs/adr/0002-redis.md": NYGARD.encode()},
    )
    out = tmp_path / "o"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert "skipped" in res.output and "0001-empty.md" in res.output
    assert "empty file" in res.output
    assert "MISMATCH" not in res.output and "Could not verify" not in res.output
    summ = _summary(out)
    assert summ["total"] == 1 and summ["verified"] == 1 and summ["mismatch"] == 0


def test_only_empty_adr_exit_0_nothing_to_verify(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-empty.md": b""})
    res = runner.invoke(app, ["scan", str(repo), "--out", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "skipped" in res.output and "n/a" in res.output
    assert "No ADRs found" not in res.output  # one was found; it was skipped


def test_empty_untracked_adr_is_skipped(tmp_path):
    repo = _repo(tmp_path, {"README.md": b"x\n"})
    p = repo / "docs/adr/0003-new.md"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"")
    res = scan_adrs(repo)
    assert res.decisions == [] and [r for r, _ in res.skipped] == ["docs/adr/0003-new.md"]


def test_headingless_but_nonblank_adr_still_parsed(tmp_path):
    repo = _repo(tmp_path, {"docs/adr/0001-one.md": b"Only one line."})
    res = scan_adrs(repo)
    assert res.skipped == [] and len(res.decisions) == 1


# ------------------------------------------------------------------ D-002


def test_d002_config_error_before_non_git_check(tmp_path):
    (tmp_path / "driftwarden.toml").write_text('mode = "bogus"\n', encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 2
    assert "config error" in res.output
    assert "not a git repository" not in res.output
    assert "Traceback" not in res.output


def test_d002_missing_explicit_config_on_non_git_dir(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path), "--config", str(tmp_path / "nope.toml")])
    assert res.exit_code == 2 and "config error" in res.output


def test_d002_config_error_in_git_repo(tmp_path):
    repo = _repo(tmp_path, {"driftwarden.toml": b"mode = [\n"})
    res = runner.invoke(app, ["scan", str(repo)])
    assert res.exit_code == 2 and "config error" in res.output


def test_d002_non_git_without_config_still_exit_2(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 2 and "not a git repository" in res.output
