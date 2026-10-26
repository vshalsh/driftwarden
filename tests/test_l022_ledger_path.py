"""L-022: default grounding-ledger location and the ruff-format docs exclude."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import git
from driftwarden.cli import app
from driftwarden.discover.adr import scan_adrs

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]

NYGARD = (
    "# 7. Use Redis for sessions\n\n## Status\n\nAccepted\n\n"
    "## Decision\n\nWe will use Redis for session storage.\n"
)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def _grounding(base: Path) -> Path:
    return base / ".driftwarden" / "logs" / "grounding"


def test_default_ledger_lands_in_scanned_repo(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    res = runner.invoke(app, ["scan", str(repo)])
    assert res.exit_code == 0, res.output
    (jsonl,) = _grounding(repo).glob("*.jsonl")
    (summ,) = _grounding(repo).glob("*.summary.json")
    assert json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])["status"] == "VERIFIED"
    assert json.loads(summ.read_text(encoding="utf-8"))["total"] == 1
    assert list(elsewhere.iterdir()) == []  # nothing written to CWD
    assert ".driftwarden" in res.output  # the ledger path is printed


def test_default_ledger_uses_repo_root_when_scanning_subdirectory(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD, "src/app/x.py": "x = 1\n"})
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["scan", str(repo / "src" / "app")])
    assert res.exit_code == 0, res.output
    assert list(_grounding(repo).glob("*.jsonl"))
    assert not (repo / "src" / "app" / ".driftwarden").exists()


def test_default_ledger_keeps_scanned_repo_clean(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["scan", str(repo)])
    assert (repo / ".driftwarden" / ".gitignore").read_text(encoding="utf-8").endswith("*\n")
    assert git(repo, "status", "--porcelain").strip() == ""


def test_existing_driftwarden_gitignore_is_not_overwritten(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD, ".driftwarden/.gitignore": "x\n"})
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["scan", str(repo)])
    assert (repo / ".driftwarden" / ".gitignore").read_text(encoding="utf-8") == "x\n"


def test_explicit_out_still_wins(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"docs/adr/0007-redis.md": NYGARD})
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    res = runner.invoke(app, ["scan", str(repo), "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert list((out / "logs" / "grounding").glob("*.jsonl"))
    assert not (repo / ".driftwarden").exists()


def test_ledger_dir_is_never_scanned_as_adrs(tmp_path):
    repo = _repo(
        tmp_path,
        {"docs/adr/0007-redis.md": NYGARD, ".driftwarden/logs/grounding/SUMMARY.md": "# x\n"},
    )
    (repo / "driftwarden.toml").write_text('adr_paths = [".driftwarden"]\n', encoding="utf-8")
    from driftwarden.config import load_config

    paths = [d.source.path for d in scan_adrs(repo, load_config(repo)).decisions]
    assert paths == ["docs/adr/0007-redis.md"]


# ------------------------------------------------------------------ ruff format exclude


def test_pyproject_excludes_markdown_from_ruff_format():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ruff = data["tool"]["ruff"]
    exclude = ruff["format"]["exclude"]
    assert "*.md" in exclude and "docs/**" in exclude
    assert ruff.get("force-exclude") is True


def _ruff() -> list[str] | None:
    exe = shutil.which("ruff", path=str(Path(sys.executable).parent)) or shutil.which("ruff")
    return [exe] if exe else None


def test_ruff_format_does_not_touch_markdown(tmp_path):
    ruff = _ruff()
    if ruff is None:
        pytest.skip("ruff not installed")
    # A markdown file whose Python code block ruff would otherwise reformat.
    md = tmp_path / "proj" / "NOTES.md"
    md.parent.mkdir()
    shutil.copy(ROOT / "pyproject.toml", md.parent / "pyproject.toml")
    original = "# Notes\n\n```python\nx = {  'a':1 }\n```\n"
    md.write_text(original, encoding="utf-8")
    proc = subprocess.run(
        [*ruff, "format", str(md)], cwd=md.parent, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert md.read_text(encoding="utf-8") == original
