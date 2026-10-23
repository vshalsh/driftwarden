from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(repo: Path, *args: str) -> str:
    import os

    env = {**os.environ, **GIT_ENV}
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, env=env, check=True
    )
    return proc.stdout


@pytest.fixture
def make_repo(tmp_path):
    """Return a factory that creates a real git repo with the given files committed."""

    def _make(files: dict[str, str] | None = None, name: str = "repo") -> Path:
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "commit.gpgsign", "false")
        for rel, content in (files or {}).items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        if files:
            git(repo, "add", "--", *files.keys())
            git(repo, "commit", "-q", "-m", "initial")
        return repo

    return _make
