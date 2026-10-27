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


FIXTURES = Path(__file__).parent / "fixtures" / "adr_repos"
INDEX_FIXTURES = Path(__file__).parent / "fixtures" / "index_repos"


@pytest.fixture
def index_fixture(tmp_path):
    """Copy tests/fixtures/index_repos/<name> into tmp_path; commit it unless git=False."""
    import shutil

    counter = iter(range(10_000))

    def _make(name: str, git_init: bool = True) -> Path:
        dest = tmp_path / f"ix-{name}-{next(counter)}"
        shutil.copytree(INDEX_FIXTURES / name, dest, symlinks=True)
        if git_init:
            git(dest, "init", "-q", "-b", "main")
            git(dest, "config", "commit.gpgsign", "false")
            git(dest, "add", "-A")
            git(dest, "commit", "-q", "-m", "fixture")
        return dest

    return _make


@pytest.fixture
def fixture_repo(tmp_path):
    """Copy tests/fixtures/adr_repos/<name> into tmp_path and make it a real git repo."""
    import shutil

    def _make(name: str = "basic") -> Path:
        dest = tmp_path / f"fx-{name}"
        shutil.copytree(FIXTURES / name, dest)
        git(dest, "init", "-q", "-b", "main")
        git(dest, "config", "commit.gpgsign", "false")
        git(dest, "add", "-A")
        git(dest, "commit", "-q", "-m", "fixture")
        return dest

    return _make


@pytest.fixture(scope="session")
def perf_factor() -> float:
    """CPU-speed multiplier for pure-Python time budgets: 1.0 on the reference Linux box
    (~22 ms for the probe), larger on slower runners. Budgets stay tight where the machine is
    fast and scale up where it is not, instead of a flat wall clock."""
    import time

    from driftwarden.claims.rules import match_sentence

    s = "We will use A, we will use B, " * 100
    best = 1e9
    for _ in range(3):
        t = time.perf_counter()
        for _ in range(5):
            match_sentence(s)
        best = min(best, (time.perf_counter() - t) / 5)
    return max(1.0, best / 0.025)


def time_5000_claim_adr(make_repo, body_fn, adr_fn, offline_fn, n: int):
    """Wall time of an end-to-end n-claim ADR (scan + structure + G1 verify), plus the repo,
    the claim set and the measured cost of one G1 verification (200 sampled calls)."""
    import time

    from driftwarden.grounding.verify import verify_source_quote

    body = "\n".join(body_fn(i) for i in range(n))
    t = time.perf_counter()
    repo, cs = offline_fn(make_repo, adr_fn(body))
    dt = time.perf_counter() - t
    sample = cs.claims[:: max(1, len(cs.claims) // 200)][:200]
    t = time.perf_counter()
    for c in sample:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
    per_call = (time.perf_counter() - t) / max(1, len(sample))
    return dt, per_call, repo, cs
