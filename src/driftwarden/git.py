"""Thin subprocess wrapper around the ``git`` CLI.

No GitPython: every call is a plain ``git`` invocation so behaviour matches
what a user would see on the command line.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from driftwarden.text import decode_text


class GitError(Exception):
    """A git command failed."""


class NotAGitRepoError(GitError):
    """The given path is not inside a git work tree."""


class GitNotFoundError(GitError):
    """The git executable is not available."""


@dataclass(frozen=True)
class LogEntry:
    sha: str
    author: str
    date: str  # ISO-8601 author date
    subject: str


def _run(args: list[str], cwd: str | Path) -> str:
    return _run_bytes(args, cwd).decode("utf-8", "replace")


def _run_bytes(args: list[str], cwd: str | Path) -> bytes:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitNotFoundError("git executable not found on PATH") from exc
    except NotADirectoryError as exc:
        raise NotAGitRepoError(f"not a directory: {cwd}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        if "not a git repository" in stderr:
            raise NotAGitRepoError(f"not a git repository: {cwd}")
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}): {stderr}")
    return proc.stdout


def _dir(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        raise NotAGitRepoError(f"path does not exist: {p}")
    return p if p.is_dir() else p.parent


def is_repo(path: str | Path) -> bool:
    """True if ``path`` is inside a git work tree."""
    try:
        return _run(["rev-parse", "--is-inside-work-tree"], _dir(path)).strip() == "true"
    except GitError:
        return False


def repo_root(path: str | Path) -> Path:
    """Absolute path of the work-tree root containing ``path``."""
    out = _run(["rev-parse", "--show-toplevel"], _dir(path)).strip()
    return Path(out).resolve()


def head_sha(path: str | Path) -> str:
    """Full SHA of HEAD. Raises GitError if the repo has no commits."""
    try:
        return _run(["rev-parse", "--verify", "HEAD^{commit}"], _dir(path)).strip()
    except NotAGitRepoError:
        raise
    except GitError as exc:
        raise GitError(f"repository at {path} has no commits (HEAD is unborn)") from exc


def commit_exists(repo: str | Path, commit: str) -> bool:
    """True if ``commit`` resolves to a commit object."""
    try:
        _run(["rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"], repo)
        return True
    except NotAGitRepoError:
        raise
    except GitError:
        return False


def show_file(repo: str | Path, commit: str, path: str) -> str:
    """Contents of ``path`` (repo-relative, POSIX) at ``commit``, decoded with
    ``text.decode_text`` (UTF-8 by default; UTF-16/32 recognised)."""
    rel = Path(path).as_posix()
    return decode_text(_run_bytes(["show", f"{commit}:{rel}"], repo))


def resolve_commit(repo: str | Path, rev: str) -> str:
    """Full SHA of the commit ``rev`` names. Raises GitError if it is not a commit."""
    return _run(["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"], repo).strip()


def ls_tree(repo: str | Path, commit: str) -> list[str]:
    """All file paths (repo-relative, POSIX) tracked at ``commit``."""
    out = _run(["ls-tree", "-r", "-z", "--name-only", f"{commit}^{{commit}}"], repo)
    return [p for p in out.split("\0") if p]


def log(
    repo: str | Path,
    path: str | None = None,
    max_count: int | None = None,
    rev: str = "HEAD",
) -> list[LogEntry]:
    """Commits reachable from ``rev``, newest first, optionally limited to ``path``."""
    sep, end = "\x1f", "\x1e"
    args = ["log", f"--format=%H{sep}%an{sep}%aI{sep}%s{end}"]
    if max_count is not None:
        args.append(f"--max-count={max_count}")
    args.append(rev)
    if path is not None:
        args += ["--", Path(path).as_posix()]
    out = _run(args, repo)
    entries = []
    for rec in out.split(end):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, author, date, subject = rec.split(sep, 3)
        entries.append(LogEntry(sha=sha, author=author, date=date, subject=subject))
    return entries


def is_tracked_and_clean(repo: str | Path, path: str) -> bool:
    """True if ``path`` is tracked and has no staged or unstaged changes vs HEAD."""
    rel = Path(path).as_posix()
    try:
        _run(["ls-files", "--error-unmatch", "--", rel], repo)
    except NotAGitRepoError:
        raise
    except GitError:
        return False
    status = _run(["status", "--porcelain", "--", rel], repo)
    return status.strip() == ""
