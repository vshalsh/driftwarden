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
    """Commits reachable from ``rev``, newest first, optionally limited to ``path``.

    Fields and records are NUL-separated (``-z``): a commit message cannot contain
    NUL, so no subject or author name can collide with the delimiters."""
    args = ["log", "-z", "--format=%H%x00%an%x00%aI%x00%s"]
    if max_count is not None:
        args.append(f"--max-count={max_count}")
    args.append(rev)
    if path is not None:
        args += ["--", Path(path).as_posix()]
    out = _run(args, repo)
    fields = out.split("\0")
    if fields and fields[-1] in ("", "\n"):
        fields.pop()
    if len(fields) % 4:
        raise GitError(f"git log: unexpected output ({len(fields)} fields)")
    return [
        LogEntry(sha=fields[i], author=fields[i + 1], date=fields[i + 2], subject=fields[i + 3])
        for i in range(0, len(fields), 4)
    ]


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


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str  # "100644", "100755", "120000" (symlink)
    sha: str
    size: int


def tree_entries(repo: str | Path, commit: str) -> list[TreeEntry]:
    """Every blob tracked at ``commit`` (submodules are not blobs and are skipped)."""
    out = _run_bytes(["ls-tree", "-r", "-z", "-l", "--full-tree", f"{commit}^{{commit}}"], repo)
    entries = []
    for rec in out.decode("utf-8", "replace").split("\0"):
        if not rec:
            continue
        meta, _, path = rec.partition("\t")
        mode, kind, sha, size = meta.split()
        if kind == "blob":
            entries.append(TreeEntry(path, mode, sha, int(size)))
    return entries


def read_blobs(repo: str | Path, shas: list[str]) -> dict[str, bytes]:
    """Raw contents of the given blob objects (one ``git cat-file --batch`` call).

    The bytes are exactly what ``git show <commit>:<path>`` prints: no filters
    and no ``export-subst`` (unlike ``git archive``).
    """
    unique = list(dict.fromkeys(shas))
    if not unique:
        return {}
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=str(repo),
            input=("\n".join(unique) + "\n").encode(),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitNotFoundError("git executable not found on PATH") from exc
    if proc.returncode != 0:
        raise GitError(f"git cat-file --batch failed: {proc.stderr.decode('utf-8', 'replace')}")
    data, pos, blobs = proc.stdout, 0, {}
    for _ in unique:
        nl = data.index(b"\n", pos)
        parts = data[pos:nl].decode("utf-8", "replace").split()
        if len(parts) != 3:
            raise GitError(f"git cat-file: unexpected header {parts!r}")
        sha, _kind, size = parts
        start = nl + 1
        blobs[sha] = data[start : start + int(size)]
        pos = start + int(size) + 1  # each object is followed by a newline
    return blobs


def parents(repo: str | Path, commit: str) -> list[str]:
    """Full SHAs of ``commit``'s parents (empty for a root commit)."""
    out = _run(["rev-list", "--parents", "-n", "1", f"{commit}^{{commit}}"], repo).split()
    return out[1:]


def last_commit_touching(repo: str | Path, rev: str, path: str) -> str | None:
    """Newest commit reachable from ``rev`` that changed ``path``, or None."""
    out = _run(["log", "-1", "--format=%H", rev, "--", Path(path).as_posix()], repo).strip()
    return out or None


def blob_at(repo: str | Path, commit: str, path: str) -> str | None:
    """Blob SHA of ``path`` at ``commit``, or None when the path is not a file there."""
    rel = Path(path).as_posix()
    out = _run_bytes(["ls-tree", "-z", f"{commit}^{{commit}}", "--", rel], repo)
    for rec in out.decode("utf-8", "replace").split("\0"):
        meta, _, name = rec.partition("\t")
        parts = meta.split()
        if name == rel and len(parts) == 3 and parts[1] == "blob" and parts[0] != "120000":
            return parts[2]
    return None


def is_ancestor(repo: str | Path, ancestor: str, descendant: str) -> bool:
    """True if ``ancestor`` is ``descendant`` or one of its ancestors (False on any error)."""
    try:
        _run(["merge-base", "--is-ancestor", ancestor, descendant], repo)
        return True
    except NotAGitRepoError:
        raise
    except GitError:
        return False


def rev_list_topo(repo: str | Path, tip: str) -> list[str]:
    """Every commit reachable from ``tip``, in topological order, ancestors first."""
    out = _run(["rev-list", "--topo-order", "--reverse", f"{tip}^{{commit}}"], repo)
    return out.split()


def shallow_boundary(repo: str | Path) -> frozenset[str]:
    """Commits whose parents are missing because the clone is shallow (the contents of
    ``.git/shallow``); empty for a complete repository."""
    if _run(["rev-parse", "--is-shallow-repository"], repo).strip() != "true":
        return frozenset()
    rel = _run(["rev-parse", "--git-path", "shallow"], repo).strip()
    p = Path(rel) if Path(rel).is_absolute() else Path(repo) / rel
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    lines = text.split("\n")  # git's format; not splitlines() (L-028 D2 audit)
    return frozenset(line.strip() for line in lines if line.strip())


def list_dir(repo: str | Path, commit: str, directory: str) -> list[str]:
    """Repo-relative paths of the blobs directly inside ``directory`` ("" = root) at
    ``commit`` (not recursive)."""
    args = ["ls-tree", "-z", f"{commit}^{{commit}}"]
    if directory:
        args += ["--", directory.rstrip("/") + "/"]
    out = _run_bytes(args, repo).decode("utf-8", "replace")
    paths = []
    for rec in out.split("\0"):
        meta, _, name = rec.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            paths.append(name)
    return paths


def commit_time(repo: str | Path, commit: str) -> int:
    """Committer timestamp (Unix seconds) of ``commit``."""
    return int(_run(["show", "-s", "--format=%ct", f"{commit}^{{commit}}"], repo).strip())


def is_clean(repo: str | Path) -> bool:
    """True if no tracked file has staged or unstaged changes (untracked files ignored)."""
    return _run(["status", "--porcelain", "--untracked-files=no"], repo).strip() == ""
