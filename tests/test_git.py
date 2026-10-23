from __future__ import annotations

import pytest

from conftest import git
from driftwarden import git as dwgit


def test_not_a_repo(tmp_path):
    assert dwgit.is_repo(tmp_path) is False
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.repo_root(tmp_path)
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.head_sha(tmp_path)


def test_missing_path(tmp_path):
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.repo_root(tmp_path / "nope")


def test_empty_repo_has_no_head(make_repo):
    repo = make_repo()
    assert dwgit.is_repo(repo)
    with pytest.raises(dwgit.GitError, match="no commits"):
        dwgit.head_sha(repo)


def test_root_head_show_log(make_repo):
    repo = make_repo({"docs/a.md": "hello\nworld\n"})
    assert dwgit.repo_root(repo / "docs") == repo.resolve()
    sha = dwgit.head_sha(repo)
    assert len(sha) == 40
    assert dwgit.commit_exists(repo, sha)
    assert not dwgit.commit_exists(repo, "0" * 40)
    assert dwgit.show_file(repo, sha, "docs/a.md") == "hello\nworld\n"

    (repo / "docs/a.md").write_text("changed\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "second | with pipe")
    entries = dwgit.log(repo)
    assert [e.subject for e in entries] == ["second | with pipe", "initial"]
    assert entries[1].sha == sha
    assert len(dwgit.log(repo, path="docs/a.md", max_count=1)) == 1
    # Old content is still readable at the old commit.
    assert dwgit.show_file(repo, sha, "docs/a.md") == "hello\nworld\n"


def test_show_file_missing(make_repo):
    repo = make_repo({"a.md": "x\n"})
    with pytest.raises(dwgit.GitError):
        dwgit.show_file(repo, dwgit.head_sha(repo), "b.md")


def test_is_tracked_and_clean(make_repo):
    repo = make_repo({"a.md": "x\n"})
    assert dwgit.is_tracked_and_clean(repo, "a.md")
    (repo / "a.md").write_text("y\n", encoding="utf-8")
    assert not dwgit.is_tracked_and_clean(repo, "a.md")
    (repo / "new.md").write_text("z\n", encoding="utf-8")
    assert not dwgit.is_tracked_and_clean(repo, "new.md")
