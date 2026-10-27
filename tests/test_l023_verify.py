"""L-023: pinned commits and canonical paths in ``verify_source_quote`` (G1/G2) and
``verify_dependency`` (G3), and the "never raises for bad provenance" contract.

Decisions under test (module docstring of grounding/verify.py):
* commit: a full 40/64-hex SHA in lowercase that git resolves, as a commit, to
  itself, or the WORKTREE sentinel. Uppercase hex is rejected, not normalised.
* path: canonical repo-relative POSIX, compared byte-exact (no NFC folding, no
  whitespace trimming, no case folding).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import unicodedata
from pathlib import Path

import pytest

from conftest import git
from driftwarden.claims import structure_scan
from driftwarden.discover.adr import scan_adrs
from driftwarden.git import NotAGitRepoError
from driftwarden.grounding.verify import (
    commit_problem,
    path_problem,
    verify_dependency,
    verify_source_quote,
)
from driftwarden.judge import Judge
from driftwarden.models import WORKTREE, DependencyRef, Provenance

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def _repo(tmp_path: Path, files: dict[str, str], *, sha256: bool = False) -> tuple[Path, str]:
    repo = tmp_path / ("r256" if sha256 else "r")
    repo.mkdir()
    fmt = ["--object-format=sha256"] if sha256 else []
    git(repo, "init", "-q", "-b", "main", *fmt)
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "core.autocrlf", "false")
    git(repo, "config", "core.precomposeunicode", "false")
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode("utf-8"))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "c")
    return repo, git(repo, "rev-parse", "HEAD").strip()


def _prov(path: str, commit: str, quote: str = "import pymongo") -> Provenance:
    return Provenance(path=path, line_start=1, line_end=1, commit=commit, quote=quote)


@pytest.fixture
def ab(tmp_path):
    repo, sha = _repo(tmp_path, {"a/b.py": "import pymongo\n"})
    git(repo, "tag", "v1")
    git(repo, "tag", "-a", "v1a", "-m", "annotated")
    return repo, sha


# ---------------------------------------------------------------- positives stay positive


def test_pinned_sha_and_worktree_verify(ab):
    repo, sha = ab
    assert verify_source_quote(repo, _prov("a/b.py", sha)).status == "VERIFIED"
    assert verify_source_quote(repo, _prov("a/b.py", WORKTREE)).status == "VERIFIED"
    assert commit_problem(repo, sha) is None and commit_problem(repo, WORKTREE) is None
    assert path_problem("a/b.py") is None


# ---------------------------------------------------------------- D1: commits


def _bad_commits(repo: Path, sha: str) -> list[str]:
    tag_obj = git(repo, "rev-parse", "v1a").strip()
    assert tag_obj != sha and len(tag_obj) == 40
    return [
        "HEAD",
        "@",
        "main",
        "refs/heads/main",
        "v1",
        "v1a",
        tag_obj,  # full 40-hex, but the annotated tag object, not the commit
        sha[:7],
        sha[:12],
        sha[:39],
        "HEAD~0",
        "HEAD^0",
        "main^{commit}",
        sha + "^{commit}",
        sha + "~0",
        "main@{0}",
        sha.upper(),
        sha[:20] + sha[20:].upper(),
        " " + sha,
        sha + " ",
        sha + "\n",
        sha + "\x00",
        "worktree",
        "WORKTREE ",
        "",
        "0" * 40,
        "0" * 64,
        sha + "0" * 24,  # 64 hex in a SHA-1 repo
    ]


def test_moving_or_derived_commits_are_mismatch(ab):
    repo, sha = ab
    for c in _bad_commits(repo, sha):
        r = verify_source_quote(repo, _prov("a/b.py", c))
        assert r.status == "MISMATCH", c
        assert "unknown commit" in r.reason, (c, r.reason)
        assert commit_problem(repo, c) is not None, c


def test_dependency_uses_the_same_commit_rule(tmp_path):
    repo, sha = _repo(tmp_path, {"requirements.txt": "pymongo==4.0\n"})
    git(repo, "tag", "-a", "v1a", "-m", "annotated")
    dep = DependencyRef(
        package="pymongo", version_spec="==4.0", manifest_path="requirements.txt", commit=sha
    )
    assert verify_dependency(repo, dep).status == "VERIFIED"
    for c in _bad_commits(repo, sha):
        if not c.strip():
            continue  # "no commit given"
        r = verify_dependency(repo, dep.model_copy(update={"commit": c}))
        assert r.status == "MISMATCH", c


def test_uppercase_sha_is_rejected_not_normalised(ab):
    """Decision: reject. git prints lowercase, the judge compares byte for byte, and
    the ledger record must round-trip unchanged; normalising would let two spellings
    of one commit verify."""
    repo, sha = ab
    r = verify_source_quote(repo, _prov("a/b.py", sha.upper()))
    assert r.status == "MISMATCH" and "lowercase" in r.reason


# ---------------------------------------------------------------- D1: paths

BAD_PATHS = [
    "a/b.py/",
    "./a/b.py",
    "a//b.py",
    "a/./b.py",
    "a/../a/b.py",
    "/a/b.py",
    "a\\b.py",  # Windows separator
    "a\\\\b.py",
    ".\\a\\b.py",
    "C:\\repo\\a\\b.py",
    "a/b.py\x00",
    "a\x00/b.py",
    "a/b.py\n",
    "a/\tb.py",
    "a/b.py\r",
    "a/b\u2028.py",
    "a/b\u202e.py",
    "a/b\ud800.py",
    ".git/config",
    "a/.GIT/x",
    "",
    ".",
    "..",
    "/",
]


@pytest.mark.parametrize("path", BAD_PATHS, ids=[repr(p) for p in BAD_PATHS])
@pytest.mark.parametrize("mode", ["sha", "worktree"])
def test_non_canonical_paths_are_mismatch(ab, path, mode):
    repo, sha = ab
    commit = sha if mode == "sha" else WORKTREE
    r = verify_source_quote(repo, _prov(path, commit))
    assert r.status == "MISMATCH"
    assert "not repo-relative" in r.reason, r.reason
    assert path_problem(path) is not None


def test_dependency_uses_the_same_path_rule(tmp_path):
    repo, sha = _repo(tmp_path, {"requirements.txt": "pymongo==4.0\n"})
    dep = DependencyRef(package="pymongo", manifest_path="requirements.txt", commit=sha)
    for p in ("./requirements.txt", "requirements.txt/", ".\\requirements.txt", "r\x00.txt"):
        r = verify_dependency(repo, dep.model_copy(update={"manifest_path": p}))
        assert r.status == "MISMATCH" and "not repo-relative" in r.reason, p


@pytest.mark.parametrize("mode", ["sha", "worktree"])
def test_path_whitespace_and_case_are_not_trimmed_or_folded(tmp_path, mode):
    """Byte-exact paths: 'a.py ' is a different (legal) git path from 'a.py'."""
    repo, sha = _repo(tmp_path, {"a.py": "x = 1\n", "b.py ": "y = 2\n"})
    commit = sha if mode == "sha" else WORKTREE
    ok = verify_source_quote(repo, _prov("b.py ", commit, "y = 2"))
    assert ok.status == "VERIFIED"
    for path, quote in (
        ("a.py ", "x = 1"),
        (" a.py", "x = 1"),
        ("b.py", "y = 2"),
        ("A.py", "x = 1"),
    ):
        assert verify_source_quote(repo, _prov(path, commit, quote)).status == "MISMATCH", path


@pytest.mark.parametrize("mode", ["sha", "worktree"])
@pytest.mark.parametrize("stored", ["NFC", "NFD"])
def test_unicode_paths_are_byte_exact(tmp_path, mode, stored):
    """A file name is matched as stored: the other normalisation form is MISMATCH
    (no NFC folding), on both the commit and the working-tree path."""
    name = unicodedata.normalize(stored, "docs/café-ü.md")
    other = unicodedata.normalize("NFD" if stored == "NFC" else "NFC", name)
    assert name != other
    repo, sha = _repo(tmp_path, {name: "Use café.\n"})
    if not (repo / name).exists() or (repo / other).exists():
        pytest.skip("file system normalises Unicode file names")
    commit = sha if mode == "sha" else WORKTREE
    assert verify_source_quote(repo, _prov(name, commit, "Use café.")).status == "VERIFIED"
    r = verify_source_quote(repo, _prov(other, commit, "Use café."))
    assert r.status == "MISMATCH" and "file missing" in r.reason


def test_worktree_lookup_matches_listing_not_the_file_system(tmp_path, monkeypatch):
    """On a case-insensitive file system 'A/B.py' would open 'a/b.py', so WORKTREE
    lookups must match each segment against the directory listing instead of
    asking the file system whether the spelling opens."""
    repo, _ = _repo(tmp_path, {"a/b.py": "import pymongo\n"})
    real_listdir = os.listdir
    seen: list[str] = []

    def listdir(p):
        seen.append(str(p))
        return real_listdir(p)

    monkeypatch.setattr(os, "listdir", listdir)
    assert verify_source_quote(repo, _prov("a/b.py", WORKTREE)).status == "VERIFIED"
    assert seen, "WORKTREE lookups must go through the directory listing"
    assert verify_source_quote(repo, _prov("A/b.py", WORKTREE)).status == "MISMATCH"
    assert verify_source_quote(repo, _prov("a/B.py", WORKTREE)).status == "MISMATCH"


def test_worktree_symlink_out_of_the_repo_is_mismatch(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("import pymongo\n", encoding="utf-8")
    repo, _ = _repo(tmp_path, {"a/b.py": "import pymongo\n"})
    try:
        (repo / "a" / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not supported")
    r = verify_source_quote(repo, _prov("a/link.py", WORKTREE))
    assert r.status == "MISMATCH" and "file missing in working tree" in r.reason


# ---------------------------------------------------------------- SHA-256 repositories


@pytest.fixture
def repo256(tmp_path):
    try:
        repo, sha = _repo(
            tmp_path, {"a/b.py": "import pymongo\n", "requirements.txt": "x==1\n"}, sha256=True
        )
    except subprocess.CalledProcessError:
        pytest.skip("git without SHA-256 object format support")
    assert len(sha) == 64
    return repo, sha


def test_sha256_full_id_verifies(repo256):
    repo, sha = repo256
    assert verify_source_quote(repo, _prov("a/b.py", sha)).status == "VERIFIED"
    dep = DependencyRef(
        package="x", version_spec="==1", manifest_path="requirements.txt", commit=sha
    )
    assert verify_dependency(repo, dep).status == "VERIFIED"


def test_sha256_prefixes_and_spellings_are_mismatch(repo256):
    """A 40-hex string is a valid *abbreviation* in a SHA-256 repository: it looks
    like a full SHA-1 but must not verify."""
    repo, sha = repo256
    for c in (sha[:40], sha[:12], sha.upper(), sha[:63], sha + "0"):
        r = verify_source_quote(repo, _prov("a/b.py", c))
        assert r.status == "MISMATCH" and "unknown commit" in r.reason, c
    dep = DependencyRef(
        package="x", version_spec="==1", manifest_path="requirements.txt", commit=sha[:40]
    )
    assert verify_dependency(repo, dep).status == "MISMATCH"


# ---------------------------------------------------------------- D7: never raises


WEIRD = [
    "\x00",
    "a\x00.py",
    "\ud800",
    "\udcff",
    "\x7f",
    "a" * 5000,
    "\u0000" * 3,
    "é\u0301",
    "-h",
    "--output=/tmp/x",
    ":(top)a/b.py",
    "a/b.py:",
]


def test_never_raises_on_hostile_strings(ab):
    repo, sha = ab
    for w in WEIRD:
        for prov in (
            _prov(w, sha),
            _prov("a/b.py", w),
            _prov("a/b.py", sha, quote=w),
            _prov(w, WORKTREE),
            _prov(w, w, quote=w),
        ):
            r = verify_source_quote(repo, prov)
            assert r.status == "MISMATCH", (w, prov)
        dep = DependencyRef(package=w or "p", manifest_path=w, commit=w)
        assert verify_dependency(repo, dep).status == "MISMATCH", w
        dep = DependencyRef(package="p", manifest_path="a/b.py", commit=w)
        assert verify_dependency(repo, dep).status == "MISMATCH", w


def test_never_raises_on_unvalidated_models(ab):
    """model_construct skips pydantic validation, as a careless caller might."""
    repo, sha = ab
    cases = [
        Provenance.model_construct(path=None, line_start=1, line_end=1, commit=sha, quote="x"),
        Provenance.model_construct(path="a/b.py", line_start=1, line_end=1, commit=None, quote="x"),
        Provenance.model_construct(
            path="a/b.py", line_start="1", line_end=1, commit=sha, quote="x"
        ),
        Provenance.model_construct(path="a/b.py", line_start=1, line_end=1, commit=sha, quote=None),
        Provenance.model_construct(path=b"a/b.py", line_start=1, line_end=1, commit=sha, quote="x"),
        Provenance.model_construct(
            path="a/b.py", line_start=1, line_end=1, commit=sha.encode(), quote="x"
        ),
    ]
    for prov in cases:
        assert verify_source_quote(repo, prov).status == "MISMATCH", prov


def test_unexpected_error_becomes_mismatch(ab, monkeypatch):
    from driftwarden import git as dw_git

    repo, sha = ab

    def boom(*_a, **_k):
        raise ValueError("embedded null byte")

    monkeypatch.setattr(dw_git, "show_file", boom)
    r = verify_source_quote(repo, _prov("a/b.py", sha))
    assert r.status == "MISMATCH" and "could not verify (ValueError" in r.reason
    dep = DependencyRef(package="p", manifest_path="a/b.py", commit=sha)
    r = verify_dependency(repo, dep)
    assert r.status == "MISMATCH" and "could not verify (ValueError" in r.reason


def test_not_a_git_repo_still_raises(tmp_path, ab):
    _repo_path, sha = ab
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(NotAGitRepoError):
        verify_source_quote(plain, _prov("a/b.py", sha))


def test_git_is_not_called_for_rejected_provenance(ab, monkeypatch):
    """Validation happens before git: a rejected commit/path never reaches subprocess."""
    repo, sha = ab
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spy(args, *a, **k):
        calls.append(list(args))
        return real_run(args, *a, **k)

    monkeypatch.setattr(subprocess, "run", spy)
    verify_source_quote(repo, _prov("a/b.py", "HEAD"))
    verify_source_quote(repo, _prov("a\x00.py", sha))
    verify_source_quote(repo, _prov("./a/b.py", sha))
    assert all("rev-parse" in c and "--show-toplevel" in c for c in calls), calls


# ---------------------------------------------------------------- callers pass pinned provenance


def _copy_commit(tmp_path: Path, src: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(src, repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")
    return repo


def test_adr_claim_and_judge_provenance_is_pinned_and_canonical(tmp_path):
    """Audit of the callers: discover/adr.py (Decision.source), claims/* (Claim.source)
    and judge/* (Evidence.ref) emit full SHAs and canonical paths, so they all still
    verify after L-023; the judge resolves 'HEAD' to a full SHA at creation time."""
    repo = _copy_commit(tmp_path, FIXTURES / "judge_repos" / "pyshop", "pyshop")
    head = git(repo, "rev-parse", "HEAD").strip()
    decisions = scan_adrs(repo).decisions
    claims = [c for s in structure_scan(decisions, repo, mode="offline") for c in s.claims]
    verdicts = Judge(repo, commit="HEAD", mode="offline").judge_all(claims)
    provs = [d.source for d in decisions] + [c.source for c in claims]
    provs += [ev.ref for v in verdicts for ev in v.evidence]
    assert decisions and claims and any(v.evidence for v in verdicts)
    for p in provs:
        assert p.commit == head, p
        assert path_problem(p.path) is None, p
        assert verify_source_quote(repo, p).status == "VERIFIED", p
    for v in verdicts:
        assert v.commit == head


def test_worktree_adr_provenance_still_verifies(tmp_path):
    repo = _copy_commit(tmp_path, FIXTURES / "adr_repos" / "basic", "basic")
    edited = repo / "docs" / "adr" / "0002-use-postgresql.md"
    edited.write_text(edited.read_text(encoding="utf-8") + "\nEdited.\n", encoding="utf-8")
    (repo / "docs" / "adr" / "0099-untracked-café.md").write_text(
        "# 99. Untracked café\n\n## Status\n\nAccepted\n\n## Decision\n\nWe use café.\n",
        encoding="utf-8",
    )
    decisions = scan_adrs(repo).decisions
    assert any(d.source.commit == WORKTREE for d in decisions)
    for d in decisions:
        assert verify_source_quote(repo, d.source).status == "VERIFIED", d.source
