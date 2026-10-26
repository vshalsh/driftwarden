"""L-003: file walk, ignore rules, language detection, binaries, unicode, symlinks."""

from __future__ import annotations

import os
import sys

import pytest

from conftest import git
from driftwarden.index import build_index, detect_language, index_files
from driftwarden.index.files import GitIgnore, is_binary


def paths(ix):
    return {f.path for f in ix}


def _symlink(link, target, is_dir=False):
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except (OSError, NotImplementedError):  # pragma: no cover - e.g. Windows without dev mode
        pytest.skip("symlinks not supported on this platform")


# --------------------------------------------------------------------------- language


@pytest.mark.parametrize(
    ("path", "lang"),
    [
        ("a/b.py", "python"),
        ("x.pyi", "python"),
        ("x.ts", "typescript"),
        ("x.d.ts", "typescript"),
        ("x.tsx", "typescript"),
        ("x.mjs", "javascript"),
        ("X.JSX", "javascript"),
        ("Main.java", "java"),
        ("main.go", "go"),
        ("go.mod", "go-mod"),
        ("Dockerfile", "dockerfile"),
        ("Dockerfile.prod", "dockerfile"),
        ("api.dockerfile", "dockerfile"),
        ("pom.xml", "maven"),
        ("main.tf", "terraform"),
        ("ci.yml", "yaml"),
        ("README", None),
        (".bashrc", None),
        ("weird.unknownext", None),
    ],
)
def test_detect_language_by_name(path, lang):
    assert detect_language(path) == lang


@pytest.mark.parametrize(
    ("head", "lang"),
    [
        (b"#!/usr/bin/env python3\n", "python"),
        (b"#!/usr/bin/python3.12\n", "python"),
        (b"#!/usr/bin/env node\n", "javascript"),
        (b"#!/bin/bash\n", "shell"),
        (b"#!/usr/bin/env perl\n", None),
        (b"no shebang", None),
    ],
)
def test_detect_language_by_shebang(head, lang):
    assert detect_language("bin/tool", head) == lang


def test_shebang_does_not_override_extension():
    assert detect_language("x.js", b"#!/usr/bin/env python\n") == "javascript"


def test_is_binary():
    assert is_binary(b"abc\x00def")
    assert is_binary(b"", "logo.PNG")
    assert not is_binary("plain é text".encode())


# --------------------------------------------------------------------------- git walk


def test_git_mode_honours_gitignore_and_lists_untracked(make_repo):
    repo = make_repo({"src/a.py": "", "forced.log": "tracked before the ignore rule"})
    (repo / ".gitignore").write_text("*.log\nbuild/\n!keep.log\n")
    git(repo, "add", ".gitignore")
    (repo / "debug.log").write_text("x")
    (repo / "keep.log").write_text("x")
    (repo / "build").mkdir()
    (repo / "build" / "out.py").write_text("x")
    (repo / "new.py").write_text("untracked, not ignored")
    ix = index_files(repo)
    assert ix.source == "git"
    assert paths(ix) == {".gitignore", "src/a.py", "forced.log", "keep.log", "new.py"}
    assert ix.get("new.py").tracked is False
    assert ix.get("src/a.py").tracked is True
    # tracked-only listing
    assert paths(index_files(repo, untracked=False)) == {".gitignore", "src/a.py", "forced.log"}


def test_git_mode_skips_deleted_and_nested_repo(make_repo):
    repo = make_repo({"a.py": "", "gone.py": ""})
    (repo / "gone.py").unlink()
    nested = repo / "vendored"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "x.py").write_text("")
    ix = index_files(repo)
    assert paths(ix) == {"a.py"}
    reasons = dict(ix.skipped)
    assert "missing" in reasons["gone.py"]
    assert any(p.rstrip("/") == "vendored" for p in reasons)


def test_index_from_subdirectory_is_relative_to_it(make_repo):
    repo = make_repo({"top.py": "", "sub/inner.py": "import os\n"})
    ix = build_index(repo / "sub")
    assert paths(ix.files) == {"inner.py"}
    assert ix.imports.edges[0].source == "inner.py"


def test_config_excludes_apply(make_repo):
    repo = make_repo({"a.py": "", "node_modules/x/index.js": "", "gen/b.py": ""})
    assert paths(index_files(repo)) == {"a.py", "gen/b.py"}  # DEFAULT_EXCLUDES
    assert paths(index_files(repo, ["gen/**"])) == {"a.py", "node_modules/x/index.js"}


def test_non_directory_root_rejected(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        index_files(f)


# --------------------------------------------------------------------------- gitignore rules


GITIGNORE = """\
# comment
*.log
!important.log
/rootonly.txt
build/
docs/**/*.tmp
**/cache
a/**/z.txt
\\#hash.txt
trailing.txt   \n
"""

CANDIDATES = [
    "x.log",
    "important.log",
    "deep/x.log",
    "rootonly.txt",
    "sub/rootonly.txt",
    "build/out.o",
    "sub/build/out.o",
    "docs/a.tmp",
    "docs/x/y/a.tmp",
    "src/a.tmp",
    "cache/c.bin",
    "x/cache/c.bin",
    "a/z.txt",
    "a/b/c/z.txt",
    "#hash.txt",
    "trailing.txt",
    "nested/local.txt",
    "nested/other.txt",
    "nested/sub/local.txt",
    "keep.py",
]


def test_walk_matches_git_check_ignore(tmp_path):
    """The stdlib walk must list exactly what ``git ls-files --others`` lists."""
    root = tmp_path / "w"
    root.mkdir()
    (root / ".gitignore").write_text(GITIGNORE)
    (root / "nested").mkdir()
    (root / "nested" / ".gitignore").write_text("local.txt\n")
    for rel in CANDIDATES:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    walk = paths(index_files(root, exclude=[]))
    git(root, "init", "-q")
    git(root, "config", "core.excludesFile", os.devnull)
    via_git = index_files(root, exclude=[])
    assert via_git.source == "git"
    assert walk == paths(via_git)
    assert "important.log" in walk and "x.log" not in walk and "keep.py" in walk


@pytest.mark.parametrize(
    ("pattern", "path", "is_dir", "ignored"),
    [
        ("*.py", "a/b.py", False, True),
        ("/a.py", "a.py", False, True),
        ("/a.py", "x/a.py", False, None),
        ("d/", "d", True, True),
        ("d/", "d", False, None),
        ("a/*/c", "a/b/c", False, True),
        ("a/*/c", "a/b/x/c", False, None),
        ("**/foo", "x/y/foo", False, True),
        ("foo/**", "foo/x/y", False, True),
        ("[ab].txt", "b.txt", False, True),
        ("[!ab].txt", "a.txt", False, None),
        ("?.md", "x.md", False, True),
    ],
)
def test_gitignore_patterns(pattern, path, is_dir, ignored):
    assert GitIgnore([pattern]).match(path, is_dir) is ignored


def test_gitignore_in_subdirectory_is_scoped():
    gi = GitIgnore(["*.txt"], base="sub")
    assert gi.match("sub/a.txt", False) is True
    assert gi.match("other/a.txt", False) is None


# ------------------------------------------------------------- binary, unicode, symlinks


def test_binary_files_listed_but_unclassified(make_repo):
    repo = make_repo({"a.py": "import os\n"})
    (repo / "img.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    (repo / "data.py").write_bytes(b"x = 1\n\x00\xff\xfe")  # .py name, binary content
    (repo / "empty.py").write_bytes(b"")
    ix = index_files(repo)
    assert ix.get("img.png").is_binary and ix.get("img.png").language is None
    assert ix.get("data.py").is_binary and not ix.get("data.py").parseable
    assert not ix.get("empty.py").is_binary and ix.get("empty.py").language == "python"
    assert ix.languages() == {"python": 2}


@pytest.mark.parametrize("use_git", [True, False], ids=["git", "walk"])
def test_unicode_file_names(tmp_path, use_git):
    root = tmp_path / "uni"
    names = ["données.py", "日本語/モジュール.py", "emoji_🚀.js", "space name.ts"]
    for n in names:
        p = root / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("import os\n" if n.endswith(".py") else "import 'react';\n")
    if use_git:
        git(root, "init", "-q")
        git(root, "config", "core.quotePath", "true")  # -z output must ignore this
    ix = build_index(root)
    assert ix.files.source == ("git" if use_git else "walk")
    assert paths(ix.files) == set(names)
    assert {e.source for e in ix.imports} == set(names)


@pytest.mark.skipif(sys.platform in ("darwin", "win32"), reason="needs a byte-path filesystem")
def test_non_utf8_file_name_round_trips(tmp_path):
    root = tmp_path / "bytes"
    root.mkdir()
    raw = os.path.join(os.fsencode(root), b"caf\xe9.py")
    try:
        with open(raw, "wb") as fh:
            fh.write(b"import os\n")
    except OSError:  # pragma: no cover
        pytest.skip("filesystem rejects non-UTF-8 names")
    for use_git in (False, True):
        if use_git:
            git(root, "init", "-q")
        ix = build_index(root)
        (entry,) = list(ix.files)
        assert os.fsencode(entry.path) == b"caf\xe9.py"
        assert ix.imports.edges[0].module == "os"


@pytest.mark.parametrize("use_git", [True, False], ids=["git", "walk"])
def test_symlinks_listed_not_followed(tmp_path, use_git):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import secret_module\n")
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "real.py").write_text("import os\n")
    _symlink(root / "alias.py", "pkg/real.py")
    _symlink(root / "leak.py", outside / "secret.py")
    _symlink(root / "loop", ".", is_dir=True)  # would recurse forever if followed
    _symlink(root / "outdir", outside, is_dir=True)
    _symlink(root / "broken.py", "nope.py")
    if use_git:
        git(root, "init", "-q")
        git(root, "add", "-A")
    ix = build_index(root, None)
    got = {f.path: f for f in ix.files}
    assert set(got) == {"pkg/real.py", "alias.py", "leak.py", "loop", "outdir", "broken.py"}
    for name in ("alias.py", "leak.py", "loop", "outdir", "broken.py"):
        assert got[name].is_symlink and not got[name].parseable
    assert got["alias.py"].link_target == "pkg/real.py"
    assert not got["pkg/real.py"].is_symlink
    modules = {e.module for e in ix.imports}
    assert modules == {"os"}  # nothing read through the links
    assert {e.source for e in ix.imports} == {"pkg/real.py"}


def test_fixture_repos_index_cleanly(index_fixture):
    for name in ("python", "js", "java", "go"):
        ix = build_index(index_fixture(name))
        assert ix.files.skipped == []
        assert len(ix.imports) > 0
    langs = build_index(index_fixture("js")).files.languages()
    assert langs["typescript"] >= 6 and langs["javascript"] >= 4
