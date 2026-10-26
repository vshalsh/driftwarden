"""L-003 acceptance: indexing a generated 5,000-file repository takes < 30 s."""

from __future__ import annotations

import time

import pytest

from conftest import git
from driftwarden.index import build_index

N_FILES = 5000
BUDGET_S = 30.0
BODY = "".join(f"# filler line {i} with some text to make the file realistic\n" for i in range(40))


def _generate(root):
    """Write a mixed-language repo of exactly N_FILES files; return expected local edges."""
    root.mkdir()
    files: dict[str, str | bytes] = {}
    expected_local = 0
    n_py, n_ts, n_java, n_go = 1600, 1400, 1000, 900
    files["go.mod"] = "module example.com/gen\n\ngo 1.22\n"
    for i in range(n_py):
        pkg = f"src/gen/p{i % 40}"
        files[f"{pkg}/__init__.py"] = ""
        prev = (i - 1) % n_py
        files[f"{pkg}/m{i}.py"] = (
            f"import os\nimport requests\nfrom gen.p{prev % 40} import m{prev}\n"
            f"from . import m{(i + 40) % n_py}\n" + BODY
        )
        expected_local += 2
    for i in range(n_ts):
        prev = (i - 1) % n_ts
        files[f"web/src/c{i % 30}/f{i}.ts"] = (
            f"import React from 'react';\nimport {{ x }} from '../c{prev % 30}/f{prev}';\n"
            "import fs from 'node:fs';\n" + BODY.replace("#", "//")
        )
        expected_local += 1
    for i in range(n_java):
        prev = (i - 1) % n_java
        files[f"java/src/com/gen/k{i % 25}/C{i}.java"] = (
            f"package com.gen.k{i % 25};\n\nimport java.util.List;\n"
            f"import com.gen.k{prev % 25}.C{prev};\nimport org.slf4j.Logger;\n"
            + BODY.replace("#", "//")
            + f"public class C{i} {{}}\n"
        )
        expected_local += 1
    for i in range(n_go):
        d = f"pkg/g{i % 50}"
        files[f"{d}/f{i}.go"] = (
            f'package g{i % 50}\n\nimport (\n\t"fmt"\n\t"example.com/gen/pkg/g{(i + 1) % 50}"\n'
            '\t"github.com/stretchr/testify/assert"\n)\n' + BODY.replace("#", "//")
        )
        expected_local += 1
    i = 0
    while len(files) < N_FILES:
        if i % 3 == 0:
            files[f"assets/img{i}.png"] = b"\x89PNG\r\n\x1a\n\x00\x00" + bytes(range(256))
        else:
            files[f"docs/n{i}.md"] = "# note\n" + BODY
        i += 1
    assert len(files) == N_FILES
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return expected_local


@pytest.fixture(scope="module")
def big_repo(tmp_path_factory):
    root = tmp_path_factory.mktemp("perf") / "gen"
    expected = _generate(root)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "generated")
    return root, expected


def test_index_5k_files_under_30s(big_repo):
    root, expected_local = big_repo
    t0 = time.perf_counter()
    ix = build_index(root)
    elapsed = time.perf_counter() - t0
    print(f"\nindexed {len(ix.files)} files, {len(ix.imports)} edges in {elapsed:.2f}s")
    assert ix.files.source == "git"
    assert len(ix.files) == N_FILES
    assert elapsed < BUDGET_S
    local = [e for e in ix.imports if e.category == "local"]
    assert len(local) == expected_local
    assert not [e for e in ix.imports if e.category == "unresolved"]
    assert set(ix.imports.external_packages()) == {
        "requests",
        "react",
        "org.slf4j",
        "github.com/stretchr/testify",
    }
    assert ix.imports.errors == []


def test_index_5k_files_walk_mode_under_30s(big_repo):
    from driftwarden.index import build_import_graph, index_files

    root, expected_local = big_repo
    t0 = time.perf_counter()
    files = index_files(root, use_git=False)
    graph = build_import_graph(files)
    elapsed = time.perf_counter() - t0
    assert files.source == "walk"
    assert len(files) == N_FILES  # the walk does not list .git/
    assert sum(e.category == "local" for e in graph) == expected_local
    assert elapsed < BUDGET_S
