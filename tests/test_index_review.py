"""L-003: regressions for the PR #9 review findings (R1-R7)."""

from __future__ import annotations

import os
import time

import pytest

from conftest import git
from driftwarden.index import build_index, index_files
from driftwarden.index.imports import extract_java, extract_js, extract_python


def mk(tmp_path, files, *, use_git=True, name="r"):
    root = tmp_path / name
    root.mkdir()
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    if use_git:
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "commit.gpgsign", "false")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "init")
    return root


def targets(root, source):
    return {(e.module, e.category, e.target) for e in build_index(root).imports.edges_from(source)}


# --------------------------------------------------------------- R1 + R2: Go package roots


def test_r1_go_root_package_is_a_local_dependency(tmp_path):
    root = mk(
        tmp_path,
        {
            "go.mod": "module example.com/m\n",
            "m.go": "package m\n",
            "sub/s.go": 'package sub\n\nimport "example.com/m"\n',
        },
    )
    graph = build_index(root).imports
    assert targets(root, "sub/s.go") == {("example.com/m", "local", ".")}
    assert graph.dependencies("sub/s.go") == {"."}
    assert graph.dependents(".") == {"sub/s.go"}


def test_r2_go_nested_module_root_and_replace_root(tmp_path):
    root = mk(
        tmp_path,
        {
            "go.mod": "module example.com/app\n\nreplace example.com/ext => ./third/ext\n",
            "main.go": 'package main\n\nimport (\n\t"example.com/lib"\n\t"example.com/ext"\n)\n',
            "lib/go.mod": "module example.com/lib\n",
            "lib/lib.go": "package lib\n",
            "third/ext/ext.go": "package ext\n",
        },
    )
    assert targets(root, "main.go") == {
        ("example.com/lib", "local", "lib"),
        ("example.com/ext", "local", "third/ext"),
    }


# --------------------------------------------------------------- R3: template interpolations


def test_r3_imports_inside_template_interpolations_are_kept():
    src = (
        "const a = `x ${require('lodash')} y`;\n"
        "const b = `${ `inner ${import('./lazy')}` }`;\n"
        "const c = `${ {k: require('./obj')}.k }` + require('after');\n"
        "const d = `require('not-code') ${'}'} import('nor-this')`;\n"
    )
    got = [(r.line, r.kind, r.module) for r in extract_js(src)]
    assert got == [
        (1, "require", "lodash"),
        (2, "dynamic", "./lazy"),
        (3, "require", "./obj"),
        (3, "require", "after"),
    ]


# --------------------------------------------------------------- R4: no catastrophic backtracking


@pytest.mark.parametrize(
    "src",
    [
        "import" + " " * 100_000 + "('./util')\n",
        "import /*" + "x" * 100_000 + "*/ ('./util')\n",
        "import a" + " " * 100_000 + "(\n",
        "import {" + " a," * 30_000 + "\n",
        "export type" + " " * 100_000 + "x\n",
        "require" + " " * 100_000 + "x\n",
    ],
    ids=["spaces", "comment", "clause-spaces", "clause-names", "export", "require"],
)
def test_r4_js_patterns_are_linear(src):
    t0 = time.perf_counter()
    extract_js(src)
    assert time.perf_counter() - t0 < 1.0


def test_r4_dynamic_import_after_whitespace_still_found():
    src = "import" + " " * 1000 + "('./util')\nimport /* c */ x from './y'\n"
    assert [r.module for r in extract_js(src)] == ["./util", "./y"]


def test_r4_other_language_patterns_are_linear():
    cases = [
        (extract_python, "from " + "." * 100_000 + "\n" + "print 'py2'\n"),
        (extract_java, "\n" * 100_000 + "class X {}\n"),
        (extract_java, "import" + " " * 100_000 + "x\n"),
        (extract_java, "import " + "a." * 50_000 + "\n"),
    ]
    for fn, src in cases:
        t0 = time.perf_counter()
        fn(src)
        assert time.perf_counter() - t0 < 1.0, fn.__name__


# --------------------------------------------------------------- R5: javax


def test_r5_only_jdk_javax_packages_are_stdlib(tmp_path):
    root = mk(
        tmp_path,
        {
            "A.java": (
                "import javax.swing.JFrame;\n"
                "import javax.crypto.Cipher;\n"
                "import javax.xml.parsers.DocumentBuilder;\n"
                "import javax.sql.DataSource;\n"
                "import javax.net.ssl.SSLContext;\n"
                "import javax.persistence.Entity;\n"
                "import javax.servlet.http.HttpServlet;\n"
                "import javax.inject.Inject;\n"
                "import javax.xml.bind.JAXB;\n"
                "import javax.annotation.Nullable;\n"
                "class A {}\n"
            )
        },
    )
    cats = {e.module: (e.category, e.package) for e in build_index(root).imports}
    stdlib = [
        "javax.swing.JFrame",
        "javax.crypto.Cipher",
        "javax.xml.parsers.DocumentBuilder",
        "javax.sql.DataSource",
        "javax.net.ssl.SSLContext",
    ]
    external = [
        "javax.persistence.Entity",
        "javax.servlet.http.HttpServlet",
        "javax.inject.Inject",
        "javax.xml.bind.JAXB",
        "javax.annotation.Nullable",
    ]
    assert {m: cats[m][0] for m in stdlib} == dict.fromkeys(stdlib, "stdlib")
    assert {m: cats[m][0] for m in external} == dict.fromkeys(external, "external")
    assert cats["javax.persistence.Entity"][1] == "javax.persistence"


# --------------------------------------------------------------- R6: Python precedence


def test_r6_package_beats_same_named_module(tmp_path):
    root = mk(
        tmp_path,
        {
            "pkg.py": "",
            "pkg/__init__.py": "",
            "pkg/sub.py": "",
            "main.py": "import pkg\nfrom pkg import sub\n",
        },
    )
    assert targets(root, "main.py") == {
        ("pkg", "local", "pkg/__init__.py"),
        ("pkg", "local", "pkg/sub.py"),
    }


def test_r6_module_in_later_root_beats_namespace_dir_in_earlier_root(tmp_path):
    root = mk(
        tmp_path,
        {
            "ns/other.py": "",  # namespace dir at the repo root (no __init__)
            "src/ns.py": "X = 1\n",  # a real module in a later source root
            "src/app/__init__.py": "",
            "src/app/m.py": "from ns import X\n",
        },
    )
    assert targets(root, "src/app/m.py") == {("ns", "local", "src/ns.py")}


def test_r6_namespace_dir_still_resolves_when_nothing_else_does(tmp_path):
    root = mk(tmp_path, {"ns/p1.py": "", "m.py": "from ns import p1\n"})
    assert targets(root, "m.py") == {("ns", "local", "ns/p1.py")}


# --------------------------------------------------------------- R7: symlinked ancestors


def test_r7_tracked_dir_replaced_by_symlink_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "module.py").write_text("import secret_outside\n")
    root = mk(tmp_path, {"src/module.py": "import os\n", "a.py": "import os\n"})
    for f in (root / "src").iterdir():
        f.unlink()
    (root / "src").rmdir()
    try:
        (root / "src").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks not supported")
    ix = build_index(root)
    assert "src/module.py" not in ix.files
    assert "secret_outside" not in {e.module for e in ix.imports}
    assert "symlink" in dict(ix.files.skipped)["src/module.py"]
    # the (untracked) link itself is listed as a link, never followed
    assert {f.path for f in ix.files} == {"a.py", "src"}
    assert ix.files.get("src").is_symlink and not ix.files.get("src").parseable


def test_r7_symlinked_ancestor_inside_repo_is_rejected_too(tmp_path):
    root = mk(tmp_path, {"real/m.py": "import os\n", "alias/m.py": "import json\n"})
    (root / "alias" / "m.py").unlink()
    (root / "alias").rmdir()
    try:
        os.symlink("real", root / "alias", target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks not supported")
    ix = index_files(root)  # git still lists the tracked alias/m.py
    assert {f.path for f in ix.files} == {"real/m.py", "alias"}
    assert ix.get("alias").is_symlink
    assert "alias/m.py" in dict(ix.skipped)


# --------------------------------------------------------------- round 2 (PR #9 @9f9a76d)


def test_r2a_symlinked_gitignore_is_not_read_in_walk_mode(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "rules").write_text("*.py\n")  # would hide every .py if it were read
    root = tmp_path / "r"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.py").write_text("import os\n")
    (root / "b.py").write_text("")
    try:
        (root / ".gitignore").symlink_to(outside / "rules")
        (root / "sub" / ".gitignore").symlink_to(outside / "rules")
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks not supported")
    ix = index_files(root, use_git=False)
    assert ix.source == "walk"
    assert {f.path for f in ix} == {".gitignore", "b.py", "sub/.gitignore", "sub/a.py"}
    assert ix.get(".gitignore").is_symlink and ix.get("sub/.gitignore").is_symlink


def test_r2b_bare_test_is_a_package_not_a_node_builtin(tmp_path):
    root = mk(tmp_path, {"a.js": "import t from 'test';\nimport n from 'node:test';\n"})
    got = {(e.module, e.category, e.package) for e in build_index(root).imports}
    assert got == {("test", "external", "test"), ("node:test", "stdlib", "test")}


def test_r2c_require_resolves_json_and_node_addons(tmp_path):
    root = mk(
        tmp_path,
        {
            "a.js": (
                "const c = require('./config');\n"
                "const addon = require('./native/addon');\n"
                "const both = require('./both');\n"
            ),
            "config.json": "{}",
            "native/addon.node": "",
            "both.js": "",
            "both.json": "{}",
        },
    )
    assert targets(root, "a.js") == {
        ("./config", "local", "config.json"),
        ("./native/addon", "local", "native/addon.node"),
        ("./both", "local", "both.js"),  # .js before .json, as in Node
    }
