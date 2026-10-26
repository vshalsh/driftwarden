# ruff: noqa: E501
"""L-003 system tests (tester seat): adversarial inputs for the repository indexer.

Independent of the author's fixtures: every repo here is built inline.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from conftest import git
from driftwarden.index import build_index, index_files

# --------------------------------------------------------------------------- helpers


def write(root, files: dict[str, str | bytes]):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_bytes(content.encode("utf-8"))  # exact bytes, no newline translation
    return root


def mk(tmp_path, files, *, use_git=True, name="r"):
    root = tmp_path / name
    root.mkdir()
    if use_git:
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "commit.gpgsign", "false")
    write(root, files)
    if use_git:
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "init")
    return root


def edge_set(root, source=None, *, fields=("module", "kind", "category", "target")):
    g = build_index(root).imports
    return {
        (e.source, *(getattr(e, f) for f in fields))
        for e in g
        if source is None or e.source == source
    }


def mods(root, source):
    """{(module, category, target)} for a file."""
    return {
        (m, c, t)
        for (_s, m, c, t) in edge_set(root, source, fields=("module", "category", "target"))
    }


@pytest.fixture(params=[True, False], ids=["git", "walk"])
def gm(request):
    return request.param


# --------------------------------------------------------------------------- python


def test_py_circular_imports_terminate_and_are_recorded(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg import b\nimport pkg.b\n",
            "pkg/b.py": "from pkg import a\nfrom . import a as aa\n",
        },
        use_git=gm,
    )
    g = build_index(root).imports
    assert "pkg/b.py" in g.dependencies("pkg/a.py")
    assert "pkg/a.py" in g.dependencies("pkg/b.py")


def test_py_self_import(tmp_path, gm):
    root = mk(tmp_path, {"m.py": "import m\n"}, use_git=gm)
    assert ("m", "local", "m.py") in mods(root, "m.py")


def test_py_conditional_try_and_function_level_imports(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": (
                "import sys\n"
                "try:\n    import ujson as json\nexcept ImportError:\n    import json\n"
                "if sys.version_info < (3, 9):\n    import typing_extensions\n"
                "def f():\n    import helper\n"
                "if False:\n    from helper import x\n"
            ),
            "helper.py": "x = 1\n",
        },
        use_git=gm,
    )
    m = {a for a, _, _ in mods(root, "a.py")}
    assert {"ujson", "json", "typing_extensions", "helper"} <= m
    assert ("helper", "local", "helper.py") in mods(root, "a.py")
    assert ("json", "stdlib", None) in mods(root, "a.py")


def test_py_dynamic_imports(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": (
                "import importlib\n"
                "importlib.import_module('helper')\n"
                "__import__('helper')\n"
                "name = 'helper'\n"
                "importlib.import_module(name)\n"  # non-literal: must not crash nor invent edges
                "importlib.import_module('.rel', package='x')\n"
            ),
            "helper.py": "",
        },
        use_git=gm,
    )
    ms = mods(root, "a.py")
    assert ("helper", "local", "helper.py") in ms
    assert not any(m == "name" for m, _, _ in ms)


def test_py_imports_in_comments_and_strings_ignored(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": (
                "# import fake_comment\n"
                "x = 'import fake_str'\n"
                'doc = """\nimport fake_doc\nfrom fake_doc2 import y\n"""\n'
                "def f():\n    '''\n    import fake_fdoc\n    '''\n"
                "import real\n"
            ),
            "real.py": "",
        },
        use_git=gm,
    )
    ms = {m for m, _, _ in mods(root, "a.py")}
    assert ms == {"real"}


def test_py_relative_beyond_top_level(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "top.py": "from .. import x\nfrom ...a import y\nfrom . import z\n",
            "pkg/__init__.py": "",
            "pkg/m.py": "from ... import q\nfrom ....deep import r\nfrom .. import pkg\n",
        },
        use_git=gm,
    )
    for src in ("top.py", "pkg/m.py"):
        for e in build_index(root).imports.edges_from(src):
            assert e.category in ("unresolved", "local")
    top = {(m, c) for m, c, _ in mods(root, "top.py")}
    assert ("..", "unresolved") in top
    assert ("...a", "unresolved") in top
    pm = {(m, c) for m, c, _ in mods(root, "pkg/m.py")}
    assert ("...", "unresolved") in pm
    assert ("....deep", "unresolved") in pm


def test_py_init_reexport_and_submodule_edges(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "lib/pkg/__init__.py": "from .core import Thing\nfrom . import util\nfrom .sub import *\n",
            "lib/pkg/core.py": "class Thing: ...\n",
            "lib/pkg/util.py": "",
            "lib/pkg/sub/__init__.py": "",
            "app.py": "from lib.pkg import Thing, util\nimport lib.pkg.core\n",
        },
        use_git=gm,
    )
    init = edge_set(root, "lib/pkg/__init__.py")
    targets = {t for (_s, _m, _k, _c, t) in init}
    assert {"lib/pkg/core.py", "lib/pkg/util.py", "lib/pkg/sub/__init__.py"} <= targets
    app = build_index(root).imports.dependencies("app.py")
    assert {"lib/pkg/util.py", "lib/pkg/core.py"} <= app


def test_py_syntax_error_falls_back_without_crashing(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "old.py": "print 'hi'\nimport helper\nfrom helper import (a,\n b)\n",
            "helper.py": "",
        },
        use_git=gm,
    )
    ix = build_index(root)
    assert "helper.py" in ix.imports.dependencies("old.py")
    assert any(p == "old.py" for p, _ in ix.imports.errors)


def test_py_future_and_star_and_alias(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": "from __future__ import annotations\nfrom helper import *\nimport helper as h, os as o\n",
            "helper.py": "",
        },
        use_git=gm,
    )
    ms = mods(root, "a.py")
    assert ("__future__", "stdlib", None) in ms
    assert ("helper", "local", "helper.py") in ms
    assert ("os", "stdlib", None) in ms


# --------------------------------------------------------------------------- js / ts


def test_ts_import_type_and_export_from(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "src/a.ts": (
                "import type { T } from './types';\n"
                "import { type U, v } from './types';\n"
                "export * from './re';\n"
                "export * as ns from './re';\n"
                "export { x, y as z } from './re';\n"
                "export type { T2 } from './types';\n"
                "import def, * as all from './re';\n"
                "import './side';\n"
                "export const local = 1;\n"
                "export { local as l2 };\n"  # no 'from': must not be an edge
            ),
            "src/types.ts": "export type T = 1;\n",
            "src/re.ts": "export const x = 1;\n",
            "src/side.ts": "",
        },
        use_git=gm,
    )
    e = build_index(root).imports.edges_from("src/a.ts")
    got = {x.target for x in e}
    assert got == {"src/types.ts", "src/re.ts", "src/side.ts"}
    kinds = {x.kind for x in e}
    assert "export" in kinds
    assert len(e) == 8  # 8 statements with a module specifier; line-accurate
    assert sorted(x.line for x in e) == [1, 2, 3, 4, 5, 6, 7, 8]


def test_js_require_and_dynamic_import(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.js": (
                "const fs = require('fs');\n"
                'const b = require("./b");\n'
                "const x = require(name);\n"
                "const t = require(`./b`);\n"
                "const lazy = () => import('./b.js');\n"
                "const tpl = import(`./${n}`);\n"
                "obj.require('./nope');\n"
                "const z = require ( './b' ).thing;\n"
            ),
            "b.js": "module.exports = 1;\n",
        },
        use_git=gm,
    )
    ms = mods(root, "a.js")
    assert ("fs", "stdlib", None) in ms
    assert ("./b", "local", "b.js") in ms
    assert ("./b.js", "local", "b.js") in ms
    assert not any("nope" in m for m, _, _ in ms)
    assert not any("${" in m for m, _, _ in ms)


def test_js_imports_in_comments_strings_templates_ignored(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.ts": (
                "// import x from './fake1';\n"
                "/* import y from './fake2';\n   require('./fake3'); */\n"
                "const s = \"import z from './fake4'\";\n"
                "const t = `\nimport q from './fake5'\nrequire('./fake6')\n`;\n"
                "const re = /import/;\n"
                "import real from './real';\n"
            ),
            "real.ts": "",
        },
        use_git=gm,
    )
    ms = {m for m, _, _ in mods(root, "a.ts")}
    assert ms == {"./real"}


def test_js_extension_swap_index_and_scoped_packages(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "src/a.ts": (
                "import './b.js';\nimport './dir';\nimport '../outside';\n"
                "import '@aws-sdk/client-s3/dist/x';\nimport 'lodash/fp';\nimport 'node:path';\nimport 'path';\n"
            ),
            "src/b.ts": "",
            "src/dir/index.tsx": "",
        },
        use_git=gm,
    )
    ms = mods(root, "src/a.ts")
    assert ("./b.js", "local", "src/b.ts") in ms
    assert ("./dir", "local", "src/dir/index.tsx") in ms
    assert ("../outside", "unresolved", None) in ms
    assert ("@aws-sdk/client-s3/dist/x", "external", None) in ms
    assert ("node:path", "stdlib", None) in ms
    assert ("path", "stdlib", None) in ms
    g = build_index(root).imports
    assert set(g.external_packages()) == {"@aws-sdk/client-s3", "lodash"}


def test_js_multiline_import_line_numbers(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.js": "import {\n  a,\n  b,\n} from './m';\nrequire('./m');\n",
            "m.js": "",
        },
        use_git=gm,
    )
    e = sorted(build_index(root).imports.edges_from("a.js"), key=lambda x: x.line)
    assert len(e) == 2 and e[1].line == 5
    assert e[0].line in (1, 4) and e[0].end_line == 4


# --------------------------------------------------------------------------- java


def test_java_static_wildcard_nested_and_comments(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "src/com/acme/util/Strs.java": 'package com.acme.util;\npublic class Strs { public static String f(){return "";} public static class In {} }\n',
            "src/com/acme/util/Nums.java": "package com.acme.util;\npublic class Nums {}\n",
            "src/com/acme/app/Main.java": (
                "package com.acme.app;\n"
                "import java.util.List;\n"
                "import static com.acme.util.Strs.f;\n"
                "import com.acme.util.Strs.In;\n"
                "import com.acme.util.*;\n"
                "import static com.acme.util.Nums.*;\n"
                "import org.springframework.stereotype.Service;\n"
                "// import com.acme.util.Fake;\n"
                "/* import com.acme.util.Fake2; */\n"
                'class M { String s = "import com.acme.util.Fake3;"; }\n'
            ),
        },
        use_git=gm,
    )
    ms = mods(root, "src/com/acme/app/Main.java")
    assert ("java.util.List", "stdlib", None) in ms
    assert ("com.acme.util.Strs.f", "local", "src/com/acme/util/Strs.java") in ms
    assert ("com.acme.util.Strs.In", "local", "src/com/acme/util/Strs.java") in ms
    assert ("com.acme.util", "local", "src/com/acme/util/Strs.java") in ms
    assert ("com.acme.util", "local", "src/com/acme/util/Nums.java") in ms
    assert ("com.acme.util.Nums", "local", "src/com/acme/util/Nums.java") in ms
    assert ("org.springframework.stereotype.Service", "external", None) in ms
    assert not any("Fake" in m for m, _, _ in ms)


def test_java_unresolved_same_package_and_default_package(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "A.java": "import B;\nimport Missing;\nclass A {}\n",
            "B.java": "class B {}\n",
        },
        use_git=gm,
    )
    ms = mods(root, "A.java")
    assert ("B", "local", "B.java") in ms


# --------------------------------------------------------------------------- go


def test_go_grouped_aliased_blank_dot_imports(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "go.mod": "module example.com/proj\n\ngo 1.22\n",
            "main.go": (
                "package main\n\n"
                'import "fmt"\n'
                'import f2 "example.com/proj/util"\n'
                "import (\n"
                '\t"os"\n'
                '\t. "example.com/proj/util"\n'
                '\t_ "github.com/lib/pq"\n'
                '\tal "github.com/aws/aws-sdk-go-v2/service/s3"\n'
                '\t// "example.com/proj/fakecomment"\n'
                '\t"example.com/proj/missing"\n'
                ")\n"
                'var s = "import \\"example.com/proj/fakestr\\""\n'
            ),
            "util/u.go": "package util\n",
        },
        use_git=gm,
    )
    ms = mods(root, "main.go")
    assert ("fmt", "stdlib", None) in ms
    assert ("os", "stdlib", None) in ms
    assert ("example.com/proj/util", "local", "util") in ms
    assert ("github.com/lib/pq", "external", None) in ms
    assert ("github.com/aws/aws-sdk-go-v2/service/s3", "external", None) in ms
    assert ("example.com/proj/missing", "unresolved", None) in ms
    assert not any("fake" in m for m, _, _ in ms)
    assert len([1 for e in build_index(root).imports.edges_from("main.go")]) == 7


def test_go_nested_module_and_backtick_import(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "go.mod": "module example.com/a\n",
            "svc/go.mod": "module example.com/a/svc\n",
            "svc/s.go": "package svc\nimport `example.com/a/svc/inner`\n",
            "svc/inner/i.go": "package inner\n",
        },
        use_git=gm,
    )
    assert ("example.com/a/svc/inner", "local", "svc/inner") in mods(root, "svc/s.go")


# --------------------------------------------------------------------------- bytes / encoding


def test_crlf_line_numbers_and_parsing(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": "import os\r\nimport helper\r\n",
            "helper.py": "",
            "b.ts": "import a from './c';\r\n\r\nimport b from './c';\r\n",
            "c.ts": "",
            "D.java": "package p;\r\nimport java.util.List;\r\nclass D {}\r\n",
            "g.go": 'package g\r\nimport (\r\n\t"fmt"\r\n\t"os"\r\n)\r\n',
        },
        use_git=gm,
    )
    a = {(e.module, e.line) for e in build_index(root).imports.edges_from("a.py")}
    assert a == {("os", 1), ("helper", 2)}
    b = sorted(e.line for e in build_index(root).imports.edges_from("b.ts"))
    assert b == [1, 3]
    assert [e.line for e in build_index(root).imports.edges_from("D.java")] == [2]
    assert sorted(e.line for e in build_index(root).imports.edges_from("g.go")) == [3, 4]


def test_lone_cr_line_endings(tmp_path, gm):
    root = mk(
        tmp_path, {"a.js": b"import a from './b';\rimport c from './b';\r", "b.js": ""}, use_git=gm
    )
    e = build_index(root).imports.edges_from("a.js")
    assert len(e) == 2


def test_bom_files_all_languages(tmp_path, gm):
    bom = b"\xef\xbb\xbf"
    root = mk(
        tmp_path,
        {
            "a.py": bom + b"import helper\n",
            "helper.py": bom,
            "b.ts": bom + b"import x from './c';\n",
            "c.ts": "",
            "D.java": bom + b"package p;\nimport java.util.List;\nclass D {}\n",
            "g.go": bom + b'package g\nimport "fmt"\n',
            "go.mod": bom + b"module example.com/m\n",
        },
        use_git=gm,
    )
    g = build_index(root).imports
    assert g.dependencies("a.py") == {"helper.py"}
    assert g.dependencies("b.ts") == {"c.ts"}
    assert [e.module for e in g.edges_from("D.java")] == ["java.util.List"]
    assert [e.module for e in g.edges_from("g.go")] == ["fmt"]


def test_utf16_bom_file_does_not_crash(tmp_path, gm):
    root = mk(
        tmp_path, {"a.py": "import os\n".encode("utf-16"), "ok.py": "import sys\n"}, use_git=gm
    )
    ix = build_index(root)
    assert ix.imports.edges_from("ok.py")


def test_non_utf8_content_does_not_crash_and_other_imports_survive(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "latin.py": b"# -*- coding: latin-1 -*-\nname = '\xe9\xe8'\nimport helper\n",
            "bad.js": b"const s = '\xff\xfe\x80';\nimport x from './h';\n",
            "bad.go": b'package g\n// \xff\xfe\nimport "fmt"\n',
            "Bad.java": b"package p;\n// \xff\nimport java.util.List;\nclass Bad {}\n",
            "helper.py": "",
            "h.js": "",
        },
        use_git=gm,
    )
    g = build_index(root).imports
    assert "helper.py" in g.dependencies("latin.py")
    assert "h.js" in g.dependencies("bad.js")
    assert [e.module for e in g.edges_from("bad.go")] == ["fmt"]
    assert [e.module for e in g.edges_from("Bad.java")] == ["java.util.List"]


def test_nul_bytes_in_source_file_is_binary_not_parsed(tmp_path, gm):
    root = mk(tmp_path, {"a.py": b"import os\n\x00\x00junk"}, use_git=gm)
    ix = build_index(root)
    ent = ix.files.get("a.py")
    assert ent.is_binary and ent.language is None
    assert not ix.imports.edges_from("a.py")


def _guarded_index(root, timeout=20):
    """Run build_index in a child process so a hang fails the test instead of the run."""
    code = (
        "import sys;from driftwarden.index import build_index;"
        "ix=build_index(sys.argv[1]);"
        "print(len(ix.files), len(ix.imports))"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code, str(root)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"build_index did not finish within {timeout}s (infinite loop)")
    assert proc.returncode == 0, proc.stderr[-500:]
    return proc.stdout.strip()


def test_root_level_init_py_does_not_hang(tmp_path, gm):
    """A repo whose root directory is itself a package (flat layout)."""
    root = mk(
        tmp_path,
        {"__init__.py": "", "a.py": "from . import b\nimport b\n", "b.py": ""},
        use_git=gm,
    )
    assert _guarded_index(root).startswith("3 ")


def test_root_level_init_py_alone_does_not_hang(tmp_path, gm):
    root = mk(tmp_path, {"__init__.py": ""}, use_git=gm)
    assert _guarded_index(root).startswith("1 0")


def test_empty_and_whitespace_only_files(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "e.py": "",
            "e.js": "",
            "E.java": "",
            "e.go": "",
            "e.ts": "",
            "w.py": "\n\n   \n",
            "w.go": "\t\n",
            "sub/__init__.py": "",
        },
        use_git=gm,
    )
    ix = build_index(root)
    assert len(ix.files) == 8
    assert len(ix.imports) == 0
    assert ix.imports.errors == []
    assert all(not f.is_binary for f in ix.files)
    assert ix.files.get("e.py").language == "python"


def test_huge_single_line_file_is_fast(tmp_path, gm):
    line = "x=1;" * 2_000_000  # 8 MB single line (above parse cap)
    mid = (
        "a=1;" * 200_000
    ) + "import real\n"  # 800 KB, imports at the end of the one line? separate line
    js = "const a='" + "q" * 900_000 + "';\nimport x from './r';\n"
    root = mk(
        tmp_path,
        {
            "huge.py": line,
            "mid.py": mid,
            "big.js": js,
            "r.js": "",
            "real.py": "",
            "minified.js": "var a=0;" * 100_000 + "require('./r');",
            "unterminated.js": "const s = 'abc\nrequire('./r');\n/* never closed\nimport z from './r'",
            "backslashes.js": "x = '" + "\\" * 100_000,
        },
        use_git=gm,
    )
    t0 = time.time()
    ix = build_index(root)
    assert time.time() - t0 < 15
    g = ix.imports
    assert "r.js" in g.dependencies("big.js")
    assert "r.js" in g.dependencies("minified.js")
    assert "real.py" in g.dependencies("mid.py")
    assert ix.files.get("huge.py").size > 2 * 1024 * 1024
    assert not g.edges_from("huge.py")  # over MAX_PARSE_BYTES: listed, not parsed


def test_pathological_regex_input_is_linear(tmp_path):
    root = mk(
        tmp_path,
        {
            "a.ts": "import " + "a, " * 50_000 + "\n",
            "b.ts": "export {" + "x," * 100_000 + "\n",
            "c.go": "package c\nimport (\n" + '\t"fmt"\n' * 50_000,
            "D.java": "import " + "a." * 100_000 + "\n",
            "e.py": "from " + "." * 50_000 + " import x\n",
        },
        use_git=False,
    )
    t0 = time.time()
    build_index(root)
    assert time.time() - t0 < 20


# --------------------------------------------------------------------------- listing / git states


def test_symlink_loops_and_dangling_links(tmp_path):
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": "", "d/x.py": ""}, use_git=False)
    os.symlink(".", root / "loop")
    os.symlink("d", root / "d" / "up_loop")
    os.symlink("../d", root / "d" / "sib")
    os.symlink("nowhere", root / "dangling.py")
    os.symlink("a.py", root / "alias.py")
    os.symlink("/etc", root / "etc_link")
    os.symlink("/etc/passwd", root / "pw.py")
    os.symlink("self", root / "self")
    t0 = time.time()
    ix = build_index(root)
    assert time.time() - t0 < 10
    paths = {f.path for f in ix.files}
    assert {"a.py", "b.py", "d/x.py"} <= paths
    assert not any(
        p.startswith("loop/") or "/up_loop/" in p or p.startswith("etc_link/") for p in paths
    )
    assert ix.files.get("alias.py").is_symlink
    # symlinked file must not be parsed as an independent source
    assert not ix.imports.edges_from("alias.py")
    assert not ix.imports.edges_from("pw.py")
    assert ix.imports.dependencies("a.py") == {"b.py"}


def test_symlink_loops_in_git_repo(tmp_path):
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": ""})
    os.symlink(".", root / "loop")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "link")
    ix = build_index(root)
    assert not any(f.path.startswith("loop/") for f in ix.files)
    assert ix.files.get("loop").is_symlink


def test_symlink_import_target_not_resolved_through_link(tmp_path, gm):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import os\n")
    root = mk(tmp_path, {"a.py": "import secret\nfrom . import secret as s2\n"}, use_git=gm)
    os.symlink(outside / "secret.py", root / "secret.py")
    ix = build_index(root)
    for e in ix.imports.edges_from("a.py"):
        assert e.target is None or e.target in ix.files


def test_repo_with_no_commits(tmp_path):
    root = tmp_path / "fresh"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(
        root,
        {
            "a.py": "import b\n",
            "b.py": "",
            ".gitignore": "ignored.py\n",
            "ignored.py": "import a\n",
        },
    )
    ix = build_index(root)
    paths = [f.path for f in ix.files]
    assert paths == [".gitignore", "a.py", "b.py"]
    assert ix.files.source == "git"
    assert ix.imports.dependencies("a.py") == {"b.py"}


def test_empty_repo_no_files_no_commits(tmp_path):
    root = tmp_path / "e"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    ix = build_index(root)
    assert len(ix.files) == 0 and len(ix.imports) == 0


def test_empty_non_git_directory(tmp_path):
    root = tmp_path / "e"
    root.mkdir()
    ix = build_index(root)
    assert len(ix.files) == 0 and ix.files.source == "walk"


def test_detached_head(tmp_path):
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": ""})
    sha = git(root, "rev-parse", "HEAD").strip()
    write(root, {"c.py": "import a\n"})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "second")
    git(root, "checkout", "-q", "--detach", sha)
    assert git(root, "rev-parse", "--abbrev-ref", "HEAD").strip() == "HEAD"
    ix = build_index(root)
    assert [f.path for f in ix.files] == ["a.py", "b.py"]
    assert ix.imports.dependencies("a.py") == {"b.py"}


def test_nested_repo_is_not_indexed_into_parent(tmp_path):
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": ""})
    inner = root / "vendor" / "inner"
    inner.mkdir(parents=True)
    git(inner, "init", "-q", "-b", "main")
    write(inner, {"x.py": "import os\n"})
    git(inner, "add", "-A")
    git(inner, "commit", "-q", "-m", "i")
    ix = build_index(root)
    paths = {f.path for f in ix.files}
    assert "a.py" in paths
    assert not any(p.startswith("vendor/inner/x.py") for p in paths), "nested repo content leaked"


def test_nested_repo_in_walk_mode(tmp_path):
    root = mk(
        tmp_path,
        {"a.py": "", "n/.git/HEAD": "ref: refs/heads/main\n", "n/x.py": "import os\n"},
        use_git=False,
    )
    ix = build_index(root)
    paths = {f.path for f in ix.files}
    assert not any(p.startswith("n/.git") for p in paths)


def test_indexing_a_subdirectory_of_a_repo(tmp_path):
    root = mk(tmp_path, {"top.py": "", "sub/a.py": "import b\n", "sub/b.py": ""})
    ix = build_index(root / "sub")
    assert [f.path for f in ix.files] == ["a.py", "b.py"]
    assert ix.imports.dependencies("a.py") == {"b.py"}


def test_gitignored_files_excluded_git_and_walk(tmp_path, gm):
    files = {
        ".gitignore": "secret.py\nout/\n*.log\n!keep.log\n/rootonly.py\nsub/**/gen_*.py\n",
        "a.py": "import secret\n",
        "secret.py": "",
        "out/o.py": "",
        "x.log": "",
        "keep.log": "",
        "rootonly.py": "",
        "sub/rootonly.py": "",
        "sub/deep/er/gen_1.py": "",
        "sub/deep/er/real.py": "",
    }
    root = tmp_path / "gi"
    root.mkdir()
    if gm:
        git(root, "init", "-q", "-b", "main")
    write(root, files)  # untracked, relying on ignore rules
    ix = build_index(root)
    paths = {f.path for f in ix.files}
    assert paths == {".gitignore", "a.py", "keep.log", "sub/rootonly.py", "sub/deep/er/real.py"}
    secret = [e for e in ix.imports.edges_from("a.py") if e.module == "secret"]
    assert all(e.target is None for e in secret)


def test_walk_and_git_modes_agree_with_nested_gitignores(tmp_path):
    files = {
        ".gitignore": "*.tmp\n",
        "a/.gitignore": "!keep.tmp\nlocal.py\n",
        "a/keep.tmp": "",
        "a/drop.tmp": "",
        "a/local.py": "",
        "a/b/local.py": "",
        "a/b/ok.py": "",
        "c/local.py": "",
    }
    r1 = tmp_path / "g"
    r1.mkdir()
    git(r1, "init", "-q", "-b", "main")
    write(r1, files)
    r2 = tmp_path / "w"
    r2.mkdir()
    write(r2, files)
    p1 = [f.path for f in index_files(r1)]
    p2 = [f.path for f in index_files(r2)]
    assert p1 == p2


def test_driftwarden_dir_excluded(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.py": "import b\n",
            "b.py": "",
            ".driftwarden/cache/x.py": "import a\n",
            ".driftwarden/config.toml": "",
            "sub/.driftwarden/y.py": "",
        },
        use_git=gm,
    )
    paths = {f.path for f in build_index(root).files}
    assert not any(".driftwarden" in p.split("/") for p in paths), paths
    assert not any(e.source.startswith(".driftwarden") for e in build_index(root).imports)


def test_driftwarden_dir_excluded_when_untracked_and_unignored(tmp_path):
    root = mk(tmp_path, {"a.py": ""})
    write(root, {".driftwarden/state.py": "import a\n", ".driftwarden/idx.json": "{}"})
    paths = {f.path for f in build_index(root).files}
    assert not any(p.startswith(".driftwarden/") for p in paths), paths


def test_default_excludes_node_modules_venv_dist(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "a.js": "import x from './node_modules/x/i.js';\n",
            "node_modules/x/i.js": "",
            "sub/node_modules/y.js": "",
            ".venv/lib/z.py": "",
            "dist/o.js": "",
            "build/o.js": "",
            "src/__pycache__/q.py": "",
        },
        use_git=gm,
    )
    paths = {f.path for f in build_index(root).files}
    assert paths == {"a.js"}


def test_tracked_but_deleted_file_is_dropped(tmp_path):
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": ""})
    (root / "b.py").unlink()
    ix = build_index(root)
    assert [f.path for f in ix.files] == ["a.py"]


def test_unicode_and_space_filenames(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "pkg dir/mod é.js": "import x from './ü.js';\n",
            "pkg dir/ü.js": "",
            "日本/a.py": "",
        },
        use_git=gm,
    )
    ix = build_index(root)
    assert ix.imports.dependencies("pkg dir/mod é.js") == {"pkg dir/ü.js"}
    assert "日本/a.py" in ix.files


def test_non_utf8_filename(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "ok.py").write_text("")
    with open(os.path.join(os.fsencode(root), b"bad\xff.py"), "wb") as fh:
        fh.write(b"import ok\n")
    ix = build_index(root)
    assert len(ix.files) == 2
    assert ix.imports.dependencies(os.fsdecode(b"bad\xff.py")) == {"ok.py"}


def test_root_is_file_raises(tmp_path):
    f = tmp_path / "f.py"
    f.write_text("")
    with pytest.raises(NotADirectoryError):
        build_index(f)


def test_relative_root_path_and_trailing_slash(tmp_path, monkeypatch):
    mk(tmp_path, {"a.py": "import b\n", "b.py": ""})
    monkeypatch.chdir(tmp_path)
    for spec in ("r", "r/", "./r", "r/../r"):
        assert [f.path for f in build_index(spec).files] == ["a.py", "b.py"]


def test_unreadable_file_is_reported_not_fatal(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    root = mk(tmp_path, {"a.py": "import b\n", "b.py": ""}, use_git=False)
    os.chmod(root / "b.py", 0)
    try:
        ix = build_index(root)
        assert ix.imports.dependencies("a.py") in (set(), {"b.py"})
    finally:
        os.chmod(root / "b.py", 0o644)


def test_fifo_in_tree_does_not_hang(tmp_path):
    root = mk(tmp_path, {"a.py": ""}, use_git=False)
    os.mkfifo(root / "pipe.py")
    t0 = time.time()
    ix = build_index(root)
    assert time.time() - t0 < 5
    assert "pipe.py" not in ix.files


# --------------------------------------------------------------------------- determinism / scale


def _snapshot(ix):
    return (
        [(f.path, f.size, f.language, f.is_binary, f.is_symlink, f.tracked) for f in ix.files],
        [tuple(vars_of(e)) for e in ix.imports],
        list(ix.imports.errors),
        list(ix.files.skipped),
    )


def vars_of(e):
    return (
        e.source,
        e.line,
        e.end_line,
        e.language,
        e.module,
        e.kind,
        e.category,
        e.target,
        e.package,
        e.names,
    )


def test_determinism_two_runs_identical_and_independent_of_creation_order(tmp_path):
    files = {
        "go.mod": "module example.com/p\n",
        "u/u.go": 'package u\nimport "fmt"\n',
        "m.go": 'package main\nimport ("fmt"; "example.com/p/u")\n',
        "J/A.java": "package J;\nimport java.util.*;\nimport J.*;\nclass A{}\n",
        "J/B.java": "package J;\nclass B{}\n",
        "J/C.java": "package J;\nclass C{}\n",
        "p/__init__.py": "from . import a, b, c\n",
        "p/a.py": "import p.b, p.c\nfrom p import b\n",
        "p/b.py": "import p.a\n",
        "p/c.py": "",
        "z.ts": "import './y';export * from './y';require('./y')\n",
        "y.ts": "",
    }
    snaps = []
    for i, order in enumerate((list(files), list(reversed(files)), sorted(files, key=hash))):
        root = tmp_path / f"d{i}"
        root.mkdir()
        write(root, {k: files[k] for k in order})
        snaps.append(_snapshot(build_index(root)))
        snaps.append(_snapshot(build_index(root)))
    # tracked flag is None in both (non-git); compare all
    assert all(s == snaps[0] for s in snaps)


def test_determinism_in_git_repo_across_runs_and_subprocess_hashseeds(tmp_path):
    root = mk(
        tmp_path,
        {f"m{i}.py": f"import m{(i + 1) % 20}\nimport os\nimport zzz\n" for i in range(20)},
    )
    code = (
        "import sys;from driftwarden.index import build_index;"
        "g=build_index(sys.argv[1]).imports;"
        "print([(e.source,e.line,e.module,e.target) for e in g])"
    )
    outs = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        outs.add(
            subprocess.run(
                [sys.executable, "-c", code, str(root)],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            ).stdout
        )
    assert len(outs) == 1


def test_edges_are_sorted(tmp_path, gm):
    root = mk(
        tmp_path,
        {
            "b.py": "import a\nimport os\n",
            "a.py": "import b\n",
            "c/d.py": "import a\n",
        },
        use_git=gm,
    )
    ed = list(build_index(root).imports)
    assert ed == sorted(ed, key=lambda e: (e.source, e.line, e.module, e.target or ""))


def test_scale_5k_files_under_budget_with_correct_edges(tmp_path):
    root = tmp_path / "big"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    n = 5000
    for i in range(n):
        d = root / f"d{i % 50}"
        d.mkdir(exist_ok=True)
        (d / f"f{i}.py").write_text(f"import d{(i + 1) % 50}.f{(i + 1) % n}\nimport os\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "x")
    t0 = time.time()
    ix = build_index(root)
    dt = time.time() - t0
    assert len(ix.files) == n
    assert dt < 30, dt
    assert ix.imports.dependencies("d0/f0.py") == {"d1/f1.py"}
    assert len([e for e in ix.imports if e.category == "local"]) == n


def test_scale_5k_files_walk_mode_under_budget(tmp_path):
    root = tmp_path / "bigw"
    root.mkdir()
    for i in range(5000):
        d = root / f"d{i % 50}" / f"s{i % 7}"
        d.mkdir(parents=True, exist_ok=True)
        j = (i + 1) % 5000
        (d / f"f{i}.ts").write_text(f"import {{a}} from '../../d{j % 50}/s{j % 7}/f{j}';\n")
    t0 = time.time()
    ix = build_index(root)
    assert time.time() - t0 < 30
    assert len(ix.files) == 5000
    assert len([e for e in ix.imports if e.category == "local"]) == 5000


def test_deep_directory_nesting(tmp_path):
    parts = ["d"] * 60
    root = tmp_path / "r"
    deep = root.joinpath(*parts)
    deep.mkdir(parents=True)
    (deep / "a.py").write_text("import os\n")
    ix = build_index(root)
    assert [f.path for f in ix.files] == ["/".join(parts) + "/a.py"]


def test_many_wildcard_java_edges(tmp_path):
    files = {f"p/C{i}.java": f"package p;\nclass C{i} {{}}\n" for i in range(300)}
    files["q/U.java"] = "package q;\nimport p.*;\nclass U {}\n"
    root = mk(tmp_path, files, use_git=False)
    assert len(build_index(root).imports.dependencies("q/U.java")) == 300
