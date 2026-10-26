"""L-003: import-graph extraction and resolution on per-language fixtures."""

from __future__ import annotations

import pytest

from driftwarden.index import build_index, index_files
from driftwarden.index.imports import (
    build_import_graph,
    extract_go,
    extract_java,
    extract_js,
    extract_python,
    mask,
    parse_go_mod,
)


def edges(repo, source=None):
    """{(source, line, kind, module, category, target)} for the repo (or one file)."""
    graph = build_index(repo).imports
    return {
        (e.source, e.line, e.kind, e.module, e.category, e.target)
        for e in graph
        if source is None or e.source == source
    }


@pytest.fixture(params=[True, False], ids=["git", "walk"])
def git_mode(request):
    return request.param


# --------------------------------------------------------------------------- python


def test_python_fixture_edges(index_fixture, git_mode):
    repo = index_fixture("python", git_init=git_mode)
    m = "src/app/main.py"
    assert edges(repo, m) == {
        (m, 5, "import", "os", "stdlib", None),
        (m, 6, "import", "sys", "stdlib", None),
        (m, 7, "from", ".", "local", "src/app/utils.py"),
        (m, 8, "from", ".models", "local", "src/app/models.py"),
        (m, 9, "from", ".sub", "local", "src/app/sub/helpers.py"),
        (m, 10, "from", "..", "unresolved", None),  # above the top-level package
        (m, 11, "import", "requests", "external", None),
        (m, 12, "from", "app.core.db", "local", "src/app/core/db.py"),
        (m, 13, "import", "app.core", "local", "src/app/core/__init__.py"),
        (m, 14, "from", "app.plugins", "local", "src/app/plugins/p1.py"),  # namespace pkg
        (m, 15, "import", "importlib", "stdlib", None),
        (m, 18, "import", "ujson", "external", None),  # inside try:
        (m, 20, "import", "json", "stdlib", None),  # inside except:
        (m, 22, "from", "typing", "stdlib", None),
        (m, 25, "from", "app.models", "local", "src/app/models.py"),  # if TYPE_CHECKING:
        (m, 29, "dynamic", "app.plugins.p1", "local", "src/app/plugins/p1.py"),
        (m, 34, "from", "app", "local", "src/app/utils.py"),  # multi-line, parenthesised
        (m, 34, "from", "app", "local", "src/app/models.py"),
    }


def test_python_relative_and_unicode(index_fixture):
    repo = index_fixture("python")
    assert edges(repo, "src/app/models.py") == {
        ("src/app/models.py", 1, "from", ".données", "local", "src/app/données.py"),
        ("src/app/models.py", 2, "from", "app", "local", "src/app/utils.py"),
    }
    h = "src/app/sub/helpers.py"
    assert edges(repo, h) == {
        (h, 1, "from", "..models", "local", "src/app/models.py"),
        (h, 2, "from", "...beyond", "unresolved", None),
    }
    assert edges(repo, "src/app/sub/__init__.py") == {
        ("src/app/sub/__init__.py", 1, "from", ".helpers", "local", "src/app/sub/helpers.py"),
    }


def test_python_scripts_shebang_and_fallback(index_fixture):
    repo = index_fixture("python")
    ix = build_index(repo)
    assert edges(repo, "scripts/run.py") == {
        ("scripts/run.py", 2, "import", "helper_script", "local", "scripts/helper_script.py"),
        ("scripts/run.py", 3, "from", "app.main", "local", "src/app/main.py"),
    }
    # extensionless file detected as Python from its shebang
    assert ix.files.get("scripts/tool").language == "python"
    assert edges(repo, "scripts/tool") == {
        ("scripts/tool", 2, "import", "argparse", "stdlib", None)
    }
    # Python 2 file: ast fails, regex fallback still finds the imports, error recorded
    assert edges(repo, "legacy/py2.py") == {
        ("legacy/py2.py", 2, "import", "os", "stdlib", None),
        ("legacy/py2.py", 2, "import", "urllib2", "external", None),
        ("legacy/py2.py", 3, "from", "collections", "stdlib", None),
    }
    assert [p for p, _ in ix.imports.errors] == ["legacy/py2.py"]


def test_python_strings_and_docstrings_are_not_imports(index_fixture):
    repo = index_fixture("python")
    modules = {e.module for e in build_index(repo).imports}
    assert "not_a_module" not in modules
    assert "fake" not in modules


def test_python_external_packages(index_fixture):
    graph = build_index(index_fixture("python")).imports
    assert set(graph.external_packages()) == {"requests", "ujson", "sqlalchemy", "urllib2"}
    sub = [e for e in graph if e.module == "sqlalchemy.orm"]
    assert sub[0].package == "sqlalchemy" and sub[0].names == ("Session",)


def test_python_extract_unit():
    src = "import a.b as c, d\nfrom .x import (y,\n  z)\nfrom . import *\n"
    raws, err = extract_python(src)
    assert err is None
    got = [(r.line, r.end_line, r.module, r.kind, r.names, r.level) for r in raws]
    assert got == [
        (1, 1, "a.b", "import", (), 0),
        (1, 1, "d", "import", (), 0),
        (2, 3, "x", "from", ("y", "z"), 1),
        (4, 4, "", "from", ("*",), 1),
    ]


def test_python_crlf_and_bom(make_repo):
    repo = make_repo({"pkg/__init__.py": "", "pkg/b.py": ""})
    (repo / "pkg" / "a.py").write_bytes(b"\xef\xbb\xbf# c\r\n\r\nfrom . import b\r\n")
    got = edges(repo, "pkg/a.py")
    assert got == {("pkg/a.py", 3, "from", ".", "local", "pkg/b.py")}


# --------------------------------------------------------------------------- js / ts


def test_js_fixture_edges(index_fixture, git_mode):
    repo = index_fixture("js", git_init=git_mode)
    i = "src/index.ts"
    assert edges(repo, i) == {
        (i, 1, "import", "./util", "local", "src/util.ts"),
        (i, 2, "import", "./lib/math", "local", "src/lib/math.js"),
        (i, 3, "import", "./types", "local", "src/types.d.ts"),  # import type
        (i, 4, "import", "fs", "stdlib", None),
        (i, 5, "import", "node:path", "stdlib", None),
        (i, 6, "import", "react", "external", None),
        (i, 7, "import", "@aws-sdk/client-s3", "external", None),
        (i, 8, "export", "./reexport", "local", "src/reexport.tsx"),
        (i, 9, "export", "./lib", "local", "src/lib/index.ts"),  # directory index
        (i, 14, "dynamic", "./lazy", "local", "src/lazy.mjs"),
        (i, 15, "import", "./side-effect.css", "local", "src/side-effect.css"),
        (i, 16, "import", "@/config", "unresolved", None),  # tsconfig alias: not read
        (i, 17, "import", "./esm.js", "local", "src/esm.ts"),  # ESM-style TS import
        (i, 18, "import", "./multi", "local", "src/multi.ts"),  # multi-line
        (i, 22, "import", "./ünïcode", "local", "src/ünïcode.js"),
        (i, 23, "import", "./does-not-exist", "unresolved", None),
    }
    multi = [e for e in build_index(repo).imports if e.module == "./multi"][0]
    assert (multi.line, multi.end_line) == (18, 21)


def test_js_comments_strings_regex_ignored(index_fixture):
    graph = build_index(index_fixture("js")).imports
    modules = {e.module for e in graph}
    for fake in ("commented", "block", "block2", "string", "regex", "not-real"):
        assert fake not in modules


def test_js_require_and_jsx(index_fixture):
    repo = index_fixture("js")
    c = "src/legacy.cjs"
    assert edges(repo, c) == {
        (c, 1, "require", "./util", "local", "src/util.ts"),
        (c, 3, "require", "lodash/fp", "external", None),  # after a regex with quotes
        (c, 4, "require", "./nope", "unresolved", None),
    }
    j = "src/App.jsx"
    assert edges(repo, j) == {
        (j, 1, "import", "react", "external", None),
        (j, 3, "import", "./util", "local", "src/util.ts"),  # after JSX text with '
    }
    pkgs = build_index(repo).imports.external_packages()
    assert set(pkgs) == {"react", "@aws-sdk/client-s3", "lodash"}


def test_js_extract_unit():
    src = (
        "import a, { b as c } from 'm1'\n"
        'import "m2"\n'
        "export * as ns from 'm3'\n"
        "import x = require('m4')\n"
        "const y = await import(`m5`)\n"
        "const z = import(`m${v}`)\n"
        "obj.import('nope'); obj.require('nope2')\n"
        "import{q}from'm6'\n"
    )
    got = [(r.line, r.kind, r.module) for r in extract_js(src)]
    assert got == [
        (1, "import", "m1"),
        (2, "import", "m2"),
        (3, "export", "m3"),
        (4, "require", "m4"),
        (5, "dynamic", "m5"),
        (8, "import", "m6"),
    ]


def test_relative_escape_above_root_is_unresolved(make_repo):
    repo = make_repo({"a.js": "import x from '../../outside.js'\n"})
    assert edges(repo) == {("a.js", 1, "import", "../../outside.js", "unresolved", None)}


# --------------------------------------------------------------------------- java


def test_java_fixture_edges(index_fixture, git_mode):
    repo = index_fixture("java", git_init=git_mode)
    base = "src/main/java/com/acme/app/"
    a = base + "App.java"
    assert edges(repo, a) == {
        (a, 3, "import", "com.acme.app.service.UserService", "local",
         base + "service/UserService.java"),
        (a, 4, "wildcard", "com.acme.app.model", "local", base + "model/Role.java"),
        (a, 4, "wildcard", "com.acme.app.model", "local", base + "model/User.java"),
        (a, 5, "static", "com.acme.app.util.Strings.trim", "local", base + "util/Strings.java"),
        (a, 6, "import", "java.util.List", "stdlib", None),
        (a, 7, "import", "org.springframework.boot.SpringApplication", "external", None),
        (a, 8, "import", "com.acme.app.Outer.Inner", "local", base + "Outer.java"),
        (a, 9, "import", "com.acme.app.missing.Gone", "unresolved", None),
    }  # fmt: skip
    t = "src/test/java/com/acme/app/AppTest.java"
    assert edges(repo, t) == {
        (t, 3, "import", "org.junit.jupiter.api.Test", "external", None),
        (t, 4, "import", "com.acme.app.App", "local", a),  # across source roots
    }
    pkgs = build_index(repo).imports.external_packages()
    assert set(pkgs) == {"org.springframework", "org.junit"}


def test_java_comments_strings_textblocks_ignored(index_fixture):
    modules = {e.module for e in build_index(index_fixture("java")).imports}
    assert not [m for m in modules if m.startswith("com.fake")]


def test_java_extract_unit():
    pkg, raws = extract_java(
        "package  a.b ;\nimport static x.Y.*;\nimport\n  p.Q;\nimport r . *;\n"
    )
    assert pkg == "a.b"
    assert [(r.line, r.end_line, r.kind, r.module) for r in raws] == [
        (2, 2, "static-wildcard", "x.Y"),
        (4, 4, "import", "p.Q"),
        (5, 5, "wildcard", "r"),
    ]


# --------------------------------------------------------------------------- go


def test_go_fixture_edges(index_fixture, git_mode):
    repo = index_fixture("go", git_init=git_mode)
    m = "main.go"
    assert edges(repo, m) == {
        (m, 4, "import", "fmt", "stdlib", None),
        (m, 5, "import", "net/http", "stdlib", None),
        (m, 7, "import", "example.com/shop/internal/store", "local", "internal/store"),
        (m, 8, "import", "example.com/shop/pkg/db", "local", "pkg/db"),
        (m, 9, "import", "github.com/lib/pq", "external", None),
        (m, 10, "import", "github.com/aws/aws-sdk-go-v2/service/s3", "external", None),
        (m, 11, "import", "example.com/lib/util", "local", "third_party/lib/util"),  # replace
        (m, 12, "import", "example.com/shop/missing", "unresolved", None),
    }
    assert edges(repo, "internal/store/store.go") == {
        ("internal/store/store.go", 3, "import", "example.com/shop/pkg/db", "local", "pkg/db")
    }
    assert edges(repo, "cmd/tool/main.go") == {
        ("cmd/tool/main.go", 3, "import", "fmt", "stdlib", None)
    }
    graph = build_index(repo).imports
    assert set(graph.external_packages()) == {
        "github.com/lib/pq",
        "github.com/aws/aws-sdk-go-v2",
    }
    assert "fake/inside/raw" not in {e.module for e in graph}
    assert "commented/out" not in {e.module for e in graph}


def test_go_extract_unit():
    src = 'package x\n\nimport "a"\nimport b "c/d"\nimport (\n\t. "e"\n\t_ `f`\n)\n'
    got = [(r.line, r.module, r.alias) for r in extract_go(src)]
    assert got == [(3, "a", None), (4, "c/d", "b"), (6, "e", "."), (7, "f", "_")]


def test_go_mod_parse():
    mod, rep = parse_go_mod(
        'module "example.com/m" // c\n\nreplace (\n  a.com/x v1 => ./x\n'
        "  b.com/y => github.com/z/y v1\n)\nreplace c.com/q => ../q\n"
    )
    assert mod == "example.com/m"
    assert rep == [("a.com/x", "./x"), ("c.com/q", "../q")]


# --------------------------------------------------------------------------- general


def test_mask_preserves_offsets():
    from driftwarden.index.imports import _JS_LEX

    src = "a = 'x // y' // z\n/* q\n r */ b = `t\nu`\n"
    out = mask(src, _JS_LEX)
    assert len(out) == len(src)
    assert out.count("\n") == src.count("\n")
    assert "//" not in out and "/*" not in out and "z" not in out


def test_binary_and_symlinked_sources_not_parsed(make_repo):
    repo = make_repo({"real.py": "import os\n"})
    (repo / "blob.py").write_bytes(b"import json\n\x00\x01binary")
    try:
        (repo / "link.py").symlink_to("real.py")
    except (OSError, NotImplementedError):  # pragma: no cover - platform without symlinks
        pytest.skip("symlinks not supported")
    graph = build_import_graph(index_files(repo))
    assert {e.source for e in graph} == {"real.py"}


def test_graph_queries(index_fixture):
    graph = build_index(index_fixture("python")).imports
    assert graph.dependencies("src/app/models.py") == {"src/app/données.py", "src/app/utils.py"}
    assert "src/app/main.py" in graph.dependents("src/app/utils.py")
    assert graph.edges_to("src/app/données.py")[0].source == "src/app/models.py"
    assert len(graph) == len(list(graph))
