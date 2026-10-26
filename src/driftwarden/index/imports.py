"""Import graph for Python, JavaScript/TypeScript, Java and Go.

Deterministic and dependency-free: Python uses :mod:`ast` (with a line-regex
fallback for files that do not parse, such as Python 2 code); the other languages
use regexes run over a *masked* copy of the source in which comments are blanked
and string contents replaced, so ``import`` inside a comment or a string is never
reported. Masking keeps every offset and newline, so line numbers are exact.

Each import becomes an :class:`ImportEdge` with a ``category``:

``local``
    Resolved to a file in the repository (``target`` is its repo-relative path; for
    Go, whose imports name packages, ``target`` is the package directory).
``stdlib``
    The language's standard library (Python ``sys.stdlib_module_names``, Node
    built-ins, ``java.*``/``javax.*``/``jdk.*``, Go paths without a dot).
``external``
    A third-party package (``package`` holds its distribution-level name, e.g.
    ``requests``, ``@aws-sdk/client-s3``, ``org.springframework``,
    ``github.com/aws/aws-sdk-go-v2``).
``unresolved``
    Looks local (relative import, path alias, path inside a local Go module) but
    no matching file exists in the index.

Resolution rules, briefly:

* **Python**: relative imports resolve against the importing file's package.
  Absolute imports are looked up in every source root: the repo root, ``src/``,
  ``lib/``, the parent of every top-level package (the highest directory chain of
  ``__init__.py``), and the importing file's own directory when that directory is
  not a package (scripts, test folders). ``from pkg import name`` gives an edge to
  ``pkg/name.py`` when ``name`` is a submodule, otherwise to ``pkg/__init__.py``.
* **JS/TS**: ``./`` and ``../`` specifiers are tried as written, with each JS/TS
  extension, as a directory ``index`` file, and with ``.js``-family extensions
  swapped for their TypeScript twins (ESM-style TS imports). ``tsconfig`` path
  aliases are not read; ``@/``, ``~/`` and ``#`` specifiers are ``unresolved``.
* **Java**: each file's ``package`` declaration plus its file name gives its
  fully-qualified name. Nested-class and static imports fall back to the longest
  matching class; ``pkg.*`` gives one edge per file of that package.
* **Go**: every ``go.mod`` contributes its module path (and local ``replace``
  directives); an import under a module path maps to that directory.
"""

from __future__ import annotations

import ast
import bisect
import posixpath
import re
import sys
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Literal

from driftwarden.index.files import FileEntry, FileIndex

Category = Literal["local", "stdlib", "external", "unresolved"]
IMPORT_LANGUAGES = ("python", "javascript", "typescript", "java", "go")


@dataclass(frozen=True, slots=True)
class RawImport:
    """One import statement as written, before resolution."""

    line: int
    """1-based line of the module name (for multi-line statements, the statement start)."""
    end_line: int
    module: str
    """The module as written: ``os.path``, ``./util``, ``com.acme.Foo``, ``net/http``."""
    kind: str
    """``import``, ``from``, ``require``, ``dynamic``, ``export``, ``static``, ``wildcard``."""
    names: tuple[str, ...] = ()
    """Python ``from`` imports: the imported names. Empty otherwise."""
    level: int = 0
    """Python relative-import level (number of leading dots)."""
    alias: str | None = None


@dataclass(frozen=True, slots=True)
class ImportEdge:
    """One resolved import: ``source`` depends on ``module`` (``target`` if local)."""

    source: str
    line: int
    end_line: int
    language: str
    module: str
    kind: str
    category: Category
    target: str | None = None
    package: str | None = None
    names: tuple[str, ...] = ()


@dataclass
class ImportGraph:
    edges: list[ImportEdge]
    errors: list[tuple[str, str]] = field(default_factory=list)
    """``(path, message)`` for files that needed a fallback parser or could not be read."""

    def __len__(self) -> int:
        return len(self.edges)

    def __iter__(self) -> Iterator[ImportEdge]:
        return iter(self.edges)

    def edges_from(self, path: str) -> list[ImportEdge]:
        return [e for e in self.edges if e.source == path]

    def edges_to(self, target: str) -> list[ImportEdge]:
        return [e for e in self.edges if e.target == target]

    def dependencies(self, path: str) -> set[str]:
        """Repo paths that ``path`` imports (local edges only)."""
        return {e.target for e in self.edges if e.source == path and e.target}

    def dependents(self, target: str) -> set[str]:
        return {e.source for e in self.edges if e.target == target}

    def external_packages(self) -> dict[str, set[str]]:
        """Third-party package name -> files that import it."""
        out: dict[str, set[str]] = defaultdict(set)
        for e in self.edges:
            if e.category == "external" and e.package:
                out[e.package].add(e.source)
        return dict(out)


# --------------------------------------------------------------------------- helpers


class _Lines:
    """Offset -> 1-based line number."""

    def __init__(self, text: str) -> None:
        self._nl = [m.start() for m in re.finditer("\n", text)]

    def at(self, offset: int) -> int:
        return bisect.bisect_left(self._nl, offset) + 1


_C_COMMENT = r"(?P<c>//[^\n]*|/\*[\s\S]*?\*/)"
_DQ = r'"(?:\\[\s\S]|[^"\\\n])*"'
_SQ = r"'(?:\\[\s\S]|[^'\\\n])*'"
_BT = r"`(?:\\[\s\S]|[^`\\])*`"

_JS_LEX = re.compile(
    _C_COMMENT
    + rf"|(?P<s>{_DQ}|{_SQ}|{_BT})"
    # A regex literal can follow an operator/opening bracket or `return`-like keyword;
    # anything else starting with "/" is division.
    + r"|(?P<pre>[(,=:\[!&|?{};+\-*%<>~^]|^|\b(?:return|typeof|case|in|of|delete|void|"
    r"throw|yield|await|do|else))(?P<ws>[ \t]*)"
    r"(?P<r>/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[A-Za-z]*)",
    re.M,
)
_JAVA_LEX = re.compile(_C_COMMENT + rf'|(?P<s>"""[\s\S]*?"""|{_DQ}|' + r"'(?:\\.|[^'\\\n])+')")
_GO_LEX = re.compile(_C_COMMENT + rf"|(?P<s>{_DQ}|`[^`]*`|" + r"'(?:\\.|[^'\\\n])+')")

_NOT_NL = re.compile(r"[^\n]")


def mask(text: str, lexer: re.Pattern[str]) -> str:
    """Blank comments and regex literals, and replace string contents with ``s``,
    keeping quotes, newlines and every offset unchanged."""

    def repl(m: re.Match[str]) -> str:
        if m.group("c") is not None:
            return _NOT_NL.sub(" ", m.group(0))
        s = m.group("s")
        if s is not None:
            q = 3 if s.startswith('"""') else 1
            return s[:q] + _NOT_NL.sub("s", s[q:-q]) + s[-q:]
        # regex literal: keep the preceding token, blank the literal
        return m.group("pre") + m.group("ws") + _NOT_NL.sub(" ", m.group("r"))

    return lexer.sub(repl, text)


def _quoted(original: str, start: int, end: int) -> str:
    """The text between the quotes of the string literal at [start, end)."""
    return original[start + 1 : end - 1]


# --------------------------------------------------------------------------- python

_PY_LINE_RE = re.compile(
    r"^[ \t]*(?:from[ \t]+(?P<from>\.*[\w.]*)[ \t]+import[ \t]+(?P<names>[^#\n]+)"
    r"|import[ \t]+(?P<mods>[^#\n]+))",
    re.M,
)


def extract_python(text: str) -> tuple[list[RawImport], str | None]:
    """Imports in Python source. Returns ``(imports, error)``; ``error`` is set when the
    file did not parse and the regex fallback was used."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        return _extract_python_regex(text), f"python syntax error, used regex fallback: {exc}"
    out: list[RawImport] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out.append(
                    RawImport(
                        node.lineno,
                        node.end_lineno or node.lineno,
                        a.name,
                        "import",
                        alias=a.asname,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            out.append(
                RawImport(
                    node.lineno,
                    node.end_lineno or node.lineno,
                    node.module or "",
                    "from",
                    names=tuple(a.name for a in node.names),
                    level=node.level or 0,
                )
            )
        elif isinstance(node, ast.Call):
            mod = _python_dynamic(node)
            if mod is not None:
                out.append(RawImport(node.lineno, node.end_lineno or node.lineno, mod, "dynamic"))
    out.sort(key=lambda r: (r.line, r.module))
    return out, None


def _python_dynamic(node: ast.Call) -> str | None:
    """``importlib.import_module("x")`` / ``import_module("x")`` / ``__import__("x")``
    with a constant, absolute module name."""
    f = node.func
    name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
    if name not in ("import_module", "__import__") or not node.args:
        return None
    if isinstance(f, ast.Attribute) and not (
        isinstance(f.value, ast.Name) and f.value.id == "importlib"
    ):
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value:
        if not arg.value.startswith("."):
            return arg.value
    return None


def _extract_python_regex(text: str) -> list[RawImport]:
    lines = _Lines(text)
    out: list[RawImport] = []
    for m in _PY_LINE_RE.finditer(text):
        ln = lines.at(m.start())
        if m.group("from") is not None:
            spec = m.group("from")
            level = len(spec) - len(spec.lstrip("."))
            names = m.group("names").strip().strip("()\\").strip()
            parsed = tuple(n.split(" as ")[0].strip() for n in names.split(",") if n.strip())
            out.append(RawImport(ln, ln, spec[level:], "from", names=parsed, level=level))
        else:
            for part in m.group("mods").split(","):
                mod = part.split(" as ")[0].strip()
                if re.fullmatch(r"[\w.]+", mod):
                    out.append(RawImport(ln, ln, mod, "import"))
    return out


# --------------------------------------------------------------------------- js / ts

_JS_SPEC = r"(?P<q>['\"])[^'\"\n]*(?P=q)"
_JS_PATTERNS = (
    (
        "import",
        re.compile(r"(?<![\w$.])import\s*(?:type\s+)?(?:[\w$*{}\s,]*?[\s}*]from\s*)?" + _JS_SPEC),
    ),
    (
        "export",
        re.compile(
            r"(?<![\w$.])export\s*(?:type\s+)?(?:\*\s*(?:as\s+[\w$]+\s*)?|\{[^}]*\}\s*)from\s*"
            + _JS_SPEC
        ),
    ),
    ("require", re.compile(r"(?<![\w$.])require\s*\(\s*" + _JS_SPEC + r"\s*\)")),
    (
        "dynamic",
        re.compile(r"(?<![\w$.])import\s*\(\s*(?P<q>['\"`])[^'\"`\n]*(?P=q)\s*[,)]"),
    ),
)


def extract_js(text: str) -> list[RawImport]:
    """Imports in JavaScript/TypeScript: ``import``, ``export … from``, ``require()``,
    ``import()`` with a literal specifier, and TS ``import x = require()``."""
    masked = mask(text, _JS_LEX)
    lines = _Lines(text)
    seen: set[int] = set()
    out: list[RawImport] = []
    for kind, pat in _JS_PATTERNS:
        for m in pat.finditer(masked):
            q = m.start("q")
            if q in seen:
                continue
            end = masked.index(m.group("q"), q + 1) + 1
            spec = _quoted(text, q, end)
            if "${" in spec or not spec:
                continue
            seen.add(q)
            out.append(RawImport(lines.at(m.start()), lines.at(q), spec, kind))
    out.sort(key=lambda r: (r.line, r.module))
    return out


# --------------------------------------------------------------------------- java

_JAVA_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
_JAVA_IMPORT = re.compile(r"^[ \t]*import\s+(static\s+)?([\w.]+?)(\s*\.\s*\*)?\s*;", re.M)


def extract_java(text: str) -> tuple[str | None, list[RawImport]]:
    """``(package, imports)`` of a Java source file."""
    masked = mask(text, _JAVA_LEX)
    lines = _Lines(text)
    pm = _JAVA_PACKAGE.search(masked)
    package = pm.group(1) if pm else None
    out: list[RawImport] = []
    for m in _JAVA_IMPORT.finditer(masked):
        static, name, star = m.group(1), m.group(2), m.group(3)
        kind = "wildcard" if star else "static" if static else "import"
        if star and static:
            kind = "static-wildcard"
        start = lines.at(m.start(2))
        out.append(RawImport(start, lines.at(m.end() - 1), name, kind))
    return package, out


# --------------------------------------------------------------------------- go

_GO_STR = r"(?:\"[^\"\n]*\"|`[^`]*`)"
_GO_SINGLE = re.compile(r"^import[ \t]+(?:(?P<alias>[\w.]+)[ \t]+)?(?P<spec>" + _GO_STR + ")", re.M)
_GO_BLOCK = re.compile(r"^import[ \t]*\((?P<body>[^)]*)\)", re.M)
_GO_ITEM = re.compile(r"(?:(?P<alias>[\w.]+)[ \t]+)?(?P<spec>" + _GO_STR + ")")


def extract_go(text: str) -> list[RawImport]:
    masked = mask(text, _GO_LEX)
    lines = _Lines(text)
    out: list[RawImport] = []

    def add(m: re.Match[str], offset: int = 0) -> None:
        s, e = m.start("spec") + offset, m.end("spec") + offset
        ln = lines.at(s)
        out.append(RawImport(ln, ln, _quoted(text, s, e), "import", alias=m.group("alias")))

    for m in _GO_SINGLE.finditer(masked):
        add(m)
    for b in _GO_BLOCK.finditer(masked):
        for m in _GO_ITEM.finditer(b.group("body")):
            add(m, b.start("body"))
    out.sort(key=lambda r: r.line)
    return out


_GO_MODULE = re.compile(r"^\s*module\s+\"?([^\s\"]+)\"?", re.M)
_GO_REPLACE_LINE = re.compile(r"^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s*=>\s*(\.{1,2}/\S*)\s*$")


def parse_go_mod(text: str) -> tuple[str | None, list[tuple[str, str]]]:
    """``(module path, [(replaced module, local relative dir)])`` from a go.mod file."""
    m = _GO_MODULE.search(text)
    module = m.group(1) if m else None
    replaces: list[tuple[str, str]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("replace") and line.rstrip().endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("replace ") or in_block:
            rm = _GO_REPLACE_LINE.match(line)
            if rm:
                replaces.append((rm.group(1), rm.group(2)))
    return module, replaces


# --------------------------------------------------------------------------- stdlib lists

PY_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | {"__future__"}

NODE_BUILTINS = frozenset(
    """assert async_hooks buffer child_process cluster console constants crypto dgram
    diagnostics_channel dns domain events fs http http2 https inspector module net os path
    perf_hooks process punycode querystring readline repl stream string_decoder sys timers
    tls trace_events tty url util v8 vm wasi worker_threads zlib test""".split()
)

JAVA_STDLIB_PREFIXES = (
    "java.", "javax.", "jdk.", "sun.", "com.sun.", "org.w3c.dom.", "org.xml.sax.",
    "org.ietf.jgss.", "org.omg.",
)  # fmt: skip

JS_EXTENSIONS = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_JS_TS_TWINS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}


def _js_package(spec: str) -> str:
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def _java_package_root(name: str) -> str:
    parts = name.split(".")
    return ".".join(parts[:2]) if len(parts) > 2 else name


def _go_package_root(path: str) -> str:
    parts = path.split("/")
    if parts[0] in ("github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 3:
        root = parts[:3]
        if len(parts) > 3 and re.fullmatch(r"v\d+", parts[3]):
            root.append(parts[3])
        return "/".join(root)
    return path


# --------------------------------------------------------------------------- resolver


_PyHit = tuple[Category, "str | None", "str | None", tuple[str, ...], str]
"""(category, target, package, names, module-as-shown) for one Python edge."""


class _Resolver:
    def __init__(self, files: FileIndex) -> None:
        self.paths = {f.path for f in files}
        py = [f.path for f in files if f.path.endswith((".py", ".pyi"))]
        self.py_packages = {
            posixpath.dirname(p)
            for p in py
            if posixpath.basename(p) in ("__init__.py", "__init__.pyi")
        }
        # Every directory that holds Python code, directly or below (namespace packages).
        self.py_dirs: set[str] = set()
        for p in py:
            d = posixpath.dirname(p)
            while d and d not in self.py_dirs:
                self.py_dirs.add(d)
                d = posixpath.dirname(d)
        self.py_roots = self._python_roots(py)
        self.java_classes: dict[str, str] = {}
        self.java_packages: dict[str, list[str]] = defaultdict(list)
        self.go_modules: list[tuple[str, str]] = []  # (module path, repo dir), longest first
        self.dirs_with_go = {posixpath.dirname(f.path) for f in files if f.path.endswith(".go")}

    # -- python
    def _python_roots(self, py: list[str]) -> list[str]:
        roots = {""}
        for d in ("src", "lib"):
            if any(p.startswith(d + "/") for p in py):
                roots.add(d)
        for pkg in self.py_packages:
            top = pkg
            while posixpath.dirname(top) in self.py_packages:
                top = posixpath.dirname(top)
            if top:
                roots.add(posixpath.dirname(top))
        return sorted(roots, key=lambda r: (r != "", r))

    def _roots_for(self, source: str) -> list[str]:
        src_dir = posixpath.dirname(source)
        if src_dir in self.py_packages or src_dir in self.py_roots:
            return self.py_roots
        return [src_dir, *self.py_roots]  # a script's own directory is on sys.path

    @staticmethod
    def _join(base: str, dotted: str) -> str:
        rel = dotted.replace(".", "/")
        return posixpath.join(base, rel) if base and rel else base or rel

    def _py_module_file(self, base: str, dotted: str) -> str | None:
        stem = self._join(base, dotted)
        pre = stem + "/" if stem else ""
        cands = [f"{pre}__init__.py", f"{pre}__init__.pyi"]
        if stem:
            cands = [f"{stem}.py", *cands, f"{stem}.pyi"]
        for c in cands:
            if c in self.paths:
                return c
        return None

    def python(self, source: str, raw: RawImport) -> list[_PyHit]:
        shown = "." * raw.level + raw.module
        if raw.level:
            base = posixpath.dirname(source)
            for _ in range(raw.level - 1):
                if not base:
                    return [("unresolved", None, None, raw.names, shown)]
                base = posixpath.dirname(base)
            mod_file = self._py_module_file(base, raw.module)
            return self._py_from(self._join(base, raw.module), mod_file, raw.names, shown)

        roots = self._roots_for(source)
        if raw.kind == "from":
            for root in roots:
                mod_file = self._py_module_file(root, raw.module)
                pkg_dir = self._join(root, raw.module)
                if mod_file or pkg_dir in self.py_dirs:
                    return self._py_from(pkg_dir, mod_file, raw.names, shown)
        # Deepest local prefix: a.b.c -> a/b/c.py, else a/b, else a.
        parts = raw.module.split(".")
        for n in range(len(parts), 0, -1):
            for root in roots:
                hit = self._py_module_file(root, ".".join(parts[:n]))
                if hit:
                    return [("local", hit, None, raw.names, shown)]
        top = parts[0]
        cat: Category = "stdlib" if top in PY_STDLIB else "external"
        return [(cat, None, top, raw.names, shown)]

    def _py_from(
        self, pkg_dir: str, mod_file: str | None, names: tuple[str, ...], shown: str
    ) -> list[_PyHit]:
        """``from <pkg_dir> import names``: an edge per name that is a submodule, plus one
        edge to the module/package itself for the remaining names."""
        out: list[_PyHit] = []
        rest: list[str] = []
        for n in names:
            sub = self._py_module_file(pkg_dir, n) if n != "*" else None
            if sub and sub != mod_file:
                out.append(("local", sub, None, (n,), shown))
            else:
                rest.append(n)
        if rest or not out:
            cat: Category = "local" if mod_file else "unresolved"
            out.insert(0, (cat, mod_file, None, tuple(rest), shown))
        return out

    # -- js/ts
    def js(self, source: str, spec: str) -> tuple[Category, str | None, str | None]:
        clean = spec.split("?", 1)[0].split("#", 1)[0] if not spec.startswith("#") else spec
        if clean.startswith(("./", "../")) or clean in (".", ".."):
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(source), clean))
            if joined == ".." or joined.startswith("../"):
                return "unresolved", None, None
            hit = self._js_file(joined)
            return ("local", hit, None) if hit else ("unresolved", None, None)
        if clean.startswith("node:"):
            return "stdlib", None, clean[5:].split("/")[0]
        if clean.startswith(("@/", "~/", "#", "/")) or not clean:
            return "unresolved", None, None
        pkg = _js_package(clean)
        if pkg in NODE_BUILTINS:
            return "stdlib", None, pkg
        return "external", None, pkg

    def _js_file(self, p: str) -> str | None:
        if p == ".":
            p = ""
        if p in self.paths:
            return p
        for ext in JS_EXTENSIONS:
            if p + ext in self.paths:
                return p + ext
        stem, ext = posixpath.splitext(p)
        for twin in _JS_TS_TWINS.get(ext, ()):
            if stem + twin in self.paths:
                return stem + twin
        for ext in JS_EXTENSIONS + (".json",):
            cand = posixpath.join(p, "index" + ext) if p else "index" + ext
            if cand in self.paths:
                return cand
        return None

    # -- java
    def add_java(self, path: str, package: str | None) -> None:
        stem = posixpath.splitext(posixpath.basename(path))[0]
        fq = f"{package}.{stem}" if package else stem
        self.java_classes.setdefault(fq, path)
        self.java_packages[package or ""].append(path)

    def java(self, raw: RawImport) -> list[tuple[Category, str | None, str | None]]:
        name = raw.module
        if raw.kind == "wildcard" and name in self.java_packages:
            return [("local", p, None) for p in sorted(self.java_packages[name])]
        parts = name.split(".")
        for n in range(len(parts), 0, -1):
            hit = self.java_classes.get(".".join(parts[:n]))
            if hit:
                return [("local", hit, None)]
        if (name + ".").startswith(JAVA_STDLIB_PREFIXES):
            return [("stdlib", None, ".".join(parts[:2]))]
        if any(name == p or name.startswith(p + ".") for p in self.java_packages if p):
            return [("unresolved", None, None)]
        return [("external", None, _java_package_root(name))]

    # -- go
    def add_go_mod(self, path: str, text: str) -> None:
        module, replaces = parse_go_mod(text)
        d = posixpath.dirname(path)
        if module:
            self.go_modules.append((module, d))
        for mod, rel in replaces:
            target = posixpath.normpath(posixpath.join(d, rel))
            if not target.startswith(".."):
                self.go_modules.append((mod, "" if target == "." else target))
        self.go_modules.sort(key=lambda m: -len(m[0]))

    def go(self, spec: str) -> tuple[Category, str | None, str | None]:
        for module, d in self.go_modules:
            if spec == module or spec.startswith(module + "/"):
                rest = spec[len(module) + 1 :] if spec != module else ""
                pkg_dir = posixpath.join(d, rest) if d else rest
                if pkg_dir in self.dirs_with_go:
                    return "local", pkg_dir, None
                return "unresolved", None, None
        if "." not in spec.split("/")[0]:
            return "stdlib", None, spec
        return "external", None, _go_package_root(spec)


# --------------------------------------------------------------------------- driver


def _read(files: FileIndex, entry: FileEntry) -> str | None:
    try:
        data = (files.root / entry.path).read_bytes()
    except OSError:
        return None
    text = data.decode("utf-8", "replace")
    return text[1:] if text.startswith("﻿") else text


def build_import_graph(files: FileIndex) -> ImportGraph:
    """Extract and resolve the imports of every parseable source file in ``files``."""
    resolver = _Resolver(files)
    errors: list[tuple[str, str]] = []
    texts: dict[str, str] = {}
    for f in files:
        if f.parseable and (
            f.language in IMPORT_LANGUAGES or f.path.endswith("/go.mod") or f.path == "go.mod"
        ):
            t = _read(files, f)
            if t is None:
                errors.append((f.path, "could not read file"))
                continue
            texts[f.path] = t

    java_raw: dict[str, list[RawImport]] = {}
    for path, t in texts.items():
        if path == "go.mod" or path.endswith("/go.mod"):
            resolver.add_go_mod(path, t)
        elif files.get(path).language == "java":  # type: ignore[union-attr]
            package, raws = extract_java(t)
            resolver.add_java(path, package)
            java_raw[path] = raws

    edges: list[ImportEdge] = []
    for path, t in texts.items():
        lang = files.get(path).language  # type: ignore[union-attr]
        if lang == "python":
            raws, err = extract_python(t)
            if err:
                errors.append((path, err))
            for r in raws:
                for cat, target, pkg, names, module in resolver.python(path, r):
                    edges.append(
                        ImportEdge(
                            path, r.line, r.end_line, lang, module, r.kind, cat, target, pkg, names
                        )
                    )
        elif lang in ("javascript", "typescript"):
            for r in extract_js(t):
                cat, target, pkg = resolver.js(path, r.module)
                edges.append(
                    ImportEdge(path, r.line, r.end_line, lang, r.module, r.kind, cat, target, pkg)
                )
        elif lang == "java":
            for r in java_raw.get(path, []):
                for cat, target, pkg in resolver.java(r):
                    edges.append(
                        ImportEdge(
                            path, r.line, r.end_line, lang, r.module, r.kind, cat, target, pkg
                        )
                    )
        elif lang == "go":
            for r in extract_go(t):
                cat, target, pkg = resolver.go(r.module)
                edges.append(
                    ImportEdge(path, r.line, r.end_line, lang, r.module, r.kind, cat, target, pkg)
                )
    edges.sort(key=lambda e: (e.source, e.line, e.module, e.target or ""))
    return ImportGraph(edges=edges, errors=errors)
