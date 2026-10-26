"""Python manifests: ``requirements*.txt`` / ``*.in`` and ``pyproject.toml``.

pyproject.toml coverage: PEP 621 ``[project] dependencies`` and
``optional-dependencies``, PEP 735 ``[dependency-groups]``, ``[build-system]
requires``, and Poetry's ``[tool.poetry.*dependencies]`` tables.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from driftwarden.index.manifests._common import LineFinder, ManifestError, quoted, tomllib
from driftwarden.models import DependencyRef
from driftwarden.text import split_lines

ECOSYSTEM = "pypi"

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_PEP508 = re.compile(
    rf"""^\s*(?P<name>{_NAME})\s*
         (?:\[(?P<extras>[^\]]*)\])?\s*
         (?P<rest>[^;]*?)\s*
         (?:;(?P<marker>.*))?$""",
    re.X,
)
_EGG = re.compile(rf"[#&]egg=(?P<name>{_NAME})")


def canonical_name(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def canonical_spec(spec: str | None) -> str | None:
    """Whitespace-free PEP 440 specifier set with clauses sorted (``<2, >=1`` == ``>=1,<2``)."""
    if spec is None:
        return None
    s = re.sub(r"\s+", "", spec)
    if s.startswith("@"):
        return s
    return ",".join(sorted(p for p in s.split(",") if p)) or None


def parse_requirement(req: str) -> tuple[str, str | None] | None:
    """PEP 508 string -> (name, version_spec). None if it is not a requirement."""
    m = _PEP508.match(req)
    if not m:
        return None
    rest = m.group("rest").strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    if rest.startswith("@"):
        return m.group("name"), "@ " + rest[1:].strip()
    if rest and not re.match(r"^(?:===|~=|==|!=|<=|>=|<|>)", rest):
        return None  # garbage after the name
    return m.group("name"), (re.sub(r"\s+", "", rest) or None)


# --------------------------------------------------------------------------- requirements


def matches_requirements(path: str) -> bool:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name.endswith((".txt", ".in")) and ("requirements" in name or name == "constraints.txt"):
        return True
    return p.parent.name.lower() == "requirements" and name.endswith((".txt", ".in"))


def parse_requirements(text: str, path: str) -> list[DependencyRef]:
    lines = split_lines(text)
    refs: list[DependencyRef] = []
    i = 0
    while i < len(lines):
        start = i
        logical = lines[i]
        while logical.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            logical = logical.rstrip()[:-1] + " " + lines[i]
        i += 1
        body = re.sub(r"(^|\s)#.*$", "", logical).strip()
        if not body:
            continue
        if body.startswith("-"):
            # -r/-c includes, --index-url etc. are not dependencies; -e VCS with #egg is.
            m = _EGG.search(body) if re.match(r"^(-e|--editable)\b", body) else None
            if m:
                url = re.split(r"\s+", body, maxsplit=1)[1].strip()
                refs.append(_ref(m.group("name"), "@ " + url, path, start + 1, None))
            continue
        body = re.split(r"\s+--?[a-z]", body, maxsplit=1)[0]  # per-line options (--hash=...)
        parsed = parse_requirement(body)
        if parsed is None:
            m = _EGG.search(body)
            if m:  # bare VCS URL with #egg=
                refs.append(_ref(m.group("name"), "@ " + body, path, start + 1, None))
            continue
        refs.append(_ref(parsed[0], parsed[1], path, start + 1, None))
    return refs


def _ref(name: str, spec: str | None, path: str, line: int, scope: str | None) -> DependencyRef:
    return DependencyRef(
        ecosystem=ECOSYSTEM,
        package=name,
        version_spec=spec,
        manifest_path=path,
        line=line,
        scope=scope,
    )


# --------------------------------------------------------------------------- pyproject


def matches_pyproject(path: str) -> bool:
    return PurePosixPath(path).name == "pyproject.toml"


def _header_rx(dotted: str) -> re.Pattern[str]:
    parts = [re.escape(p) for p in dotted.split(".")]
    sep = r"\s*\.\s*"
    alt = sep.join(rf"""(?:{p}|"{p}"|'{p}')""" for p in parts)
    return re.compile(rf"^\s*\[\s*{alt}\s*\]")


def _section_bounds(lf: LineFinder, dotted: str) -> tuple[int, int | None]:
    start = lf.peek(_header_rx(dotted))
    if start is None:
        return 1, None
    nxt = lf.peek(r"^\s*\[", start + 1)
    return start, (nxt - 1) if nxt else None


def parse_pyproject(text: str, path: str) -> list[DependencyRef]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"TOML: {exc}") from None
    lf = LineFinder(text)
    refs: list[DependencyRef] = []

    def from_list(reqs: Any, section: str, scope: str | None) -> None:
        if not isinstance(reqs, list):
            return
        lo, hi = _section_bounds(lf, section)
        for req in reqs:
            if not isinstance(req, str):
                continue  # e.g. PEP 735 {include-group = "..."}
            parsed = parse_requirement(req)
            if parsed is None:
                continue
            line = lf.find(quoted(req), lo, hi)
            refs.append(_ref(parsed[0], parsed[1], path, line, scope))

    project = data.get("project")
    if isinstance(project, dict):
        from_list(project.get("dependencies"), "project", None)
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for extra, reqs in opt.items():
                section = "project.optional-dependencies"
                if _section_bounds(lf, section) == (1, None):
                    section = "project"
                from_list(reqs, section, f"optional:{extra}")

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group, reqs in groups.items():
            from_list(reqs, "dependency-groups", f"group:{group}")

    build = data.get("build-system")
    if isinstance(build, dict):
        from_list(build.get("requires"), "build-system", "build")

    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        tables: list[tuple[str, Any, str | None]] = [
            ("tool.poetry.dependencies", poetry.get("dependencies"), None),
            ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies"), "dev"),
        ]
        group = poetry.get("group")
        if isinstance(group, dict):
            for g, body in group.items():
                if isinstance(body, dict):
                    tables.append(
                        (f"tool.poetry.group.{g}.dependencies", body.get("dependencies"), g)
                    )
        for section, table, scope in tables:
            if not isinstance(table, dict):
                continue
            lo, hi = _section_bounds(lf, section)
            for name, spec in table.items():
                if name.lower() == "python":
                    continue
                key = rf"""^\s*(?:{re.escape(name)}|"{re.escape(name)}"|'{re.escape(name)}')\s*="""
                own = lf.peek(_header_rx(f"{section}.{name}"))
                line = own if own is not None else lf.find(key, lo, hi)
                refs.append(_ref(name, _poetry_spec(spec), path, line, scope))
    return refs


def _poetry_spec(spec: Any) -> str | None:
    if isinstance(spec, str):
        return spec.strip() or None
    if isinstance(spec, dict):
        if isinstance(spec.get("version"), str):
            return spec["version"].strip() or None
        for k in ("git", "url", "path"):
            if isinstance(spec.get(k), str):
                return f"@ {spec[k]}"
    if isinstance(spec, list):  # multiple-constraint form
        parts = [_poetry_spec(s) for s in spec]
        return " || ".join(p for p in parts if p) or None
    return None
