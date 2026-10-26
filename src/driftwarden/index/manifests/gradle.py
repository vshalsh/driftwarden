"""Java / Kotlin: Gradle build scripts (Groovy and Kotlin DSL) and version catalogs.

Build scripts are not executed; dependencies are read from the literal forms
people actually write:

* ``implementation "g:a:v"`` / ``implementation("g:a:v")`` / ``api(platform("g:a:v"))``
* ``implementation group: "g", name: "a", version: "v"`` (and the Kotlin
  ``group = "g", name = "a"`` named-argument form)
* ``plugins { id("org.springframework.boot") version "3.2.0" }``
* ``gradle/libs.versions.toml`` ``[libraries]`` and ``[plugins]``

Anything computed (``libs.foo``, ``project(":core")``, string templates other
than a whole-version ``$var``) is skipped.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from driftwarden.index.manifests._common import (
    LineFinder,
    ManifestError,
    quoted,
    strip_toml_comments,
    tomllib,
)
from driftwarden.models import DependencyRef
from driftwarden.text import split_lines

CONFIGS = (
    "implementation|api|compileOnly|runtimeOnly|compileOnlyApi|annotationProcessor|"
    "kapt|ksp|classpath|developmentOnly|testImplementation|testCompileOnly|"
    "testRuntimeOnly|testAnnotationProcessor|androidTestImplementation|"
    "debugImplementation|releaseImplementation|compile|testCompile|runtime|"
    "testRuntime|providedCompile|providedRuntime|integrationTestImplementation"
)
_Q = r"""["']"""
_COORD = re.compile(
    rf"""(?<![\w.])(?P<cfg>{CONFIGS})\s*\(?\s*(?:(?:enforcedPlatform|platform)\s*\(\s*)?
         {_Q}(?P<coord>[^"'$:\s]+:[^"':\s]+(?::[^"'\s]*)?){_Q}""",
    re.X,
)
_MAP = re.compile(
    rf"""(?<![\w.])(?P<cfg>{CONFIGS})\s*\(?\s*group\s*[:=]\s*{_Q}(?P<g>[^"']+){_Q}\s*,\s*
         name\s*[:=]\s*{_Q}(?P<a>[^"']+){_Q}
         (?:\s*,\s*version\s*[:=]\s*{_Q}(?P<v>[^"']*){_Q})?""",
    re.X,
)
# id 'x' / id("x") / id "x" version '1' apply false / kotlin("jvm") version "1.9.22"
_PLUGIN = re.compile(
    rf"""(?<![\w.])(?:id\s*\(?\s*{_Q}(?P<id>[\w.-]+){_Q}|kotlin\s*\(\s*{_Q}(?P<kt>[\w.-]+){_Q})
         (?:\s*\))?
         (?:\s*version\s*\(?\s*{_Q}(?P<v>[^"']+){_Q})?""",
    re.X,
)
_TEST = re.compile(r"^(test|androidTest|integrationTest)")


def matches(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")


def matches_catalog(path: str) -> bool:
    return PurePosixPath(path).name.endswith(".versions.toml")


def _strip_comments(lines: list[str]) -> list[str]:
    """Blank out // and /* */ comments, keeping line numbering (strings respected)."""
    out: list[str] = []
    in_block = False
    for line in lines:
        buf: list[str] = []
        i, quote = 0, ""
        while i < len(line):
            ch, two = line[i], line[i : i + 2]
            if in_block:
                if two == "*/":
                    in_block, i = False, i + 2
                    continue
                i += 1
                continue
            if quote:
                buf.append(ch)
                if ch == "\\" and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if two == "//":
                break
            if two == "/*":
                in_block, i = True, i + 2
                continue
            if ch in "\"'":
                quote = ch
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


def _scope(cfg: str) -> str | None:
    if cfg in ("implementation", "api", "compile", "runtimeOnly", "runtime"):
        return None
    if _TEST.match(cfg):
        return "test"
    return cfg


def parse(text: str, path: str) -> list[DependencyRef]:
    lines = _strip_comments(split_lines(text))
    variables: dict[str, str] = {}
    var_rx = re.compile(rf"""^\s*(?:def|val|var|ext\.)?\s*(\w+)\s*=\s*{_Q}([^"'$]+){_Q}\s*$""")
    for line in lines:
        m = var_rx.match(line)
        if m:
            variables[m.group(1)] = m.group(2)
    refs: list[DependencyRef] = []
    in_plugins = False
    depth = 0
    for n, line in enumerate(lines, 1):
        if re.match(r"^\s*plugins\s*\{", line):
            in_plugins, depth = True, 0
        if in_plugins:
            for m in _PLUGIN.finditer(line):
                plugin = m.group("id") or f"org.jetbrains.kotlin.{m.group('kt')}"
                refs.append(
                    DependencyRef(
                        ecosystem="gradle-plugin",
                        package=plugin,
                        version_spec=m.group("v"),
                        manifest_path=path,
                        line=n,
                        scope="plugin",
                    )
                )
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_plugins = False
            continue
        for m in _COORD.finditer(line):
            parts = m.group("coord").split(":")
            version = parts[2] if len(parts) > 2 else None
            if version and version.startswith("$"):
                version = variables.get(version.lstrip("${").rstrip("}"), version)
            refs.append(_ref(f"{parts[0]}:{parts[1]}", version or None, path, n, m.group("cfg")))
        for m in _MAP.finditer(line):
            refs.append(
                _ref(f"{m.group('g')}:{m.group('a')}", m.group("v"), path, n, m.group("cfg"))
            )
    return refs


def _ref(pkg: str, version: str | None, path: str, line: int, cfg: str) -> DependencyRef:
    return DependencyRef(
        ecosystem="maven",
        package=pkg,
        version_spec=version,
        manifest_path=path,
        line=line,
        scope=_scope(cfg),
    )


def parse_catalog(text: str, path: str) -> list[DependencyRef]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"TOML: {exc}") from None
    lf = LineFinder(strip_toml_comments(text))
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    refs: list[DependencyRef] = []

    def version_of(spec: dict[str, Any]) -> str | None:
        v = spec.get("version")
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            if isinstance(v.get("ref"), str):
                ref = versions.get(v["ref"])
                return ref if isinstance(ref, str) else None
            for k in ("strictly", "require", "prefer"):
                if isinstance(v.get(k), str):
                    return v[k]
        ref = spec.get("version.ref")
        return versions.get(ref) if isinstance(ref, str) else None

    for table, eco in (("libraries", "maven"), ("plugins", "gradle-plugin")):
        body = data.get(table)
        if not isinstance(body, dict):
            continue
        lo = lf.peek(rf"^\s*\[\s*{table}\s*\]") or 1
        for alias, spec in body.items():
            key = rf"""^\s*(?:{re.escape(alias)}|{quoted(alias)})\s*="""
            line = lf.find(key, lo)
            pkg: str | None = None
            version: str | None = None
            if isinstance(spec, str):
                parts = spec.split(":")
                if eco == "maven" and len(parts) >= 2:
                    pkg, version = f"{parts[0]}:{parts[1]}", (parts[2] if len(parts) > 2 else None)
                elif eco == "gradle-plugin":
                    pkg, version = parts[0], (parts[1] if len(parts) > 1 else None)
            elif isinstance(spec, dict):
                if isinstance(spec.get("module"), str):
                    pkg = spec["module"]
                elif isinstance(spec.get("group"), str) and isinstance(spec.get("name"), str):
                    pkg = f"{spec['group']}:{spec['name']}"
                elif isinstance(spec.get("id"), str):
                    pkg = spec["id"]
                version = version_of(spec)
            if pkg:
                refs.append(
                    DependencyRef(
                        ecosystem=eco,
                        package=pkg,
                        version_spec=version or None,
                        manifest_path=path,
                        line=line,
                        scope=f"catalog:{alias}" if eco == "maven" else "plugin",
                    )
                )
    return refs
