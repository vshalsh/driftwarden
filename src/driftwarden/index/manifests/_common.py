"""Helpers shared by the manifest parsers: errors, line lookup, XML/YAML with lines,
container image references.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from xml.parsers import expat

import yaml

from driftwarden.text import split_lines

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

__all__ = ["tomllib"]


class ManifestError(ValueError):
    """The manifest is malformed beyond what the parser can recover from."""


# --------------------------------------------------------------------------- lines


class LineFinder:
    """Find the 1-based line of a declaration in raw text.

    Parsers built on libraries without position info (tomllib, json) use this to
    map a parsed entry back to its line. Lines are consumed once each so that two
    identical entries get two different lines, deterministically in file order.
    """

    def __init__(self, text: str) -> None:
        self.lines = split_lines(text)
        self._used: set[int] = set()

    def find(self, pattern: str | re.Pattern[str], start: int = 1, end: int | None = None) -> int:
        """First unused line in ``start..end`` (1-based, inclusive) matching ``pattern``.

        Falls back to the first matching line (used or not), then to ``start``.
        """
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        hi = len(self.lines) if end is None else min(end, len(self.lines))
        first: int | None = None
        for n in range(max(start, 1), hi + 1):
            if rx.search(self.lines[n - 1]):
                if n not in self._used:
                    self._used.add(n)
                    return n
                if first is None:
                    first = n
        return first if first is not None else max(start, 1)

    def peek(self, pattern: str | re.Pattern[str], start: int = 1) -> int | None:
        """First line matching ``pattern`` at or after ``start``, without consuming it."""
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        for n in range(max(start, 1), len(self.lines) + 1):
            if rx.search(self.lines[n - 1]):
                return n
        return None


def strip_toml_comments(text: str) -> str:
    """``text`` with TOML ``#`` comments removed, line structure unchanged.

    String-aware (basic, literal and multi-line strings), so ``#`` inside a
    value such as ``"pkg @ https://x/p.whl#sha256=..."`` is kept. Used so that
    line lookups never land on a commented-out copy of a declaration.
    """
    out: list[str] = []
    mode = ""  # "", '"', "'", '"""', "'''"
    for line in split_lines(text):
        buf: list[str] = []
        i, n = 0, len(line)
        while i < n:
            ch = line[i]
            if mode in ('"""', "'''"):
                if line.startswith(mode, i):
                    buf.append(mode)
                    i += 3
                    mode = ""
                    continue
                if mode == '"""' and ch == "\\" and i + 1 < n:
                    buf.append(line[i : i + 2])
                    i += 2
                    continue
                buf.append(ch)
                i += 1
                continue
            if mode in ('"', "'"):
                buf.append(ch)
                if mode == '"' and ch == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == mode:
                    mode = ""
                i += 1
                continue
            if ch == "#":
                break
            if line.startswith(('"""', "'''"), i):
                mode = line[i : i + 3]
                buf.append(mode)
                i += 3
                continue
            if ch in "\"'":
                mode = ch
            buf.append(ch)
            i += 1
        if mode in ('"', "'"):
            mode = ""  # single-line strings cannot span lines
        out.append("".join(buf))
    return "\n".join(out) + "\n"


def quoted(value: str) -> str:
    """Regex matching ``value`` as a quoted string literal ("..." or '...')."""
    v = re.escape(value)
    return rf"""(?:"{v}"|'{v}')"""


# --------------------------------------------------------------------------- XML


@dataclass
class XmlNode:
    tag: str  # local name, namespace prefix/URI stripped
    attrs: dict[str, str]
    line: int  # 1-based line of the start tag
    children: list[XmlNode] = field(default_factory=list)
    text: str = ""

    def child(self, tag: str) -> XmlNode | None:
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def child_text(self, tag: str) -> str | None:
        c = self.child(tag)
        return c.text.strip() if c is not None else None

    def iter(self, tag: str | None = None) -> Iterator[XmlNode]:
        stack = [self]
        while stack:
            node = stack.pop()
            if tag is None or node.tag == tag:
                yield node
            stack.extend(reversed(node.children))

    def attr(self, name: str) -> str | None:
        """Attribute by name, case-insensitively (MSBuild is case-insensitive)."""
        for k, v in self.attrs.items():
            if k.lower() == name.lower():
                return v
        return None


_DTD = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.I)


def _local(name: str) -> str:
    # expat with namespace_separator=" " gives "uri local"; plain gives "prefix:local".
    name = name.rsplit(" ", 1)[-1]
    return name.rsplit(":", 1)[-1]


def parse_xml(text: str) -> XmlNode:
    """Parse XML into an XmlNode tree with line numbers. Raises ManifestError.

    Manifests from untrusted repos must not be able to stall a scan, so any
    DOCTYPE or entity declaration is rejected outright (no pom.xml, csproj or
    packages.config needs one); this rules out entity-expansion bombs and
    external entities. Character data is collected in lists, not by repeated
    string concatenation.
    """
    if _DTD.search(text):
        raise ManifestError("XML: DOCTYPE / entity declarations are not allowed in manifests")
    parser = expat.ParserCreate(namespace_separator=" ")
    root: list[XmlNode] = []
    stack: list[tuple[XmlNode, list[str]]] = []

    def reject(*_args: object) -> None:
        raise ManifestError("XML: DOCTYPE / entity declarations are not allowed in manifests")

    def start(name: str, attrs: dict[str, str]) -> None:
        node = XmlNode(
            tag=_local(name),
            attrs={_local(k): v for k, v in attrs.items()},
            line=parser.CurrentLineNumber,
        )
        if stack:
            stack[-1][0].children.append(node)
        else:
            root.append(node)
        stack.append((node, []))

    def end(name: str) -> None:
        node, parts = stack.pop()
        node.text = "".join(parts)

    def chars(data: str) -> None:
        if stack:
            stack[-1][1].append(data)

    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(text, True)
    except expat.ExpatError as exc:
        raise ManifestError(f"XML: {exc}") from None
    if not root:
        raise ManifestError("XML: no root element")
    return root[0]


# --------------------------------------------------------------------------- YAML


def compose_yaml(text: str) -> list[yaml.Node]:
    """All YAML documents as position-carrying node trees. Raises ManifestError."""
    try:
        return [d for d in yaml.compose_all(text, Loader=yaml.SafeLoader) if d is not None]
    except yaml.YAMLError as exc:
        msg = str(exc).replace("\n", " ")
        raise ManifestError(f"YAML: {msg}") from None


_MERGE_TAG = "tag:yaml.org,2002:merge"


def _is_merge_key(k: yaml.Node) -> bool:
    return isinstance(k, yaml.ScalarNode) and (k.tag == _MERGE_TAG or k.value == "<<")


def ymap_items(
    node: yaml.Node | None, _seen: frozenset[int] = frozenset()
) -> list[tuple[str, yaml.Node]]:
    """Key/value pairs of a mapping with YAML merge keys (``<<: *base`` or
    ``<<: [*a, *b]``) resolved. Explicit keys override merged ones; in a merge
    list the first mapping wins. Values keep their own source positions (an
    inherited value points at the anchor's line). Cycle-safe.
    """
    if not isinstance(node, yaml.MappingNode) or id(node) in _seen:
        return []
    seen = _seen | {id(node)}
    explicit: list[tuple[str, yaml.Node]] = []
    merged: list[tuple[str, yaml.Node]] = []
    for k, v in node.value:
        if _is_merge_key(k):
            sources = v.value if isinstance(v, yaml.SequenceNode) else [v]
            for src in sources:
                merged.extend(ymap_items(src, seen))
        elif isinstance(k, yaml.ScalarNode):
            explicit.append((k.value, v))
    out: dict[str, yaml.Node] = {}
    for key, v in explicit:
        out.setdefault(key, v)
    for key, v in merged:
        out.setdefault(key, v)
    return list(out.items())


def ymap_get(node: yaml.Node | None, key: str) -> yaml.Node | None:
    for k, v in ymap_items(node):
        if k == key:
            return v
    return None


def yscalar(node: yaml.Node | None) -> str | None:
    if isinstance(node, yaml.ScalarNode) and node.tag != "tag:yaml.org,2002:null":
        return str(node.value)
    return None


def yline(node: yaml.Node) -> int:
    return node.start_mark.line + 1


# --------------------------------------------------------------------------- images


def split_image(ref: str) -> tuple[str, str | None]:
    """Split a container image reference into (name, version_spec).

    ``registry:5000/team/app:1.2@sha256:ab`` -> (``registry:5000/team/app``,
    ``1.2@sha256:ab``). The version is the tag and/or digest; None when neither
    is given (Docker would use ``latest``, but the manifest did not say so).
    """
    ref = ref.strip()
    digest: str | None = None
    name = ref
    if "@" in ref:
        name, digest = ref.split("@", 1)
    tag: str | None = None
    # Colons inside ${VAR:-default} interpolations are not tag separators.
    masked = re.sub(r"\$\{[^}]*\}", lambda m: "_" * len(m.group(0)), name)
    slash = masked.rfind("/")
    colon = masked.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
    version = tag
    if digest:
        version = f"{tag or ''}@{digest}"
    return name, (version or None)


def canonical_image(name: str) -> str:
    """Docker Hub aliases: ``nginx`` == ``library/nginx`` == ``docker.io/library/nginx``."""
    n = name.strip().lower()
    for prefix in ("index.docker.io/", "registry-1.docker.io/", "docker.io/"):
        if n.startswith(prefix):
            n = n[len(prefix) :]
            break
    if n.startswith("library/"):
        n = n[len("library/") :]
    return n
