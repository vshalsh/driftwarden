"""Java / Maven: ``pom.xml``.

Reports ``<parent>``, every ``<dependency>`` (including dependencyManagement and
profiles) and build ``<plugin>`` entries as ``groupId:artifactId``. ``${prop}``
references are resolved from ``<properties>`` and the project's own coordinates;
unresolvable ones are kept verbatim.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import ManifestError, XmlNode, parse_xml
from driftwarden.models import DependencyRef

ECOSYSTEM = "maven"
_PROP = re.compile(r"\$\{([^}]+)\}")


def matches(path: str) -> bool:
    name = PurePosixPath(path).name
    return name == "pom.xml" or name.endswith(".pom")


def _props(root: XmlNode) -> dict[str, str]:
    props: dict[str, str] = {}
    p = root.child("properties")
    if p is not None:
        for c in p.children:
            props[c.tag] = c.text.strip()
    parent = root.child("parent")
    for key in ("groupId", "artifactId", "version"):
        own = root.child_text(key)
        par = parent.child_text(key) if parent is not None else None
        if par:
            props[f"project.parent.{key}"] = par
        if own or par:
            props[f"project.{key}"] = own or par or ""
    return props


EXPANSION_BUDGET = 64 * 1024  # max characters of any expanded value


class _Resolver:
    """``${prop}`` expansion with cycle detection and a size budget.

    Each property is expanded once (memoised). The length of an expansion is
    computed from its parts *before* the string is built, so a property bomb
    (``<v>${v}${v}...</v>`` or a chain of ten-fold references) is rejected with
    a ManifestError without allocating it. Unknown properties stay verbatim.
    """

    def __init__(self, props: dict[str, str]) -> None:
        self.props = props
        self.memo: dict[str, str] = {}
        self.active: set[str] = set()

    def prop(self, name: str) -> str:
        if name in self.memo:
            return self.memo[name]
        if name in self.active:
            raise ManifestError(f"pom.xml: property cycle through ${{{name}}}")
        self.active.add(name)
        try:
            value = self.expand(self.props[name])
        finally:
            self.active.discard(name)
        self.memo[name] = value
        return value

    def expand(self, value: str) -> str:
        parts: list[str] = []
        size = 0
        pos = 0
        for m in _PROP.finditer(value):
            name = m.group(1)
            piece = self.prop(name) if name in self.props else m.group(0)
            for chunk in (value[pos : m.start()], piece):
                size += len(chunk)
                if size > EXPANSION_BUDGET:
                    raise ManifestError(
                        f"pom.xml: property expansion exceeds budget of {EXPANSION_BUDGET} chars"
                    )
                parts.append(chunk)
            pos = m.end()
        tail = value[pos:]
        if size + len(tail) > EXPANSION_BUDGET:
            raise ManifestError(
                f"pom.xml: property expansion exceeds budget of {EXPANSION_BUDGET} chars"
            )
        parts.append(tail)
        return "".join(parts)


def _resolve(value: str | None, resolver: _Resolver) -> str | None:
    if value is None:
        return None
    return resolver.expand(value).strip() or None


def parse(text: str, path: str) -> list[DependencyRef]:
    root = parse_xml(text)
    if root.tag != "project":
        raise ManifestError(f"pom.xml root element is <{root.tag}>, expected <project>")
    props = _Resolver(_props(root))
    refs: list[DependencyRef] = []

    def add(node: XmlNode, scope: str | None) -> None:
        group = _resolve(node.child_text("groupId"), props)
        artifact = _resolve(node.child_text("artifactId"), props)
        if not artifact:
            return
        if not group and node.tag == "plugin":
            group = "org.apache.maven.plugins"  # Maven's default plugin group
        if not group:
            return
        refs.append(
            DependencyRef(
                ecosystem=ECOSYSTEM,
                package=f"{group}:{artifact}",
                version_spec=_resolve(node.child_text("version"), props),
                manifest_path=path,
                line=node.line,
                scope=scope,
            )
        )

    parent = root.child("parent")
    if parent is not None:
        add(parent, "parent")
    for node in root.iter():
        if node.tag == "dependency":
            add(node, _resolve(node.child_text("scope"), props))
        elif node.tag == "plugin":
            add(node, "plugin")
    return refs
