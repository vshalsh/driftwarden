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


def _resolve(value: str | None, props: dict[str, str]) -> str | None:
    if value is None:
        return None
    for _ in range(10):  # bounded: properties may reference properties
        new = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value.strip() or None


def parse(text: str, path: str) -> list[DependencyRef]:
    root = parse_xml(text)
    if root.tag != "project":
        raise ManifestError(f"pom.xml root element is <{root.tag}>, expected <project>")
    props = _props(root)
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
