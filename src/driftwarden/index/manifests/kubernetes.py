"""Kubernetes manifests: container images in any workload (Pod, Deployment,
StatefulSet, DaemonSet, Job, CronJob, custom resources with a pod template ...).

A YAML file counts as a Kubernetes manifest when it has top-level
``apiVersion:`` and ``kind:`` keys. Every ``image:`` under a ``containers`` /
``initContainers`` / ``ephemeralContainers`` list is reported, with scope
``<Kind>/<metadata.name>``.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

import yaml

from driftwarden.index.manifests._common import (
    compose_yaml,
    split_image,
    yline,
    ymap_get,
    ymap_items,
    yscalar,
)
from driftwarden.models import DependencyRef

ECOSYSTEM = "docker"
CONTAINER_KEYS = ("containers", "initContainers", "ephemeralContainers")
_API = re.compile(r"^apiVersion\s*:", re.M)
_KIND = re.compile(r"^kind\s*:", re.M)


def matches(path: str, text: str | None = None) -> bool:
    if not PurePosixPath(path).name.lower().endswith((".yaml", ".yml")):
        return False
    if text is None:
        return True
    return bool(_API.search(text) and _KIND.search(text))


def parse(text: str, path: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for doc in compose_yaml(text):
        kind = yscalar(ymap_get(doc, "kind")) or "?"
        name = yscalar(ymap_get(ymap_get(doc, "metadata"), "name")) or "?"
        for img in _images(doc):
            image = yscalar(img)
            if not image:
                continue
            pkg, version = split_image(image)
            if pkg:
                refs.append(
                    DependencyRef(
                        ecosystem=ECOSYSTEM,
                        package=pkg,
                        version_spec=version,
                        manifest_path=path,
                        line=yline(img),
                        scope=f"{kind}/{name}",
                    )
                )
    return refs


def _images(root: yaml.Node) -> list[yaml.Node]:
    """``image`` nodes of every container list, in document order. Alias-safe."""
    found: list[yaml.Node] = []
    seen: set[int] = set()
    stack: list[yaml.Node] = [root]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in ymap_items(node):
                if key in CONTAINER_KEYS and isinstance(value, yaml.SequenceNode):
                    for c in value.value:
                        img = ymap_get(c, "image")
                        if img is not None and id(img) not in seen:
                            seen.add(id(img))
                            found.append(img)
            stack.extend(reversed([v for _, v in node.value]))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(reversed(node.value))
    found.sort(key=lambda n: (n.start_mark.line, n.start_mark.column))
    return found
