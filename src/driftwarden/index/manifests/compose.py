"""docker-compose / Compose Specification files: ``services.<name>.image``.

Variable interpolation (``${TAG:-1.2}``) is kept verbatim: the manifest says
exactly that, and the verifier compares against what the manifest says.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import (
    ManifestError,
    compose_yaml,
    split_image,
    yline,
    ymap_get,
    ymap_items,
    yscalar,
)
from driftwarden.models import DependencyRef

ECOSYSTEM = "docker"
_NAME = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$", re.I)


def matches(path: str) -> bool:
    return bool(_NAME.match(PurePosixPath(path).name))


def parse(text: str, path: str) -> list[DependencyRef]:
    docs = compose_yaml(text)
    refs: list[DependencyRef] = []
    for doc in docs:
        services = ymap_get(doc, "services")
        if services is None:
            if ymap_get(doc, "version") is None and docs and len(docs) == 1:
                # compose v1: services at top level
                services = doc
            else:
                continue
        for name, svc in ymap_items(services):
            img_node = ymap_get(svc, "image")
            image = yscalar(img_node)
            if not image or img_node is None:
                continue
            pkg, version = split_image(image)
            if not pkg:
                continue
            refs.append(
                DependencyRef(
                    ecosystem=ECOSYSTEM,
                    package=pkg,
                    version_spec=version,
                    manifest_path=path,
                    line=yline(img_node),
                    scope=f"service:{name}",
                )
            )
    if not docs:
        raise ManifestError("compose file is empty")
    return refs
