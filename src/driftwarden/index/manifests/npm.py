"""JavaScript / TypeScript: ``package.json``."""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import LineFinder, ManifestError
from driftwarden.models import DependencyRef

ECOSYSTEM = "npm"

SECTIONS = {
    "dependencies": None,
    "devDependencies": "dev",
    "peerDependencies": "peer",
    "optionalDependencies": "optional",
}


def matches(path: str) -> bool:
    return PurePosixPath(path).name == "package.json"


def _json_key(key: str) -> str:
    return rf'"{re.escape(json.dumps(key)[1:-1])}"\s*:'


def parse(text: str, path: str) -> list[DependencyRef]:
    try:
        data = json.loads(text.lstrip("﻿"))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ManifestError("JSON: top level is not an object")
    lf = LineFinder(text)
    refs: list[DependencyRef] = []
    for section, scope in SECTIONS.items():
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        lo = lf.peek(_json_key(section)) or 1
        for name, spec in deps.items():
            if not isinstance(name, str) or not name:
                continue
            refs.append(
                DependencyRef(
                    ecosystem=ECOSYSTEM,
                    package=name,
                    version_spec=(spec.strip() or None) if isinstance(spec, str) else None,
                    manifest_path=path,
                    line=lf.find(_json_key(name), lo),
                    scope=scope,
                )
            )
    return refs
