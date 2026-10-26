"""JavaScript / TypeScript: ``package.json``."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import ManifestError
from driftwarden.models import DependencyRef
from driftwarden.text import split_lines

ECOSYSTEM = "npm"

SECTIONS = {
    "dependencies": None,
    "devDependencies": "dev",
    "peerDependencies": "peer",
    "optionalDependencies": "optional",
}
# A JSON object key at the start of a line: "name" :
_KEY = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:')


def matches(path: str) -> bool:
    return PurePosixPath(path).name == "package.json"


def _key_lines(text: str) -> dict[str, list[int]]:
    """Decoded key -> 1-based lines where it starts a line, in file order. One pass.

    Keys are JSON-decoded, so ``"caf\\u00e9"`` and ``"café"`` index the same.
    """
    index: dict[str, list[int]] = defaultdict(list)
    for n, line in enumerate(split_lines(text), 1):
        m = _KEY.match(line)
        if not m:
            continue
        try:
            key = json.loads(f'"{m.group(1)}"')
        except json.JSONDecodeError:
            continue
        index[key].append(n)
    return index


def parse(text: str, path: str) -> list[DependencyRef]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ManifestError("JSON: top level is not an object")
    index = _key_lines(text)
    used: set[int] = set()

    def take(key: str, lo: int) -> int:
        # Each key occurs on very few lines, so this is O(1) per lookup in practice.
        for n in index.get(key, ()):
            if n >= lo and n not in used:
                used.add(n)
                return n
        return lo  # e.g. minified JSON: fall back to the section's line

    refs: list[DependencyRef] = []
    for section, scope in SECTIONS.items():
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        lo = take(section, 1)
        for name, spec in deps.items():
            if not isinstance(name, str) or not name:
                continue
            refs.append(
                DependencyRef(
                    ecosystem=ECOSYSTEM,
                    package=name,
                    version_spec=(spec.strip() or None) if isinstance(spec, str) else None,
                    manifest_path=path,
                    line=take(name, lo),
                    scope=scope,
                )
            )
    return refs
