"""Go: ``go.mod`` ``require`` directives (single-line and block form).

``// indirect`` requirements get scope ``indirect``. ``replace``/``exclude``/
``retract`` are not dependencies and are ignored.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import ManifestError
from driftwarden.models import DependencyRef
from driftwarden.text import split_lines

ECOSYSTEM = "go"
_REQ = re.compile(r'^\s*(?P<mod>"[^"]+"|`[^`]+`|[^\s"`]+)\s+(?P<ver>v[^\s/]+)\s*(?P<rest>.*)$')


def matches(path: str) -> bool:
    return PurePosixPath(path).name == "go.mod"


def parse(text: str, path: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    block: str | None = None
    saw_module = False
    for n, raw in enumerate(split_lines(text), 1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if block:
            if line.startswith(")"):
                block = None
                continue
            if block == "require":
                _add(refs, line, path, n)
            continue
        m = re.match(r"^(\w+)\s*(.*)$", line)
        if not m:
            raise ManifestError(f"go.mod line {n}: unexpected {line[:40]!r}")
        verb, rest = m.group(1), m.group(2).strip()
        if verb == "module":
            saw_module = True
        if rest.startswith("("):
            block = verb
            continue
        if verb == "require":
            _add(refs, rest, path, n)
    if block:
        raise ManifestError(f"go.mod: unterminated {block} ( block")
    if not saw_module and not refs:
        raise ManifestError("go.mod: no module directive")
    return refs


def _add(refs: list[DependencyRef], spec: str, path: str, line: int) -> None:
    m = _REQ.match(spec)
    if not m:
        return
    mod = m.group("mod").strip('"`')
    rest = m.group("rest")
    refs.append(
        DependencyRef(
            ecosystem=ECOSYSTEM,
            package=mod,
            version_spec=m.group("ver"),
            manifest_path=path,
            line=line,
            scope="indirect" if re.search(r"//\s*indirect\b", rest) else None,
        )
    )
