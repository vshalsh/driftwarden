"""Dockerfile / Containerfile base images.

Reports every ``FROM`` image (and ``COPY --from=<image>`` / ``RUN
--mount=from=<image>`` that names an image rather than a build stage) as an
ecosystem ``docker`` dependency: package = image name (registry and path
included), version_spec = tag and/or digest. ``ARG`` defaults declared before
the first ``FROM`` are substituted; references to earlier stages and
``scratch`` are skipped.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import split_image
from driftwarden.models import DependencyRef
from driftwarden.text import split_lines

ECOSYSTEM = "docker"
_VAR = re.compile(r"\$(?:\{(?P<b>\w+)(?::?[-+](?P<d>[^}]*))?\}|(?P<n>\w+))")


def matches(path: str) -> bool:
    name = PurePosixPath(path).name
    low = name.lower()
    return (
        low in ("dockerfile", "containerfile")
        or low.startswith(("dockerfile.", "containerfile."))
        or low.endswith((".dockerfile", ".containerfile"))
    )


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; returns (first line number, joined text)."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for n, line in enumerate(split_lines(text), 1):
        stripped = line.strip()
        if not buf:
            start = n
            if not stripped or stripped.startswith("#"):
                continue
        elif stripped.startswith("#"):
            continue  # comment lines inside a continuation are dropped
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _subst(value: str, args: dict[str, str]) -> str:
    def rep(m: re.Match[str]) -> str:
        name = m.group("b") or m.group("n")
        if name in args:
            return args[name]
        if m.group("d") is not None:
            return m.group("d")
        return m.group(0)

    return _VAR.sub(rep, value)


def parse(text: str, path: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    args: dict[str, str] = {}
    stages: set[str] = set()
    seen_from = False
    for line, inst in _logical_lines(text):
        parts = inst.split()
        verb = parts[0].upper()
        words = parts[1:]
        if verb == "ARG" and not seen_from:
            for w in words:
                k, eq, v = w.partition("=")
                if eq:
                    args[k] = v.strip("\"'")
        elif verb == "FROM":
            seen_from = True
            words = [w for w in words if not w.startswith("--")]
            if not words:
                continue
            _add(refs, _subst(words[0], args), path, line, "base", stages)
            if len(words) >= 3 and words[1].upper() == "AS":
                stages.add(words[2].lower())
        elif verb in ("COPY", "ADD", "RUN"):
            for w in words:
                m = re.match(r"^--(?:from|mount=.*\bfrom)=([^,\s]+)", w)
                if m:
                    _add(refs, _subst(m.group(1), args), path, line, "copy-from", stages)
    return refs


def _add(
    refs: list[DependencyRef], image: str, path: str, line: int, scope: str, stages: set[str]
) -> None:
    if image.lower() == "scratch" or image.lower() in stages or image.isdigit():
        return
    name, version = split_image(image)
    if not name or "$" in name:
        return  # unresolved build argument: not a concrete image
    refs.append(
        DependencyRef(
            ecosystem=ECOSYSTEM,
            package=name,
            version_spec=version,
            manifest_path=path,
            line=line,
            scope=scope,
        )
    )
