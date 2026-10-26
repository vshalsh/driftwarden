"""Dockerfile / Containerfile base images.

Reports every ``FROM`` image (scope ``base``), plus ``COPY --from=<image>``
(scope ``copy-from``) and ``RUN --mount=...,from=<image>`` (scope
``mount-from``) when they name an image rather than a build stage. Only the
instruction's leading ``--`` options are read, never shell arguments. Each is an
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


# BuildKit heredoc marker: <<EOF, <<-EOF, <<"EOF", <<'EOF' (word delimiter only).
_HEREDOC = re.compile(r"""<<(?P<dash>-?)(?P<q>["']?)(?P<word>[A-Za-z_][A-Za-z0-9_]*)(?P=q)""")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; returns (first line number, joined text).

    Heredoc bodies (``COPY <<EOF /x`` ... ``EOF``, ``RUN <<-"END"`` ...) are
    payload of the enclosing instruction and are consumed, never parsed as
    instructions. An unterminated heredoc consumes the rest of the file.
    """
    lines = split_lines(text)
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    i = 0
    while i < len(lines):
        n, stripped = i + 1, lines[i].strip()
        i += 1
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
        inst = " ".join(buf)
        out.append((start, inst))
        buf = []
        # Skip the bodies of every heredoc opened by this instruction, in order.
        for m in _HEREDOC.finditer(inst):
            word, dash = m.group("word"), bool(m.group("dash"))
            while i < len(lines):
                body = lines[i].lstrip("\t") if dash else lines[i]
                i += 1
                if body.rstrip("\r") == word:
                    break
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
        if not parts:
            continue  # a lone continuation backslash
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
        elif verb in ("COPY", "RUN"):
            # Only the instruction's own leading --options; anything after the first
            # non-option word is a path or shell text (``RUN echo --from=x``).
            for w in words:
                if not w.startswith("--"):
                    break
                key, _, value = w[2:].partition("=")
                if verb == "COPY" and key == "from" and value:
                    _add(refs, _subst(value, args), path, line, "copy-from", stages)
                elif verb == "RUN" and key == "mount":
                    src = _mount_from(value)
                    if src:
                        _add(refs, _subst(src, args), path, line, "mount-from", stages)
    return refs


def _mount_from(spec: str) -> str | None:
    """``from=`` of a ``RUN --mount=type=...,from=...,target=...`` spec."""
    for part in spec.split(","):
        k, _, v = part.partition("=")
        if k.strip().lower() == "from" and v.strip():
            return v.strip()
    return None


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
