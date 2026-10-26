"""Dependency-manifest parsers, one module per ecosystem. Deterministic, no LLM.

Each parser turns manifest text into ``DependencyRef`` records (package,
version_spec, manifest_path, line, ...). These parsers are the ground truth for
grounding check G3: ``verify_dependency()`` re-runs them on the manifest as it
was at the cited commit.

Public entry points never raise on manifest *content*: a malformed manifest
gives a ``ManifestResult`` with ``errors`` set and whatever could be read.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from driftwarden import git
from driftwarden.index.manifests import (
    compose,
    dockerfile,
    dotnet,
    golang,
    gradle,
    kubernetes,
    maven,
    npm,
    python,
    terraform,
)
from driftwarden.index.manifests._common import ManifestError, canonical_image
from driftwarden.models import WORKTREE, DependencyRef
from driftwarden.text import read_text_file

__all__ = [
    "ManifestError",
    "ManifestResult",
    "Parser",
    "PARSERS",
    "canonical_package",
    "canonical_version",
    "detect",
    "parse_manifest",
    "parse_manifest_at",
    "scan_manifests",
]

MAX_MANIFEST_BYTES = 2_000_000


@dataclass(frozen=True)
class Parser:
    kind: str  # e.g. "requirements", "pyproject", "package.json"
    matches: Callable[[str], bool]
    parse: Callable[[str, str], list[DependencyRef]]
    sniff: Callable[[str, str], bool] | None = None  # content check for generic names


@dataclass
class ManifestResult:
    path: str
    kind: str | None
    refs: list[DependencyRef] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    commit: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


# Order matters: the first matching parser wins (compose before generic k8s YAML).
PARSERS: tuple[Parser, ...] = (
    Parser("requirements", python.matches_requirements, python.parse_requirements),
    Parser("pyproject", python.matches_pyproject, python.parse_pyproject),
    Parser("package.json", npm.matches, npm.parse),
    Parser("pom", maven.matches, maven.parse),
    Parser("gradle", gradle.matches, gradle.parse),
    Parser("gradle-catalog", gradle.matches_catalog, gradle.parse_catalog),
    Parser("go.mod", golang.matches, golang.parse),
    Parser("msbuild", dotnet.matches, dotnet.parse),
    Parser("dockerfile", dockerfile.matches, dockerfile.parse),
    Parser("compose", compose.matches, compose.parse),
    Parser("terraform", terraform.matches, terraform.parse),
    Parser(
        "kubernetes",
        lambda p: kubernetes.matches(p),
        kubernetes.parse,
        sniff=lambda p, t: kubernetes.matches(p, t),
    ),
)


def detect(path: str, text: str | None = None) -> Parser | None:
    """The parser for ``path`` (repo-relative POSIX), or None if it is not a manifest.

    Parsers with a ``sniff`` (generic ``*.yaml``) also need ``text`` to decide;
    without it they are reported as candidates.
    """
    for p in PARSERS:
        if p.matches(path):
            if p.sniff is not None and text is not None and not p.sniff(path, text):
                continue
            return p
    return None


def _prepare(text: str) -> str:
    """Strip a BOM; recover mis-decoded UTF-16; reject other text containing NULs."""
    if text.startswith("﻿"):
        text = text[1:]
    if "\x00" not in text:
        return text
    body = text[2:] if text.startswith("��") else text  # UTF-16 BOM as UTF-8
    if body.count("\x00") * 2 >= len(body) - 1:
        recovered = body.replace("\x00", "")
        if "�" not in recovered:
            return recovered.removeprefix("﻿")
    raise ManifestError("undecodable manifest (binary data or an unrecognised encoding)")


def parse_manifest(path: str, text: str) -> ManifestResult:
    """Parse one manifest. Never raises on bad content.

    A leading byte-order mark is removed here, once, for every parser (line
    numbers are unaffected: the BOM sits on line 1). Text that still contains
    NULs is recovered if it is ASCII UTF-16 that was mis-decoded as UTF-8, and
    is otherwise reported as an "undecodable manifest" error, never parsed into
    a silently empty result.
    """
    try:
        clean: str | None = _prepare(text)
        problem = None
    except ManifestError as exc:
        clean, problem = None, str(exc)
    parser = detect(path, clean if clean is not None else text)
    if parser is None:
        return ManifestResult(path=path, kind=None, errors=["not a recognised manifest"])
    res = ManifestResult(path=path, kind=parser.kind)
    if clean is None:
        res.errors.append(problem or "undecodable manifest")
        return res
    text = clean
    if len(text) > MAX_MANIFEST_BYTES:
        res.errors.append(f"manifest larger than {MAX_MANIFEST_BYTES} bytes; skipped")
        return res
    try:
        res.refs = parser.parse(text, path)
    except ManifestError as exc:
        res.errors.append(str(exc))
    except RecursionError:
        res.errors.append("manifest nested too deeply")
    except Exception as exc:  # noqa: BLE001 - a parser bug must not abort a scan
        res.errors.append(f"parser error: {type(exc).__name__}: {exc}")
    return res


def parse_manifest_at(repo: str | Path, path: str, commit: str) -> ManifestResult:
    """Parse ``path`` as it is at ``commit`` (``git show``), or in the working tree
    when ``commit`` is WORKTREE. Every returned ref carries ``commit``.

    Raises git.GitError if the file cannot be read at that commit.
    """
    if commit == WORKTREE:
        text = read_text_file(Path(git.repo_root(repo)) / path)
    else:
        text = git.show_file(repo, commit, path)
    res = parse_manifest(path, text)
    res.commit = commit
    res.refs = [r.model_copy(update={"commit": commit}) for r in res.refs]
    return res


def scan_manifests(repo: str | Path, commit: str = "HEAD") -> list[ManifestResult]:
    """Every manifest tracked at ``commit``, parsed. Commit is resolved to a full SHA."""
    root = git.repo_root(repo)
    sha = git.resolve_commit(root, commit)
    results: list[ManifestResult] = []
    for path in git.ls_tree(root, sha):
        if "node_modules/" in f"/{path}":
            continue  # vendored packages' own manifests are not this repo's dependencies
        parser = detect(path)
        if parser is None:
            continue
        try:
            text = git.show_file(root, sha, path)
        except git.GitError as exc:
            results.append(ManifestResult(path=path, kind=parser.kind, errors=[str(exc)]))
            continue
        if parser.sniff is not None and not parser.sniff(path, text):
            continue
        res = parse_manifest(path, text)
        res.commit = sha
        res.refs = [r.model_copy(update={"commit": sha}) for r in res.refs]
        results.append(res)
    return results


# --------------------------------------------------------------------------- comparison


def canonical_package(ecosystem: str | None, name: str) -> str:
    """Comparison key for a package name, following each ecosystem's own rules."""
    n = name.strip()
    if ecosystem == "pypi":
        return python.canonical_name(n)
    if ecosystem in ("nuget", "dotnet-sdk"):
        return n.lower()
    if ecosystem == "docker":
        return canonical_image(n)
    if ecosystem in ("terraform-provider", "terraform-module"):
        return terraform.canonical_source(n)
    return n


def canonical_version(ecosystem: str | None, spec: str | None) -> str | None:
    """Comparison key for a version spec; None and blank both mean "unversioned"."""
    if spec is None or not spec.strip():
        return None
    if ecosystem == "pypi":
        return python.canonical_spec(spec)
    if ecosystem in ("npm", "terraform", "terraform-provider", "terraform-module"):
        return re.sub(r"\s+", " ", spec.strip())
    return spec.strip()
