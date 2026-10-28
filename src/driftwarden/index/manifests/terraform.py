"""Terraform / OpenTofu (``*.tf``, ``*.tofu``, and the JSON syntax ``*.tf.json``,
``*.tofu.json``).

* ``terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } } }``
  -> ecosystem ``terraform-provider``, package = source (legacy ``aws = "~> 3.0"``
  implies ``hashicorp/aws``).
* ``terraform { required_version = ">= 1.5" }`` -> ecosystem ``terraform``, package ``terraform``.
* ``module "vpc" { source = "terraform-aws-modules/vpc/aws"  version = "5.1.0" }``
  -> ecosystem ``terraform-module`` (local ``./`` / ``../`` sources are skipped).
* ``provider "aws" { ... }`` blocks -> ecosystem ``terraform-provider``, package =
  the local name, scope ``provider-block``.

The JSON syntax carries the same blocks as JSON objects (a block may also be an
array of objects). JSON has no positions, so each record's line is the first
unused line where its key starts a line, below its section; minified JSON falls
back to the section's line (as for ``package.json``).
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._common import ManifestError
from driftwarden.index.manifests._hcl import Attr, Block, parse_hcl
from driftwarden.index.manifests.npm import _key_lines
from driftwarden.models import DependencyRef


def matches(path: str) -> bool:
    return PurePosixPath(path).name.endswith((".tf", ".tofu", ".tf.json", ".tofu.json"))


_REGISTRY_ADDR = re.compile(
    r"^(?:[A-Za-z0-9.-]+(?::\d+)?/)?[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_-]+)?$"
)
_GETTER = re.compile(r"^([A-Za-z0-9]+)::(.*)$", re.S)
_SCP = re.compile(r"^(?P<user>[\w.-]+@)(?P<host>[\w.-]+)(?P<rest>:.*)$", re.S)


def canonical_source(source: str) -> str:
    """Comparison key for a provider / module source address.

    Registry addresses (``[host/]namespace/name[/system]``) are case-insensitive
    and the public registry host is implied, so they are lower-cased. Every other
    source (git, http(s), s3, gcs, GitHub/Bitbucket shorthand) is case-sensitive
    except for the parts that are case-insensitive by definition: the forced
    getter (``git::``), the URL scheme and the host name. Paths and query values
    such as ``?ref=V1`` keep their case, so ``?ref=V1`` != ``?ref=v1``.
    """
    s = source.strip()
    for prefix in ("registry.terraform.io/", "registry.opentofu.org/"):
        if s.lower().startswith(prefix):
            s = s[len(prefix) :]
            break
    low = s.lower()
    if not low.startswith(("github.com/", "bitbucket.org/")) and _REGISTRY_ADDR.match(s):
        return low
    getter = ""
    m = _GETTER.match(s)
    if m:
        getter, s = m.group(1).lower() + "::", m.group(2)
    if "://" in s:
        scheme, rest = s.split("://", 1)
        end = len(rest)
        for ch in "/?#":
            i = rest.find(ch)
            if i != -1:
                end = min(end, i)
        authority, tail = rest[:end], rest[end:]
        user, at, host = authority.rpartition("@")
        s = f"{scheme.lower()}://{user}{at}{host.lower()}{tail}"
    elif scp := _SCP.match(s):
        s = f"{scp.group('user')}{scp.group('host').lower()}{scp.group('rest')}"
    else:
        head, slash, tail = s.partition("/")
        if "." in head:  # github.com/Org/Repo shorthand: the host comes first
            s = head.lower() + slash + tail
    return getter + s


def _str(attr: Attr | None) -> str | None:
    if attr is None or not isinstance(attr.value, str):
        return None
    return attr.value.strip() or None


def parse(text: str, path: str) -> list[DependencyRef]:
    if PurePosixPath(path).name.endswith(".json"):
        return _parse_json(text, path)
    root = parse_hcl(text)
    refs: list[DependencyRef] = []

    def add(eco: str, pkg: str, version: str | None, line: int, scope: str | None) -> None:
        refs.append(
            DependencyRef(
                ecosystem=eco,
                package=pkg,
                version_spec=version,
                manifest_path=path,
                line=line,
                scope=scope,
            )
        )

    for block in root.blocks:
        if block.type == "terraform":
            rv = block.attrs.get("required_version")
            if _str(rv) and rv is not None:
                add("terraform", "terraform", _str(rv), rv.line, "core")
            for rp in (b for b in block.blocks if b.type == "required_providers"):
                _required_providers(rp, add)
        elif block.type == "module" and block.labels:
            src = block.attrs.get("source")
            source = _str(src)
            if not source or src is None or source.startswith(("./", "../")):
                continue
            add(
                "terraform-module",
                source,
                _str(block.attrs.get("version")),
                src.line,
                f"module:{block.labels[0]}",
            )
        elif block.type == "provider" and block.labels:
            add(
                "terraform-provider",
                block.labels[0],
                _str(block.attrs.get("version")),
                block.line,
                "provider-block",
            )
    return refs


def _required_providers(rp: Block, add) -> None:
    for local, attr in rp.attrs.items():
        if isinstance(attr.value, str):  # legacy: aws = "~> 3.0"
            add(
                "terraform-provider",
                f"hashicorp/{local}",
                attr.value.strip() or None,
                attr.line,
                None,
            )
        elif isinstance(attr.value, dict):
            source = _str(attr.value.get("source")) or f"hashicorp/{local}"
            add("terraform-provider", source, _str(attr.value.get("version")), attr.line, None)


def _objects(value: object) -> list[dict]:
    """A JSON block body: one object, or an array of objects."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _jstr(value: object) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _parse_json(text: str, path: str) -> list[DependencyRef]:
    """``*.tf.json``: the same records as the native syntax (L-026, D-L025-9)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ManifestError("JSON: top level is not an object")
    index = _key_lines(text)
    used: set[int] = set()

    def take(key: str, lo: int) -> int:
        for n in index.get(key, ()):
            if n >= lo and n not in used:
                used.add(n)
                return n
        return lo

    refs: list[DependencyRef] = []

    def add(eco: str, pkg: str, version: str | None, line: int, scope: str | None) -> None:
        refs.append(
            DependencyRef(
                ecosystem=eco, package=pkg, version_spec=version, manifest_path=path,
                line=line, scope=scope,
            )
        )  # fmt: skip

    for tf in _objects(data.get("terraform")):
        lo = take("terraform", 1)
        rv = _jstr(tf.get("required_version"))
        if rv:
            add("terraform", "terraform", rv, take("required_version", lo), "core")
        for rp in _objects(tf.get("required_providers")):
            rp_line = take("required_providers", lo)
            for local, spec in rp.items():
                if not isinstance(local, str) or not local:
                    continue
                if isinstance(spec, str):
                    add("terraform-provider", f"hashicorp/{local}", _jstr(spec),
                        take(local, rp_line), None)  # fmt: skip
                elif isinstance(spec, dict):
                    source = _jstr(spec.get("source")) or f"hashicorp/{local}"
                    add("terraform-provider", source, _jstr(spec.get("version")),
                        take(local, rp_line), None)  # fmt: skip
    for mod in _objects(data.get("module")):
        lo = take("module", 1)
        for name, bodies in mod.items():
            for body in _objects(bodies):
                source = _jstr(body.get("source"))
                if not source or source.startswith(("./", "../")):
                    continue
                line = take(name, lo)
                add("terraform-module", source, _jstr(body.get("version")),
                    take("source", line), f"module:{name}")  # fmt: skip
    for prov in _objects(data.get("provider")):
        lo = take("provider", 1)
        for name, bodies in prov.items():
            for body in _objects(bodies):
                add("terraform-provider", name, _jstr(body.get("version")), take(name, lo),
                    "provider-block")  # fmt: skip
    return refs
