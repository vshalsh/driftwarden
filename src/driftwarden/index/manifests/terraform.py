"""Terraform / OpenTofu (``*.tf``, ``*.tofu``).

* ``terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } } }``
  -> ecosystem ``terraform-provider``, package = source (legacy ``aws = "~> 3.0"``
  implies ``hashicorp/aws``).
* ``terraform { required_version = ">= 1.5" }`` -> ecosystem ``terraform``, package ``terraform``.
* ``module "vpc" { source = "terraform-aws-modules/vpc/aws"  version = "5.1.0" }``
  -> ecosystem ``terraform-module`` (local ``./`` / ``../`` sources are skipped).
* ``provider "aws" { ... }`` blocks -> ecosystem ``terraform-provider``, package =
  the local name, scope ``provider-block``.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from driftwarden.index.manifests._hcl import Attr, Block, parse_hcl
from driftwarden.models import DependencyRef


def matches(path: str) -> bool:
    return PurePosixPath(path).name.endswith((".tf", ".tofu"))


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
