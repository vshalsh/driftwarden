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

from pathlib import PurePosixPath

from driftwarden.index.manifests._hcl import Attr, Block, parse_hcl
from driftwarden.models import DependencyRef


def matches(path: str) -> bool:
    return PurePosixPath(path).name.endswith((".tf", ".tofu"))


def canonical_source(source: str) -> str:
    s = source.strip().lower()
    for prefix in ("registry.terraform.io/", "registry.opentofu.org/"):
        if s.startswith(prefix):
            return s[len(prefix) :]
    return s


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
