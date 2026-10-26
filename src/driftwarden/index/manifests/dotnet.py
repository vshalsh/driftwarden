""".NET: SDK-style project files (``*.csproj``, ``*.fsproj``, ``*.vbproj``),
central package management (``Directory.Packages.props``) and ``packages.config``.

Reports ``<PackageReference>`` / ``<PackageVersion>`` (``Include`` or ``Update``,
version from the attribute or a ``<Version>`` child), ``<package id version>``
from packages.config, and the project SDK (``Microsoft.NET.Sdk.Web`` ...) as
ecosystem ``dotnet-sdk``.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from driftwarden.index.manifests._common import ManifestError, XmlNode, parse_xml
from driftwarden.models import DependencyRef

ECOSYSTEM = "nuget"
PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
PROPS_NAMES = ("directory.packages.props", "directory.build.props", "packages.config")


def matches(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.endswith(PROJECT_SUFFIXES) or name in PROPS_NAMES


def parse(text: str, path: str) -> list[DependencyRef]:
    root = parse_xml(text)
    refs: list[DependencyRef] = []
    name = PurePosixPath(path).name.lower()
    if name == "packages.config":
        if root.tag != "packages":
            raise ManifestError(f"packages.config root is <{root.tag}>, expected <packages>")
        for node in root.iter("package"):
            pid = node.attr("id")
            if pid:
                scope = (
                    "dev" if (node.attr("developmentDependency") or "").lower() == "true" else None
                )
                refs.append(_ref(pid, node.attr("version"), path, node.line, scope))
        return refs
    if root.tag != "Project":
        raise ManifestError(f"MSBuild root is <{root.tag}>, expected <Project>")
    for sdk in (root.attr("Sdk") or "").split(";"):
        sdk = sdk.strip()
        if sdk:
            sdk_name, _, sdk_ver = sdk.partition("/")
            refs.append(
                DependencyRef(
                    ecosystem="dotnet-sdk",
                    package=sdk_name,
                    version_spec=sdk_ver or None,
                    manifest_path=path,
                    line=root.line,
                    scope="sdk",
                )
            )
    for node in root.iter():
        if node.tag not in ("PackageReference", "PackageVersion", "GlobalPackageReference"):
            continue
        pkg = node.attr("Include") or node.attr("Update")
        if not pkg:
            continue
        version = node.attr("Version") or node.attr("VersionOverride")
        if version is None:
            child = next((c for c in node.children if c.tag.lower() == "version"), None)
            version = child.text.strip() if child is not None else None
        scope = "central" if node.tag == "PackageVersion" else _scope(node)
        refs.append(_ref(pkg.strip(), version, path, node.line, scope))
    return refs


def _scope(node: XmlNode) -> str | None:
    assets = node.attr("PrivateAssets")
    if assets is None:
        child = next((c for c in node.children if c.tag == "PrivateAssets"), None)
        assets = child.text if child is not None else None
    return "dev" if assets and assets.strip().lower() == "all" else None


def _ref(pkg: str, version: str | None, path: str, line: int, scope: str | None) -> DependencyRef:
    return DependencyRef(
        ecosystem=ECOSYSTEM,
        package=pkg,
        version_spec=(version.strip() or None) if version else None,
        manifest_path=path,
        line=line,
        scope=scope,
    )
