"""L-004: manifest parsers produce the right package lists (fixtures, per ecosystem)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import git
from driftwarden.index.manifests import (
    canonical_package,
    canonical_version,
    detect,
    parse_manifest,
    parse_manifest_at,
    scan_manifests,
)
from driftwarden.index.manifests._common import split_image
from driftwarden.index.manifests.python import parse_requirement
from driftwarden.models import WORKTREE

POLY = Path(__file__).parent / "fixtures" / "manifest_repos" / "poly"


def _parse(rel: str):
    res = parse_manifest(rel, (POLY / rel).read_text(encoding="utf-8"))
    assert res.errors == [], res.errors
    return res


def _rows(rel: str):
    return [(r.package, r.version_spec, r.line, r.scope) for r in _parse(rel).refs]


@pytest.fixture
def poly_repo(tmp_path):
    """The polyglot fixture as a git repo: commit 1 = README only, commit 2 = manifests."""
    repo = tmp_path / "poly"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("# poly\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "root")
    for item in POLY.iterdir():
        dest = repo / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "manifests")
    return repo


# --------------------------------------------------------------------------- per ecosystem


def test_requirements_txt():
    assert _rows("requirements.txt") == [
        ("fastapi", ">=0.110,<1.0", 5, None),
        ("SQLAlchemy", "==2.0.29", 6, None),
        ("psycopg2-binary", "==2.9.9", 7, None),
        ("requests", None, 8, None),
        ("uvicorn", ">=0.29", 9, None),
        ("mylib", "@ https://example.invalid/mylib-1.0.tar.gz", 11, None),
        (
            "acme-tooling",
            "@ git+https://example.invalid/acme/tooling.git@v1.2#egg=acme-tooling",
            12,
            None,
        ),
    ]


def test_pyproject_toml():
    assert _rows("pyproject.toml") == [
        ("pydantic", ">=2", 9, None),
        ("redis", ">=5.0", 10, None),
        ("httpx", None, 11, None),
        ("mkdocs", "~=1.5", 15, "optional:docs"),
        ("pytest", ">=8", 17, "optional:test"),
        ("pytest-cov", None, 18, "optional:test"),
        ("ruff", "==0.4.1", 22, "group:lint"),
        ("hatchling", ">=1.20", 2, "build"),
        ("celery", "^5.3", 26, None),
        ("boto3", ">=1.34", 27, None),
        ("black", "24.3.0", 30, "dev"),
    ]


def test_package_json():
    assert _rows("services/web/package.json") == [
        ("react", "^18.2.0", 9, None),
        ("react-dom", "^18.2.0", 10, None),
        ("@tanstack/react-query", "5.28.0", 11, None),
        ("axios", "~1.6.8", 12, None),
        ("typescript", "^5.4.0", 15, "dev"),
        ("vite", "5.2.0", 16, "dev"),
        ("react", ">=18", 19, "peer"),
    ]


def test_pom_xml():
    # The commented-out mysql dependency and the <exclusion> are not dependencies.
    assert _rows("services/billing/pom.xml") == [
        ("org.springframework.boot:spring-boot-starter-parent", "3.2.4", 6, "parent"),
        ("org.springframework.boot:spring-boot-starter-web", None, 19, None),
        ("org.apache.kafka:kafka-clients", "3.7.0", 23, None),  # ${kafka.version} resolved
        ("org.postgresql:postgresql", "42.7.3", 28, "runtime"),
        ("org.junit.jupiter:junit-jupiter", "5.10.2", 41, "test"),
        ("org.springframework.boot:spring-boot-maven-plugin", None, 50, "plugin"),
    ]


def test_gradle_kts():
    rows = [
        (r.ecosystem, *row)
        for r, row in zip(
            _parse("services/ledger/build.gradle.kts").refs,
            _rows("services/ledger/build.gradle.kts"),
            strict=True,
        )
    ]
    assert rows == [
        ("gradle-plugin", "org.springframework.boot", "3.2.4", 3, "plugin"),
        ("gradle-plugin", "io.spring.dependency-management", "1.1.4", 4, "plugin"),
        ("maven", "software.amazon.awssdk:bom", "2.25.0", 10, None),
        ("maven", "org.springframework.boot:spring-boot-starter-data-jpa", None, 11, None),
        ("maven", "com.fasterxml.jackson.core:jackson-databind", "2.17.0", 12, None),
        ("maven", "org.postgresql:postgresql", "42.7.3", 15, None),
        ("maven", "org.junit.jupiter:junit-jupiter", "5.10.2", 18, "test"),
    ]  # commented-out mysql / lombok lines are skipped


def test_gradle_version_catalog():
    assert _rows("services/ledger/gradle/libs.versions.toml") == [
        ("com.google.guava:guava", "33.1.0-jre", 5, "catalog:guava"),
        ("org.slf4j:slf4j-api", "2.0.12", 6, "catalog:slf4j-api"),
        ("org.apache.commons:commons-lang3", "3.14.0", 7, "catalog:commons-lang3"),
        ("com.github.ben-manes.versions", "0.51.0", 10, "plugin"),
    ]


def test_go_mod():
    assert _rows("services/gateway/go.mod") == [
        ("github.com/gin-gonic/gin", "v1.9.1", 5, None),
        ("github.com/redis/go-redis/v9", "v9.5.1", 8, None),
        ("google.golang.org/grpc", "v1.63.2", 9, None),
        ("golang.org/x/net", "v0.24.0", 10, "indirect"),
    ]  # replace / exclude are not requirements


def test_csproj():
    assert _rows("services/api/Api.csproj") == [
        ("Microsoft.NET.Sdk.Web", None, 1, "sdk"),
        ("Npgsql.EntityFrameworkCore.PostgreSQL", "8.0.2", 8, None),
        ("Serilog.AspNetCore", "8.0.1", 9, None),
        ("StyleCop.Analyzers", "1.1.118", 12, "dev"),
        ("MediatR", None, 13, None),
    ]


def test_dockerfile():
    digest = "sha256:" + "1" * 64
    assert _rows("services/api/Dockerfile") == [
        ("mcr.microsoft.com/dotnet/sdk", "8.0", 5, "base"),  # ARG defaults substituted
        ("node", "20-alpine", 10, "base"),
        ("mcr.microsoft.com/dotnet/aspnet", f"8.0@{digest}", 13, "base"),
        ("nginx", "1.25", 15, "copy-from"),  # --from=build (a stage) is skipped
    ]


def test_docker_compose():
    assert _rows("docker-compose.yml") == [
        ("registry.example.com:5000/acme/api", "${API_TAG:-latest}", 4, "service:api"),
        ("postgres", "16.2", 7, "service:db"),
        ("redis", "7-alpine", 11, "service:cache"),
        ("rabbitmq", None, 13, "service:queue"),
    ]


def test_terraform():
    rows = [
        (r.ecosystem, r.package, r.version_spec, r.line)
        for r in _parse("infra/terraform/main.tf").refs
    ]
    assert rows == [
        ("terraform", "terraform", ">= 1.5.0", 2),
        ("terraform-provider", "hashicorp/aws", "~> 5.40", 5),
        ("terraform-provider", "hashicorp/random", None, 9),
        ("terraform-provider", "hashicorp/google", "~> 4.0", 12),
        ("terraform-provider", "aws", None, 17),
        ("terraform-module", "terraform-aws-modules/vpc/aws", "5.7.0", 22),
    ]  # local module source ./modules/thing skipped; heredoc and comments ignored


def test_kubernetes():
    assert _rows("deploy/k8s/app.yaml") == [
        ("ghcr.io/acme/migrate", "2024.04", 11, "Deployment/api"),
        ("ghcr.io/acme/api", "1.4.2", 14, "Deployment/api"),
        ("envoyproxy/envoy", "v1.29.1", 18, "Deployment/api"),
        ("busybox", None, 31, "CronJob/nightly"),
    ]  # ConfigMap data.image is not a container image


# --------------------------------------------------------------------------- dispatch


@pytest.mark.parametrize(
    "path,kind",
    [
        ("requirements.txt", "requirements"),
        ("requirements-dev.txt", "requirements"),
        ("requirements/prod.in", "requirements"),
        ("a/pyproject.toml", "pyproject"),
        ("package.json", "package.json"),
        ("pom.xml", "pom"),
        ("build.gradle", "gradle"),
        ("x/build.gradle.kts", "gradle"),
        ("gradle/libs.versions.toml", "gradle-catalog"),
        ("go.mod", "go.mod"),
        ("src/App.csproj", "msbuild"),
        ("Directory.Packages.props", "msbuild"),
        ("packages.config", "msbuild"),
        ("Dockerfile", "dockerfile"),
        ("docker/api.Dockerfile", "dockerfile"),
        ("Dockerfile.prod", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("docker-compose.yml", "compose"),
        ("compose.yaml", "compose"),
        ("docker-compose.override.yml", "compose"),
        ("infra/main.tf", "terraform"),
        ("k8s/deploy.yaml", "kubernetes"),
    ],
)
def test_detect(path, kind):
    p = detect(path)
    assert p is not None and p.kind == kind


@pytest.mark.parametrize("path", ["README.md", "setup.py", "go.sum", "package-lock.json", "x.txt"])
def test_detect_non_manifest(path):
    assert detect(path) is None


def test_generic_yaml_needs_apiversion_and_kind():
    assert detect("mkdocs.yml", (POLY / "mkdocs.yml").read_text()) is None
    assert detect("k.yaml", "apiVersion: v1\nkind: Pod\n").kind == "kubernetes"


def test_scan_manifests_finds_every_ecosystem(poly_repo):
    results = scan_manifests(poly_repo)
    head = git(poly_repo, "rev-parse", "HEAD").strip()
    kinds = {r.path: r.kind for r in results}
    assert kinds == {
        "deploy/k8s/app.yaml": "kubernetes",
        "docker-compose.yml": "compose",
        "infra/terraform/main.tf": "terraform",
        "pyproject.toml": "pyproject",
        "requirements.txt": "requirements",
        "services/api/Api.csproj": "msbuild",
        "services/api/Dockerfile": "dockerfile",
        "services/billing/pom.xml": "pom",
        "services/gateway/go.mod": "go.mod",
        "services/ledger/build.gradle.kts": "gradle",
        "services/ledger/gradle/libs.versions.toml": "gradle-catalog",
        "services/web/package.json": "package.json",
    }
    assert all(r.ok for r in results)
    refs = [ref for r in results for ref in r.refs]
    assert len(refs) == 69
    assert {ref.commit for ref in refs} == {head}
    ecos = {ref.ecosystem for ref in refs}
    assert ecos == {
        "pypi",
        "npm",
        "maven",
        "gradle-plugin",
        "go",
        "nuget",
        "dotnet-sdk",
        "docker",
        "terraform",
        "terraform-provider",
        "terraform-module",
    }


def test_scan_at_root_commit_has_no_manifests(poly_repo):
    root = git(poly_repo, "rev-list", "--max-parents=0", "HEAD").strip()
    assert scan_manifests(poly_repo, root) == []


def test_parse_manifest_at_worktree(poly_repo):
    res = parse_manifest_at(poly_repo, "services/gateway/go.mod", WORKTREE)
    assert res.commit == WORKTREE and len(res.refs) == 4
    assert {r.commit for r in res.refs} == {WORKTREE}


def test_scan_skips_node_modules(make_repo):
    repo = make_repo(
        {
            "package.json": '{"dependencies": {"left-pad": "1.0.0"}}\n',
            "node_modules/left-pad/package.json": '{"dependencies": {"evil": "1"}}\n',
        }
    )
    assert [r.path for r in scan_manifests(repo)] == ["package.json"]


# --------------------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    "req,expected",
    [
        ("requests", ("requests", None)),
        ("requests >= 2.31 , < 3", ("requests", ">=2.31,<3")),
        ("Foo.Bar_baz[x,y]==1.0; python_version<'3.12'", ("Foo.Bar_baz", "==1.0")),
        ("name (>=1.0)", ("name", ">=1.0")),
        ("pkg @ https://x.invalid/p.whl", ("pkg", "@ https://x.invalid/p.whl")),
        ("not a requirement", None),
        ("", None),
    ],
)
def test_parse_requirement(req, expected):
    assert parse_requirement(req) == expected


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("nginx", ("nginx", None)),
        ("nginx:1.25", ("nginx", "1.25")),
        ("localhost:5000/app", ("localhost:5000/app", None)),
        ("localhost:5000/app:2", ("localhost:5000/app", "2")),
        ("app@sha256:abc", ("app", "@sha256:abc")),
        ("app:${TAG:-1}", ("app", "${TAG:-1}")),
    ],
)
def test_split_image(ref, expected):
    assert split_image(ref) == expected


def test_canonical_names():
    assert canonical_package("pypi", "SQLAlchemy") == canonical_package("pypi", "sqlalchemy")
    assert canonical_package("pypi", "psycopg2_binary") == canonical_package(
        "pypi", "psycopg2-binary"
    )
    assert canonical_package("nuget", "MediatR") == "mediatr"
    assert canonical_package("docker", "docker.io/library/nginx") == canonical_package(
        "docker", "nginx"
    )
    assert canonical_package("npm", "React") != canonical_package("npm", "react")
    assert canonical_version("pypi", "<2, >=1") == canonical_version("pypi", ">=1,<2")
    assert canonical_version("npm", "^1.0") != canonical_version("npm", "^1.1")
    assert canonical_version("go", "") is None


def test_requirements_line_continuation_and_comments():
    text = (
        "# c\n\nflask \\\n  >=3.0  # web\n--find-links x\n-c constraints.txt\n"
        "gunicorn==22.0.0 --hash=sha256:aa\n"
    )
    res = parse_manifest("requirements.txt", text)
    assert [(r.package, r.version_spec, r.line) for r in res.refs] == [
        ("flask", ">=3.0", 3),
        ("gunicorn", "==22.0.0", 7),
    ]


def test_duplicate_entries_get_distinct_lines():
    text = '[project]\ndependencies = [\n  "a>=1",\n  "a>=1",\n]\n'
    res = parse_manifest("pyproject.toml", text)
    assert [r.line for r in res.refs] == [3, 4]


def test_pom_dependency_management_and_project_version():
    text = """<project><groupId>g</groupId><artifactId>a</artifactId><version>9.9</version>
<dependencyManagement><dependencies><dependency>
<groupId>g</groupId><artifactId>b</artifactId><version>${project.version}</version>
</dependency></dependencies></dependencyManagement></project>
"""
    res = parse_manifest("pom.xml", text)
    assert [(r.package, r.version_spec, r.line) for r in res.refs] == [("g:b", "9.9", 2)]


def test_packages_config_and_central_versions():
    pc = (
        '<?xml version="1.0"?>\n<packages>\n'
        '  <package id="Newtonsoft.Json" version="13.0.3" />\n</packages>\n'
    )
    assert [
        (r.package, r.version_spec, r.line) for r in parse_manifest("packages.config", pc).refs
    ] == [("Newtonsoft.Json", "13.0.3", 3)]
    props = (
        "<Project>\n<ItemGroup>\n"
        '<PackageVersion Include="Polly" Version="8.3.1" />\n</ItemGroup>\n</Project>\n'
    )
    refs = parse_manifest("Directory.Packages.props", props).refs
    assert [(r.package, r.version_spec, r.scope, r.line) for r in refs] == [
        ("Polly", "8.3.1", "central", 3)
    ]


def test_compose_v1_top_level_services():
    res = parse_manifest("docker-compose.yml", "web:\n  image: nginx:1.0\n")
    assert [(r.package, r.version_spec, r.line) for r in res.refs] == [("nginx", "1.0", 2)]


def test_dockerfile_unresolved_arg_and_scratch():
    text = "ARG BASE\nFROM $BASE\nFROM scratch\nFROM python:${PY:-3.12}-slim AS py\nFROM py\n"
    refs = parse_manifest("Dockerfile", text).refs
    assert [(r.package, r.version_spec, r.line) for r in refs] == [("python", "3.12-slim", 4)]
