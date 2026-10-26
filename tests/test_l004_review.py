"""L-004: regression tests for the Codex review findings on PR #10 (one block each)."""

from __future__ import annotations

import pytest

from conftest import git
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import canonical_package, parse_manifest, scan_manifests
from driftwarden.models import DependencyRef


def _rows(path: str, text: str):
    res = parse_manifest(path, text)
    assert res.errors == [], res.errors
    return [(r.package, r.version_spec, r.line, r.scope) for r in res.refs]


def _sha(repo):
    return git(repo, "rev-parse", "HEAD").strip()


# --------------------------------------------------------------------------- (1) compose merge keys

COMPOSE_MERGE = """\
x-base: &base
  image: python:3.12-slim
  restart: always
x-tagged: &tagged
  image: busybox:1.36
services:
  worker:
    <<: *base
    command: celery
  api:
    <<: *base
    image: python:3.13-slim
  multi:
    <<: [*tagged, *base]
"""


def test_compose_merge_key_inherits_image_with_anchor_position():
    assert _rows("docker-compose.yml", COMPOSE_MERGE) == [
        ("python", "3.12-slim", 2, "service:worker"),  # from the anchor, at its line
        ("python", "3.13-slim", 12, "service:api"),  # explicit key overrides the merge
        ("busybox", "1.36", 5, "service:multi"),  # first mapping in a merge list wins
    ]


def test_compose_merge_key_verifies(make_repo):
    repo = make_repo({"docker-compose.yml": COMPOSE_MERGE})
    dep = DependencyRef(
        manifest_path="docker-compose.yml",
        package="python",
        version_spec="3.12-slim",
        scope="service:worker",
        commit=_sha(repo),
    )
    assert verify_dependency(repo, dep).status == "VERIFIED"


def test_compose_recursive_merge_is_safe():
    text = "services:\n  a: &a\n    image: x:1\n    <<: *a\n"
    assert _rows("compose.yaml", text) == [("x", "1", 3, "service:a")]


# --------------------------------------------------------------------------- (2) VersionOverride


@pytest.mark.parametrize(
    "item,expected",
    [
        (
            '<PackageReference Include="Polly">'
            "<VersionOverride>2.0.0</VersionOverride></PackageReference>",
            "2.0.0",
        ),
        ('<PackageReference Include="Polly" VersionOverride="2.0.0" />', "2.0.0"),
        ('<PackageReference Include="Polly" Version="1.0.0" VersionOverride="2.0.0" />', "2.0.0"),
        (
            '<PackageReference Include="Polly" Version="1.0.0">'
            "<VersionOverride>2.0.0</VersionOverride></PackageReference>",
            "2.0.0",
        ),
        (
            '<PackageReference Include="Polly"><Version>1.0.0</Version>'
            "<VersionOverride>2.0.0</VersionOverride></PackageReference>",
            "2.0.0",
        ),
        ('<PackageReference Include="Polly" Version="1.0.0" />', "1.0.0"),
    ],
)
def test_csproj_version_override_precedence(item, expected):
    text = f"<Project>\n<ItemGroup>\n{item}\n</ItemGroup>\n</Project>\n"
    assert _rows("App.csproj", text) == [("Polly", expected, 3, None)]


# --------------------------------------------------------------------- (3) terraform source case


def test_terraform_module_source_case_is_significant_in_ref_and_path(make_repo):
    tf = 'module "m" {\n  source = "git::https://example.com/Org/Repo.git?ref=V1"\n}\n'
    repo = make_repo({"main.tf": tf})
    base = {"manifest_path": "main.tf", "commit": _sha(repo), "version_spec": None}
    ok = "git::https://example.com/Org/Repo.git?ref=V1"
    assert verify_dependency(repo, DependencyRef(package=ok, **base)).status == "VERIFIED"
    for wrong in (
        "git::https://example.com/Org/Repo.git?ref=v1",
        "git::https://example.com/org/repo.git?ref=V1",
    ):
        r = verify_dependency(repo, DependencyRef(package=wrong, **base))
        assert r.status == "MISMATCH", wrong
    # Scheme and host are case-insensitive.
    same = "GIT::HTTPS://EXAMPLE.COM/Org/Repo.git?ref=V1"
    assert verify_dependency(repo, DependencyRef(package=same, **base)).status == "VERIFIED"


@pytest.mark.parametrize(
    "a,b,equal",
    [
        ("hashicorp/AWS", "hashicorp/aws", True),  # registry addresses: case-insensitive
        ("registry.terraform.io/Hashicorp/aws", "hashicorp/aws", True),
        ("Terraform-AWS-Modules/vpc/aws", "terraform-aws-modules/vpc/aws", True),
        ("github.com/Org/Repo?ref=V1", "github.com/Org/Repo?ref=v1", False),
        ("GitHub.com/Org/Repo?ref=V1", "github.com/Org/Repo?ref=V1", True),
        ("git@github.com:Org/Repo.git?ref=V1", "git@GITHUB.COM:Org/Repo.git?ref=V1", True),
        ("git@github.com:Org/Repo.git", "git@github.com:org/repo.git", False),
        (
            "s3::https://s3.amazonaws.com/Bucket/Key.zip",
            "s3::https://s3.amazonaws.com/bucket/key.zip",
            False,
        ),
    ],
)
def test_terraform_canonical_source(a, b, equal):
    eco = "terraform-module"
    assert (canonical_package(eco, a) == canonical_package(eco, b)) is equal


# --------------------------------------------------------------------------- (4) pyproject comments


def test_pyproject_line_lookup_skips_toml_comments():
    text = (
        "[project]\n"
        'name = "x"\n'
        '# old: "requests>=2",\n'
        "dependencies = [\n"
        '  # "requests>=2",\n'
        '  "requests>=2",  # "requests>=2"\n'
        "]\n"
    )
    assert _rows("pyproject.toml", text) == [("requests", ">=2", 6, None)]


def test_pyproject_hash_inside_string_is_not_a_comment():
    text = '[project]\ndependencies = [\n  "pkg @ https://x.invalid/p.whl#sha256=ab",\n]\n'
    assert _rows("pyproject.toml", text) == [
        ("pkg", "@ https://x.invalid/p.whl#sha256=ab", 3, None)
    ]


def test_poetry_line_lookup_skips_comments():
    text = '[tool.poetry.dependencies]\n# celery = "^4"\ncelery = "^5.3"\n'
    assert _rows("pyproject.toml", text) == [("celery", "^5.3", 3, None)]


def test_version_catalog_line_lookup_skips_comments():
    text = '[libraries]\n# guava = "a:b:1"\nguava = "com.google.guava:guava:33.0"\n'
    assert _rows("gradle/libs.versions.toml", text) == [
        ("com.google.guava:guava", "33.0", 3, "catalog:guava")
    ]


# --------------------------------------------------------------------------- (5) scan sniffing


def test_scan_sniffs_bom_prefixed_k8s_yaml(make_repo):
    repo = make_repo()
    (repo / "deploy.yaml").write_bytes(
        b"\xef\xbb\xbfapiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: nginx:1.25\n"
    )
    (repo / "utf16.yaml").write_bytes(
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: redis:7\n".encode("utf-16")
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "c")
    got = {
        r.path: [(d.package, d.version_spec, d.line) for d in r.refs] for r in scan_manifests(repo)
    }
    assert got == {"deploy.yaml": [("nginx", "1.25", 5)], "utf16.yaml": [("redis", "7", 5)]}


# --------------------------------------------------------------------------- (6) Dockerfile options


@pytest.mark.parametrize(
    "line",
    [
        "RUN echo --from=redis:7",
        "RUN ./build.sh --mount=from=redis:7",
        "COPY ./x --from=redis:7 /y",
        "ADD . /src --from=redis:7",
        "RUN --network=none echo --from=redis:7",
    ],
)
def test_dockerfile_shell_args_are_not_options(line):
    assert _rows("Dockerfile", f"FROM alpine:3.19\n{line}\n") == [("alpine", "3.19", 1, "base")]


def test_dockerfile_leading_options_distinguish_copy_and_mount():
    text = (
        "FROM alpine:3.19 AS build\n"
        "COPY --chown=1000 --from=nginx:1.25 /a /b\n"
        "RUN --mount=type=cache,target=/c --mount=type=bind,from=golang:1.22,target=/g make\n"
        "RUN --mount=type=bind,from=build,target=/x true\n"
        "ADD --from=ignored:1 /a /b\n"
    )
    assert _rows("Dockerfile", text) == [
        ("alpine", "3.19", 1, "base"),
        ("nginx", "1.25", 2, "copy-from"),
        ("golang", "1.22", 3, "mount-from"),
    ]


# --------------------------------------------------------------------------- (7) poetry git pins


def test_poetry_git_dependency_keeps_pin():
    text = (
        "[tool.poetry.dependencies]\n"
        'a = { git = "https://github.com/x/a.git", rev = "abc123" }\n'
        'b = { git = "https://github.com/x/b.git", tag = "v1.2" }\n'
        'c = { git = "https://github.com/x/c.git", branch = "main", subdirectory = "pkg" }\n'
        'd = { git = "https://github.com/x/d.git" }\n'
    )
    assert _rows("pyproject.toml", text) == [
        ("a", "@ https://github.com/x/a.git#rev=abc123", 2, None),
        ("b", "@ https://github.com/x/b.git#tag=v1.2", 3, None),
        ("c", "@ https://github.com/x/c.git#branch=main&subdirectory=pkg", 4, None),
        ("d", "@ https://github.com/x/d.git", 5, None),
    ]


def test_poetry_git_pin_tamper_caught(make_repo):
    text = '[tool.poetry.dependencies]\na = { git = "https://github.com/x/a.git", tag = "v1" }\n'
    repo = make_repo({"pyproject.toml": text})
    base = {"manifest_path": "pyproject.toml", "package": "a", "commit": _sha(repo)}
    good = DependencyRef(version_spec="@ https://github.com/x/a.git#tag=v1", **base)
    assert verify_dependency(repo, good).status == "VERIFIED"
    for wrong in ("@ https://github.com/x/a.git#tag=v2", "@ https://github.com/x/a.git"):
        r = verify_dependency(repo, DependencyRef(version_spec=wrong, **base))
        assert r.status == "MISMATCH", wrong
