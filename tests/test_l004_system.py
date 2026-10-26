"""L-004 system tests (adversarial): manifest parsers + verify_dependency() (G3).

Own fixtures, real-world style. Expectations are written from the ecosystems'
semantics, not from the implementation.
"""

from __future__ import annotations

import json
import random
import subprocess

import pytest

from conftest import git
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import (
    canonical_package,
    parse_manifest,
    scan_manifests,
)
from driftwarden.models import WORKTREE, DependencyRef

# --------------------------------------------------------------------------- helpers


def rows(path: str, text: str):
    res = parse_manifest(path, text)
    assert res.errors == [], res.errors
    return {(r.package, r.version_spec, r.scope) for r in res.refs}


def sha(repo, rev="HEAD"):
    return git(repo, "rev-parse", rev).strip()


def commit_all(repo, msg="c"):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return sha(repo)


def dep(path, pkg, ver, commit, **kw):
    return DependencyRef(manifest_path=path, package=pkg, version_spec=ver, commit=commit, **kw)


# --------------------------------------------------------------------------- python

REQS = """\
# base
-r common.txt
-c constraints.txt
--index-url https://pypi.example/simple
--extra-index-url https://x.example/simple
requests[security,socks]>=2.31,<3 ; python_version >= "3.8" and sys_platform != "win32"
Flask_SQLAlchemy==3.1.1 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
urllib3 @ https://files.example/urllib3-2.0.tar.gz#sha256=abc
-e git+https://github.com/acme/widget.git@v1.2#egg=widget&subdirectory=pkg
-e ./local/pkg
./vendored/thing
https://github.com/acme/tool/archive/main.zip#egg=tool
numpy>=1.26 # trailing comment
Pillow === 10.0.0
django~=4.2.0
"""


def test_requirements_realworld():
    got = rows("requirements.txt", REQS)
    pk_ = {p for p, _, _ in got}
    assert pk_ == {
        "requests",
        "Flask_SQLAlchemy",
        "urllib3",
        "widget",
        "tool",
        "numpy",
        "Pillow",
        "django",
    }
    d = {p: v for p, v, _ in got}
    assert d["requests"] == ">=2.31,<3"
    assert d["Flask_SQLAlchemy"] == "==3.1.1"
    assert d["Pillow"] == "===10.0.0"
    assert d["django"] == "~=4.2.0"
    assert d["numpy"] == ">=1.26"


def test_requirements_line_numbers_with_continuation():
    res = parse_manifest("requirements.txt", REQS)
    line = {r.package: r.line for r in res.refs}
    assert line["requests"] == 6
    assert line["Flask_SQLAlchemy"] == 7
    assert line["urllib3"] == 10
    assert line["numpy"] == 15


def test_requirements_crlf_and_bom():
    text = "﻿requests==2.0\r\nflask==3.0\r\n"
    res = parse_manifest("requirements.txt", text)
    assert {r.package for r in res.refs} == {"requests", "flask"}, "BOM must not eat 1st dep"
    assert [r.line for r in res.refs] == [1, 2]


def test_pyproject_bom():
    text = '﻿[project]\nname="x"\ndependencies=["requests>=2"]\n'
    res = parse_manifest("pyproject.toml", text)
    assert res.errors == [] and {r.package for r in res.refs} == {"requests"}


def test_requirements_utf16_powershell_freeze():
    """`pip freeze > requirements.txt` in Windows PowerShell yields UTF-16 LE+BOM."""
    raw = "requests==2.31.0\r\nflask==3.0.0\r\n".encode("utf-16")
    text = raw.decode("utf-8", errors="replace")
    res = parse_manifest("requirements.txt", text)
    assert {r.package for r in res.refs} == {"requests", "flask"}


PYPROJECT = """\
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
dependencies = [
  "requests>=2.31",
  'click>=8 ; python_version >= "3.9"',
  "rich[jupyter] ~= 13.0",
  "pkg @ git+https://github.com/a/b.git@v1",
]

[project.optional-dependencies]
docs = ["sphinx>=7"]
test = ["pytest>=8", "requests>=2.31"]

[dependency-groups]
dev = ["ruff", {include-group = "test"}]

[tool.poetry.dependencies]
python = "^3.11"
httpx = {version = "^0.27", extras = ["http2"]}
mylib = {git = "https://github.com/a/mylib.git"}

[tool.poetry.group.lint.dependencies]
black = "^24"
"""


def test_pyproject_realworld():
    got = rows("pyproject.toml", PYPROJECT)
    pkgs = {p for p, _, _ in got}
    assert pkgs == {
        "setuptools",
        "wheel",
        "requests",
        "click",
        "rich",
        "pkg",
        "sphinx",
        "pytest",
        "ruff",
        "httpx",
        "mylib",
        "black",
    }
    assert ("requests", ">=2.31", "optional:test") in got
    assert ("requests", ">=2.31", None) in got
    assert ("ruff", None, "group:dev") in got
    assert ("httpx", "^0.27", None) in got
    assert ("black", "^24", "lint") in got
    assert ("python", "^3.11", None) not in got


# --------------------------------------------------------------------------- npm

PKGJSON = """\
{
  "name": "mono", "private": true,
  "workspaces": ["packages/*", "apps/*"],
  "dependencies": {
    "@scope/pkg": "^1.2.3",
    "left-pad": "git+https://github.com/a/left-pad.git#v1",
    "local": "file:../local",
    "alias": "npm:real-pkg@^2",
    "star": "*",
    "empty": ""
  },
  "devDependencies": {"typescript": "~5.4.0", "left-pad": "1.0.0"},
  "peerDependencies": {"react": ">=18 <20"},
  "optionalDependencies": {"fsevents": "^2"},
  "overrides": {"semver": "7.5.4"},
  "scripts": {"dependencies": "echo"}
}
"""


def test_package_json_workspaces_and_variants():
    got = rows("package.json", PKGJSON)
    assert {p for p, _, _ in got} == {
        "@scope/pkg",
        "left-pad",
        "local",
        "alias",
        "star",
        "empty",
        "typescript",
        "react",
        "fsevents",
    }
    assert ("left-pad", "1.0.0", "dev") in got
    assert ("alias", "npm:real-pkg@^2", None) in got
    assert ("empty", None, None) in got
    # overrides are not direct deps
    assert "semver" not in {p for p, _, _ in got}


def test_package_json_bom_crlf_unicode():
    text = '﻿{\r\n "dependencies": {\r\n  "café": "1.0.0"\r\n }\r\n}\r\n'
    res = parse_manifest("package.json", text)
    assert [(r.package, r.line) for r in res.refs] == [("café", 3)]


def test_package_json_duplicate_line_numbers_distinct():
    res = parse_manifest("package.json", PKGJSON)
    lp = sorted(r.line for r in res.refs if r.package == "left-pad")
    assert len(lp) == 2 and lp[0] != lp[1]


# --------------------------------------------------------------------------- maven

POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.4</version>
  </parent>
  <groupId>com.acme</groupId>
  <artifactId>app</artifactId>
  <properties>
    <jackson.version>2.17.0</jackson.version>
    <guava.v>${jackson.version}</guava.v>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-dependencies</artifactId>
        <version>2023.0.1</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
      <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>core</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
  <build><plugins>
    <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.12.1</version></plugin>
  </plugins></build>
  <profiles>
    <profile><id>it</id>
      <dependencies>
        <dependency><groupId>org.testcontainers</groupId><artifactId>postgresql</artifactId>
          <version>1.19.7</version><scope>test</scope></dependency>
      </dependencies>
    </profile>
  </profiles>
  <!-- <dependency><groupId>commented</groupId><artifactId>out</artifactId></dependency> -->
</project>
"""


def test_pom_parent_bom_profiles():
    got = rows("pom.xml", POM)
    names = {p for p, _, _ in got}
    assert names == {
        "org.springframework.boot:spring-boot-starter-parent",
        "org.springframework.cloud:spring-cloud-dependencies",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.junit.jupiter:junit-jupiter",
        "com.acme:core",
        "org.apache.maven.plugins:maven-compiler-plugin",
        "org.testcontainers:postgresql",
    }
    assert ("com.fasterxml.jackson.core:jackson-databind", "2.17.0", None) in got
    assert ("com.acme:core", "3.2.4", None) in got  # project.version inherited from parent
    assert ("org.springframework.cloud:spring-cloud-dependencies", "2023.0.1", "import") in got
    assert ("org.junit.jupiter:junit-jupiter", None, "test") in got


def test_pom_malformed():
    res = parse_manifest("pom.xml", "<project><dependencies><dependency>")
    assert res.errors and res.refs == []


# --------------------------------------------------------------------------- gradle

GRADLE = """\
plugins {
    id 'java'
    id("org.springframework.boot") version "3.2.0"
    id "io.spring.dependency-management" version '1.1.4' apply false
}
ext {
    junitVersion = '5.10.2'
}
def guavaVersion = "33.0.0-jre"
dependencies {
    implementation 'com.google.guava:guava:33.0.0-jre'
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.22")
    api platform("org.springframework.boot:spring-boot-dependencies:3.2.0")
    implementation group: 'org.apache.commons', name: 'commons-lang3', version: '3.14.0'
    testImplementation "org.junit.jupiter:junit-jupiter:$junitVersion"
    runtimeOnly 'org.postgresql:postgresql'
    implementation "com.google.guava:guava:${guavaVersion}"
    compileOnly libs.lombok
    implementation project(':core')
    // implementation 'commented:out:1.0'
    /* implementation 'block:commented:1.0' */
    kapt("com.google.dagger:dagger-compiler:2.50")
    implementation('io.netty:netty-all:4.1.100.Final@jar')
}
"""


def test_gradle_variants():
    got = rows("build.gradle", GRADLE)
    names = {p for p, _, _ in got}
    assert "commented:out" not in names and "block:commented" not in names
    assert ("com.google.guava:guava", "33.0.0-jre", None) in got
    assert ("org.apache.commons:commons-lang3", "3.14.0", None) in got
    assert ("org.junit.jupiter:junit-jupiter", "5.10.2", "test") in got
    assert ("org.postgresql:postgresql", None, None) in got
    assert ("org.springframework.boot:spring-boot-dependencies", "3.2.0", None) in got
    assert ("org.springframework.boot", "3.2.0", "plugin") in got
    assert ("io.spring.dependency-management", "1.1.4", "plugin") in got
    assert ("com.google.dagger:dagger-compiler", "2.50", "kapt") in got
    assert "io.netty:netty-all" in names
    assert not any("lombok" in p or p.startswith(":") for p in names)


def test_gradle_kts_named_args_and_catalog():
    kts = 'dependencies {\n  implementation(group = "a.b", name = "c", version = "1.0")\n}\n'
    assert ("a.b:c", "1.0", None) in rows("build.gradle.kts", kts)
    cat = """[versions]
ktor = "2.3.9"
[libraries]
ktor-core = { module = "io.ktor:ktor-server-core", version.ref = "ktor" }
okhttp = "com.squareup.okhttp3:okhttp:4.12.0"
grp = { group = "g", name = "n", version = { strictly = "1.2" } }
[plugins]
kotlin = { id = "org.jetbrains.kotlin.jvm", version = "1.9.22" }
"""
    got = rows("gradle/libs.versions.toml", cat)
    assert ("io.ktor:ktor-server-core", "2.3.9", "catalog:ktor-core") in got
    assert ("com.squareup.okhttp3:okhttp", "4.12.0", "catalog:okhttp") in got
    assert ("g:n", "1.2", "catalog:grp") in got
    assert ("org.jetbrains.kotlin.jvm", "1.9.22", "plugin") in got


# --------------------------------------------------------------------------- go

GOMOD = """\
module github.com/acme/svc

go 1.22
toolchain go1.22.1

require github.com/gin-gonic/gin v1.9.1
require (
	github.com/stretchr/testify v1.9.0
	golang.org/x/sys v0.18.0 // indirect
	example.com/old v1.0.0 // indirect; do not use
	gopkg.in/yaml.v3 v3.0.1
	github.com/pre/release v1.2.3-rc.1+incompatible
)

replace github.com/gin-gonic/gin => github.com/fork/gin v1.9.2
replace (
	github.com/stretchr/testify v1.9.0 => ../testify
)
exclude github.com/bad/pkg v0.0.1
exclude (
	github.com/worse/pkg v0.0.2
)
retract v1.0.1
"""


def test_gomod_replace_exclude_indirect():
    got = rows("go.mod", GOMOD)
    assert got == {
        ("github.com/gin-gonic/gin", "v1.9.1", None),
        ("github.com/stretchr/testify", "v1.9.0", None),
        ("golang.org/x/sys", "v0.18.0", "indirect"),
        ("example.com/old", "v1.0.0", "indirect"),
        ("gopkg.in/yaml.v3", "v3.0.1", None),
        ("github.com/pre/release", "v1.2.3-rc.1+incompatible", None),
    }


def test_gomod_crlf():
    res = parse_manifest("go.mod", GOMOD.replace("\n", "\r\n"))
    assert res.errors == [] and len(res.refs) == 6


# --------------------------------------------------------------------------- dotnet

CSPROJ = """﻿<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Serilog.AspNetCore" Version="8.0.1" />
    <PackageReference Include="Newtonsoft.Json">
      <Version>13.0.3</Version>
    </PackageReference>
    <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
    <PackageReference Update="Microsoft.SourceLink.GitHub" Version="8.0.0" />
    <PackageReference Include="NoVersion.Central" />
    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Cond" Version="$(CondVersion)" Condition="'$(X)'=='1'" />
    <ProjectReference Include="..\\core\\core.csproj" />
    <Reference Include="System.Web" />
  </ItemGroup>
</Project>
"""


def test_csproj_variants():
    got = rows("src/App.csproj", CSPROJ)
    assert ("Microsoft.NET.Sdk.Web", None, "sdk") in got
    assert ("Serilog.AspNetCore", "8.0.1", None) in got
    assert ("Newtonsoft.Json", "13.0.3", None) in got
    assert ("StyleCop.Analyzers", "1.1.118", "dev") in got
    assert ("NoVersion.Central", None, None) in got
    assert ("Floating", "1.*", None) in got
    assert ("Cond", "$(CondVersion)", None) in got
    names = {p for p, _, _ in got}
    assert not names & {"core", "System.Web", "..\\core\\core.csproj"}


def test_packages_config_and_central():
    pc = (
        '<?xml version="1.0"?><packages><package id="Foo" version="1.0" '
        'developmentDependency="true"/></packages>'
    )
    assert ("Foo", "1.0", "dev") in rows("packages.config", pc)
    cp = '<Project><ItemGroup><PackageVersion Include="A" Version="2.0"/></ItemGroup></Project>'
    assert ("A", "2.0", "central") in rows("Directory.Packages.props", cp)


# --------------------------------------------------------------------------- docker

DOCKERFILE = """\
# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
ARG BASE=gcr.io/distroless/static-debian12:nonroot
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
RUN --mount=type=cache,target=/root/.cache go build -o /out/app .
FROM node:20@sha256:0123456789abcdef AS web
FROM ${BASE}
COPY --from=build /out/app /app
COPY --from=web /dist /dist
COPY --from=nginx:1.25 /etc/nginx/nginx.conf /nginx.conf
COPY --from=0 /x /x
FROM scratch
FROM $UNDEFINED_BASE
FROM registry.local:5000/team/app:v1
"""


def test_dockerfile_multistage_arg():
    got = rows("Dockerfile", DOCKERFILE)
    assert got == {
        ("golang", "1.22-alpine", "base"),
        ("node", "20@sha256:0123456789abcdef", "base"),
        ("gcr.io/distroless/static-debian12", "nonroot", "base"),
        ("nginx", "1.25", "copy-from"),
        ("registry.local:5000/team/app", "v1", "base"),
    }


def test_dockerfile_crlf_and_name_variants():
    text = "FROM alpine:3.19\r\nRUN echo hi\r\n"
    assert rows("svc/Dockerfile.prod", text) == {("alpine", "3.19", "base")}
    assert rows("svc/app.dockerfile", text) == {("alpine", "3.19", "base")}


COMPOSE = """\
name: stack
services:
  db:
    image: postgres:16.2@sha256:aa11
  cache:
    image: "docker.io/library/redis:7"
  app:
    build: .
    image: ${REGISTRY:-ghcr.io/acme}/app:${TAG:-1.2}
  anchor: &a
    image: nginx
  other:
    <<: *a
volumes: {}
"""


def test_compose_digest_and_interpolation():
    got = rows("docker-compose.yml", COMPOSE)
    assert ("postgres", "16.2@sha256:aa11", "service:db") in got
    assert ("docker.io/library/redis", "7", "service:cache") in got
    assert ("${REGISTRY:-ghcr.io/acme}/app", "${TAG:-1.2}", "service:app") in got
    assert ("nginx", None, "service:anchor") in got
    assert canonical_package("docker", "docker.io/library/redis") == canonical_package(
        "docker", "redis"
    )


K8S = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox:1.36
      containers:
        - name: app
          image: ghcr.io/acme/api:1.4.2
        - name: side
          image: envoyproxy/envoy@sha256:ff00
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg}
data:
  image: not-an-image:1
---
# empty doc follows
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: j
              image: python:3.12-slim
"""


def test_k8s_multidoc():
    got = rows("deploy/all.yaml", K8S)
    assert got == {
        ("busybox", "1.36", "Deployment/web"),
        ("ghcr.io/acme/api", "1.4.2", "Deployment/web"),
        ("envoyproxy/envoy", "@sha256:ff00", "Deployment/web"),
        ("python", "3.12-slim", "CronJob/nightly"),
    }


# --------------------------------------------------------------------------- terraform

TF = """\
terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    random = "~> 3.0"
    datadog = {
      source = "DataDog/datadog"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}
module "local" {
  source = "./modules/x"
}
module "git" {
  source = "git::https://example.com/mod.git?ref=v1"
}
# module "ghost" { source = "a/b/c" }
"""


def test_terraform():
    got = rows("main.tf", TF)
    assert ("terraform", ">= 1.5, < 2.0", "core") in got
    assert ("hashicorp/aws", "~> 5.40", None) in got
    assert ("hashicorp/random", "~> 3.0", None) in got
    assert ("DataDog/datadog", None, None) in got
    assert ("terraform-aws-modules/vpc/aws", "5.1.0", "module:vpc") in got
    assert not any(p == "./modules/x" or p == "a/b/c" for p, _, _ in got)
    assert any(p.startswith("git::") for p, _, _ in got)


def test_terraform_malformed_no_raise():
    res = parse_manifest("main.tf", "terraform {\n required_providers {\n aws = {")
    assert res.errors


# --------------------------------------------------------------------------- robustness

ALL_NAMES = [
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "pom.xml",
    "build.gradle",
    "libs.versions.toml",
    "go.mod",
    "a.csproj",
    "Dockerfile",
    "docker-compose.yml",
    "main.tf",
    "k8s.yaml",
]


@pytest.mark.parametrize("name", ALL_NAMES)
@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n\n",
        "﻿",
        "\x00\x01\x02\xff\xfe" * 100,
        "{" * 5000,
        "[" * 5000,
        "<a>" * 3000,
        "(" * 3000,
        "‮\u0000\U0001f600" * 50,
        "a" * 500_000,
    ],
)
def test_garbage_never_raises(name, text):
    res = parse_manifest(name, text)  # must not raise
    assert isinstance(res.refs, list)


@pytest.mark.parametrize("name", ALL_NAMES)
def test_oversize_skipped(name):
    res = parse_manifest(name, "x" * 2_000_001)
    assert res.errors and res.refs == []


def test_huge_requirements_fast():
    import time

    text = "".join(f"pkg{i}==1.{i}\n" for i in range(50_000))
    t = time.time()
    res = parse_manifest("requirements.txt", text)
    assert len(res.refs) == 50_000
    assert time.time() - t < 20


def test_huge_package_json_line_lookup_not_quadratic():
    import time

    deps = {f"p{i}": "1.0.0" for i in range(20_000)}
    text = json.dumps({"dependencies": deps}, indent=2)
    t = time.time()
    res = parse_manifest("package.json", text)
    assert len(res.refs) == 20_000
    assert time.time() - t < 20


_BOMB = """
from driftwarden.index.manifests import parse_manifest
n = 9
ents = "".join(
    '<!ENTITY %s "%s">' % (chr(98 + i), ("&" + chr(97 + i) + ";") * 4) for i in range(n)
)
xml = (
    '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">' + ents
    + "]><project><artifactId>&" + chr(97 + n) + ";</artifactId></project>"
)
print(len(xml))
parse_manifest("pom.xml", xml)
"""


def test_billion_laughs_xml():
    """A ~1 KB pom.xml with nested entities must not stall a scan (subprocess with a
    hard limit so a regression cannot hang the suite)."""
    import sys

    try:
        subprocess.run([sys.executable, "-c", _BOMB], timeout=15, check=True)
    except subprocess.TimeoutExpired:
        pytest.fail("pom.xml entity-expansion bomb (~1KB) took >15s: DoS on untrusted repos")


def test_yaml_alias_bomb():
    lines = ["a: &a [x,x,x,x,x,x,x,x,x]"]
    prev = "a"
    for i in range(30):
        cur = chr(98 + i % 20) + str(i)
        lines.append(f"{cur}: &{cur} [*{prev},*{prev},*{prev}]")
        prev = cur
    text = "apiVersion: v1\nkind: Pod\n" + "\n".join(lines) + "\n"
    parse_manifest("pod.yaml", text)


# --------------------------------------------------------------------------- git history


@pytest.fixture
def hist(make_repo):
    repo = make_repo({"requirements.txt": "requests==2.0\n"})
    c1 = sha(repo)
    (repo / "requirements.txt").write_text("requests==2.1\nflask==3.0\n")
    c2 = commit_all(repo, "bump")
    git(repo, "mv", "requirements.txt", "requirements-prod.txt")
    c3 = commit_all(repo, "rename")
    git(repo, "rm", "-q", "requirements-prod.txt")
    c4 = commit_all(repo, "delete")
    (repo / "requirements-prod.txt").write_text("requests==2.1\nflask==3.0\n")
    c5 = commit_all(repo, "re-add")
    return repo, [c1, c2, c3, c4, c5]


def test_history_every_commit(hist):
    repo, (c1, c2, c3, c4, c5) = hist

    def V(p, n, v, c):
        return verify_dependency(repo, dep(p, n, v, c)).status

    assert V("requirements.txt", "requests", "==2.0", c1) == "VERIFIED"
    assert V("requirements.txt", "requests", "==2.1", c1) == "MISMATCH"
    assert V("requirements.txt", "requests", "==2.1", c2) == "VERIFIED"
    assert V("requirements.txt", "flask", "==3.0", c2) == "VERIFIED"
    assert V("requirements.txt", "flask", "==3.0", c1) == "MISMATCH"
    # renamed: old path gone, new path present
    assert V("requirements.txt", "requests", "==2.1", c3) == "MISMATCH"
    assert V("requirements-prod.txt", "requests", "==2.1", c3) == "VERIFIED"
    # deleted
    r = verify_dependency(repo, dep("requirements-prod.txt", "requests", "==2.1", c4))
    assert r.status == "MISMATCH" and "missing" in r.reason
    assert V("requirements-prod.txt", "requests", "==2.1", c5) == "VERIFIED"
    assert [len(x.refs) for x in scan_manifests(repo, c2)] == [2]
    assert scan_manifests(repo, c4) == []


def test_non_existent_commit(hist):
    repo, _ = hist
    for bad in ["0" * 40, "deadbeef" * 5, "f" * 40, "nope", "", "  ", "-1", "--all", "HEAD~99"]:
        r = verify_dependency(repo, dep("requirements-prod.txt", "requests", "==2.1", bad))
        assert r.status == "MISMATCH", bad


def test_no_commit_on_claim(hist):
    repo, _ = hist
    r = verify_dependency(repo, DependencyRef(manifest_path="requirements-prod.txt", package="x"))
    assert r.status == "MISMATCH"


def test_commit_must_be_pinned_not_symbolic(hist):
    """DependencyRef.commit is documented as a full SHA or WORKTREE. A moving ref
    (HEAD / branch / tag / short sha) makes the claim non-reproducible."""
    repo, (c1, c2, c3, c4, c5) = hist
    git(repo, "tag", "v1", c1)
    git(repo, "branch", "side", c2)
    cases = [
        ("HEAD", "requirements-prod.txt", "==2.1"),
        ("main", "requirements-prod.txt", "==2.1"),
        ("side", "requirements.txt", "==2.1"),
        ("v1", "requirements.txt", "==2.0"),
        (c1[:7], "requirements.txt", "==2.0"),
        ("HEAD~4", "requirements.txt", "==2.0"),
    ]
    accepted = [
        sym
        for sym, path, ver in cases
        if verify_dependency(repo, dep(path, "requests", ver, sym)).status == "VERIFIED"
    ]
    assert not accepted, f"non-SHA commit values accepted: {accepted}"


def test_commit_object_that_is_not_a_commit(hist):
    repo, (c1, *_r) = hist
    tree = git(repo, "rev-parse", f"{c1}^{{tree}}").strip()
    blob = git(repo, "rev-parse", f"{c1}:requirements.txt").strip()
    for oid in (tree, blob):
        r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.0", oid))
        assert r.status == "MISMATCH", f"non-commit object {oid[:8]} accepted"


def test_path_attacks(hist):
    repo, (c1, *_r) = hist
    for p in [
        "../requirements.txt",
        "/etc/passwd",
        "",
        ".",
        "a/../requirements.txt",
        "-e",
        "--help",
    ]:
        r = verify_dependency(repo, dep(p, "requests", "==2.0", c1))
        assert r.status == "MISMATCH", p


def test_non_manifest_file_rejected(make_repo):
    repo = make_repo({"notes.txt": "requests==2.0\n", "README.md": "requests==2.0\n"})
    for p in ("notes.txt", "README.md"):
        r = verify_dependency(repo, dep(p, "requests", "==2.0", sha(repo)))
        assert r.status == "MISMATCH"


def test_no_commit_repo(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.0", "a" * 40))
    assert r.status == "MISMATCH"
    r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.0", WORKTREE))
    assert r.status == "MISMATCH"
    (repo / "requirements.txt").write_text("requests==2.0\n")
    r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.0", WORKTREE))
    assert r.status == "VERIFIED"
    with pytest.raises(Exception):  # noqa: B017 - any clean error, not a hang
        scan_manifests(repo, "HEAD")


def test_not_a_repo_raises_git_error(tmp_path):
    from driftwarden.git import GitError

    with pytest.raises(GitError):
        verify_dependency(tmp_path, dep("requirements.txt", "r", None, "a" * 40))


def test_shallow_and_detached(hist, tmp_path):
    repo, (c1, c2, c3, c4, c5) = hist
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)], check=True
    )
    r = verify_dependency(shallow, dep("requirements.txt", "requests", "==2.0", c1))
    assert r.status == "MISMATCH"
    r = verify_dependency(shallow, dep("requirements-prod.txt", "requests", "==2.1", c5))
    assert r.status == "VERIFIED"
    git(repo, "checkout", "-q", "--detach", c2)
    assert (
        verify_dependency(repo, dep("requirements.txt", "flask", "==3.0", c2)).status == "VERIFIED"
    )
    assert (
        verify_dependency(repo, dep("requirements-prod.txt", "flask", "==3.0", c5)).status
        == "VERIFIED"
    )
    assert (
        verify_dependency(repo, dep("requirements-prod.txt", "flask", "==3.0", WORKTREE)).status
        == "MISMATCH"
    )


def test_unreachable_commit_still_verifies_by_sha(hist):
    repo, (c1, c2, *_r) = hist
    git(repo, "checkout", "-q", "--orphan", "other")
    git(repo, "rm", "-rfq", ".")
    (repo / "go.mod").write_text("module x\n\nrequire a.b/c v1.0.0\n")
    commit_all(repo, "orphan")
    r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.1", c2))
    assert r.status == "VERIFIED"


def test_worktree_crlf_bom_match_git_show(make_repo):
    repo = make_repo()
    (repo / "requirements.txt").write_bytes(b"\xef\xbb\xbfrequests==2.0\r\nflask==3\r\n")
    c = commit_all(repo)
    for commit in (c, WORKTREE):
        r = verify_dependency(repo, dep("requirements.txt", "requests", "==2.0", commit, line=1))
        assert r.status == "VERIFIED", (commit, r.reason)
        r = verify_dependency(repo, dep("requirements.txt", "flask", "==3", commit, line=2))
        assert r.status == "VERIFIED", (commit, r.reason)


def test_binary_manifest_in_repo(make_repo):
    repo = make_repo()
    (repo / "package.json").write_bytes(bytes(range(256)) * 50)
    (repo / "requirements.txt").write_bytes(b"\xff\xfe\x00\x00")
    c = commit_all(repo)
    for p in ("package.json", "requirements.txt"):
        r = verify_dependency(repo, dep(p, "x", None, c))
        assert r.status == "MISMATCH"
    assert len(scan_manifests(repo, c)) == 2


# --------------------------------------------------------------------------- name normalisation


def _one(make_repo, path, text):
    repo = make_repo({path: text})
    return repo, sha(repo)


@pytest.mark.parametrize(
    "manifest,claim,ok",
    [
        ("requests", "request", False),
        ("requests", "requests2", False),
        ("requests", "Requests", True),
        ("foo-bar", "foo_bar", True),
        ("foo_bar", "foo.bar", True),
        ("Foo.Bar", "foo-bar", True),
        ("foo-bar", "foobar", False),
        ("foo--bar", "foo-bar", True),  # PEP 503 collapses runs
        ("zope.interface", "zope-interface", True),
        ("py", "pyy", False),
        ("a", "a-", False),
    ],
)
def test_pypi_name_normalisation(make_repo, manifest, claim, ok):
    repo, c = _one(make_repo, "requirements.txt", f"{manifest}==1.0\n")
    r = verify_dependency(repo, dep("requirements.txt", claim, "==1.0", c))
    assert (r.status == "VERIFIED") is ok, r.reason


_CS = (
    '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="1"/>'
    "</ItemGroup></Project>"
)
_TFP = 'terraform { required_providers { aws = { source = "hashicorp/aws" } } }'
_POM = (
    "<project><dependencies><dependency><groupId>G</groupId><artifactId>a</artifactId>"
    "</dependency></dependencies></project>"
)


@pytest.mark.parametrize(
    "path,text,claim,eco,ok",
    [
        ("package.json", '{"dependencies":{"foo-bar":"1"}}', "foo_bar", "npm", False),
        ("package.json", '{"dependencies":{"React":"1"}}', "react", "npm", False),
        ("package.json", '{"dependencies":{"@a/b":"1"}}', "b", "npm", False),
        ("package.json", '{"dependencies":{"@a/b":"1"}}', "@a/b", "npm", True),
        ("go.mod", "module m\nrequire github.com/A/B v1.0.0\n", "github.com/a/b", "go", False),
        ("pom.xml", _POM, "g:a", "maven", False),
        ("a.csproj", _CS, "newtonsoft.json", "nuget", True),
        ("a.csproj", _CS, "Newtonsoft_Json", "nuget", False),
        ("Dockerfile", "FROM nginx:1.25\n", "library/nginx", "docker", True),
        ("Dockerfile", "FROM nginx:1.25\n", "docker.io/library/nginx", "docker", True),
        ("Dockerfile", "FROM nginx:1.25\n", "ghcr.io/library/nginx", "docker", False),
        ("Dockerfile", "FROM nginx:1.25\n", "nginx-unprivileged", "docker", False),
        ("Dockerfile", "FROM ghcr.io/a/b:1\n", "docker.io/a/b", "docker", False),
        ("Dockerfile", "FROM a/b:1\n", "docker.io/a/b", "docker", True),
        ("main.tf", _TFP, "hashicorp/awss", "terraform-provider", False),
    ],
)
def test_other_ecosystem_name_rules(make_repo, path, text, claim, eco, ok):
    repo, c = _one(make_repo, path, text)
    res = parse_manifest(path, text)
    ref = next(r for r in res.refs if r.ecosystem == eco)
    r = verify_dependency(repo, dep(path, claim, ref.version_spec, c, ecosystem=eco))
    assert (r.status == "VERIFIED") is ok, r.reason


def test_cross_ecosystem_false_accept(make_repo):
    repo, c = _one(make_repo, "package.json", '{"dependencies":{"left-pad":"1.0.0"}}')
    r = verify_dependency(repo, dep("package.json", "left-pad", "1.0.0", c, ecosystem="pypi"))
    assert r.status == "MISMATCH"


def test_version_whitespace_ok_but_value_strict(make_repo):
    repo, c = _one(make_repo, "requirements.txt", "requests>=2.0, <3\n")
    ok = verify_dependency(repo, dep("requirements.txt", "requests", "<3,>=2.0", c))
    assert ok.status == "VERIFIED"
    for bad in (">=2.0", "<3", ">=2.0,<4", ">2.0,<3", "==2.0", None):
        r = verify_dependency(repo, dep("requirements.txt", "requests", bad, c))
        assert r.status == "MISMATCH", bad


def test_wrong_manifest_path_same_package(make_repo):
    repo = make_repo({"a/requirements.txt": "requests==2.0\n", "b/requirements.txt": "flask==1\n"})
    c = sha(repo)
    r = verify_dependency(repo, dep("b/requirements.txt", "requests", "==2.0", c))
    assert r.status == "MISMATCH"


def test_line_and_scope_tamper(make_repo):
    repo, c = _one(make_repo, "package.json", '{\n"devDependencies":{\n"a":"1"}}\n')
    base = dict(manifest_path="package.json", package="a", version_spec="1", commit=c)
    assert verify_dependency(repo, DependencyRef(**base, line=3, scope="dev")).status == "VERIFIED"
    assert verify_dependency(repo, DependencyRef(**base, line=2)).status == "MISMATCH"
    assert verify_dependency(repo, DependencyRef(**base, scope="peer")).status == "MISMATCH"
    assert verify_dependency(repo, DependencyRef(**base, line=0)).status == "MISMATCH"
    assert verify_dependency(repo, DependencyRef(**base, line=-3)).status == "MISMATCH"


# --------------------------------------------------------------------------- random tamper


@pytest.fixture(scope="module")
def poly_big(tmp_path_factory):
    repo = tmp_path_factory.mktemp("big")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    files = {
        "requirements.txt": REQS,
        "pyproject.toml": PYPROJECT,
        "package.json": PKGJSON,
        "pom.xml": POM,
        "build.gradle": GRADLE,
        "go.mod": GOMOD,
        "App.csproj": CSPROJ,
        "Dockerfile": DOCKERFILE,
        "docker-compose.yml": COMPOSE,
        "main.tf": TF,
        "k8s/all.yaml": K8S,
    }
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    commit_all(repo)
    return repo


def _mutations(rng, ref: DependencyRef, other_commit: str, other_paths: list[str]):
    """(label, tampered, must_fail): must_fail is False only if provably equivalent."""
    junk = "".join(rng.choice("qxzw") for _ in range(3))
    out = []
    out.append(("pkg+junk", ref.model_copy(update={"package": ref.package + junk}), True))
    out.append(("pkg-prefix", ref.model_copy(update={"package": junk + ref.package}), True))
    if len(ref.package) > 2:
        i = rng.randrange(len(ref.package))
        p2 = ref.package[:i] + ref.package[i + 1 :]
        same = canonical_package(ref.ecosystem, p2) == canonical_package(ref.ecosystem, ref.package)
        out.append(("pkg-del", ref.model_copy(update={"package": p2}), not same))
    ver = ref.version_spec
    out.append(("ver+junk", ref.model_copy(update={"version_spec": (ver or "") + junk}), True))
    if ver:
        out.append(("ver-none", ref.model_copy(update={"version_spec": None}), True))
        digs = [i for i, ch in enumerate(ver) if ch.isdigit()]
        if digs:
            i = rng.choice(digs)
            v2 = ver[:i] + str((int(ver[i]) + 1) % 10) + ver[i + 1 :]
            out.append(("ver-digit", ref.model_copy(update={"version_spec": v2}), True))
    out.append(("commit", ref.model_copy(update={"commit": other_commit}), True))
    out.append(("commit-zero", ref.model_copy(update={"commit": "0" * 40}), True))
    others = [p for p in other_paths if p != ref.manifest_path]
    out.append(("path", ref.model_copy(update={"manifest_path": rng.choice(others)}), True))
    if ref.line is not None:
        out.append(("line", ref.model_copy(update={"line": ref.line + rng.randint(1, 5)}), True))
    other_eco = "pypi" if ref.ecosystem != "pypi" else "npm"
    out.append(("eco", ref.model_copy(update={"ecosystem": other_eco}), True))
    if ref.scope is not None:
        out.append(("scope", ref.model_copy(update={"scope": ref.scope + "x"}), True))
    return out


def test_random_tamper_all_caught(poly_big, make_repo):
    repo = poly_big
    head = sha(repo)
    other = make_repo({"README.md": "x\n"}, name="other")
    other_commit = sha(other)  # exists only in another repo -> unknown here
    results = scan_manifests(repo, head)
    refs = [r for res in results for r in res.refs]
    assert len(refs) > 80
    by_path = {res.path: res.refs for res in results}
    rng = random.Random(1234)
    paths = sorted(by_path)
    total = 0
    escaped = []
    for ref in refs:
        assert verify_dependency(repo, ref).status == "VERIFIED", ref
        for label, t, must in _mutations(rng, ref, other_commit, paths):
            if not must:
                continue
            if t.manifest_path != ref.manifest_path:
                # a claim moved to another manifest may legitimately hold there
                legit = [
                    x
                    for x in by_path[t.manifest_path]
                    if canonical_package(x.ecosystem, x.package)
                    == canonical_package(x.ecosystem, t.package)
                    and x.version_spec == t.version_spec
                    and (t.ecosystem is None or x.ecosystem == t.ecosystem)
                    and (t.scope is None or x.scope == t.scope)
                    and (t.line is None or x.line == t.line)
                ]
                if legit:
                    continue
            total += 1
            if verify_dependency(repo, t).status != "MISMATCH":
                escaped.append((label, ref.package, t))
    assert total > 800
    assert not escaped, f"{len(escaped)}/{total} tampered records escaped, e.g. {escaped[:3]}"
