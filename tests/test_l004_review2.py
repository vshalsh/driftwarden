"""L-004: regression tests for Codex review round 2 on PR #10 (findings a-d)."""

from __future__ import annotations

import time

import pytest

from conftest import git
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import parse_manifest
from driftwarden.index.manifests.python import parse_requirement
from driftwarden.models import DependencyRef


def _rows(path: str, text: str):
    res = parse_manifest(path, text)
    assert res.errors == [], res.errors
    return [(r.package, r.version_spec, r.line, r.scope) for r in res.refs]


# --------------------------------------------------------------------------- (a) heredocs

HEREDOC = """\
# syntax=docker/dockerfile:1.4
FROM alpine:3.19
COPY <<EOF /tmp/Dockerfile.inner
FROM redis:7
COPY --from=evil:1 / /
EOF
RUN <<EOT bash
  echo FROM postgres:16
EOT
RUN <<-"END"
\tFROM mysql:8
\tEND
COPY <<'A' <<B /x/
FROM a:1
A
FROM b:1
B
FROM python:3.12
"""


def test_dockerfile_heredoc_payload_is_not_instructions():
    assert _rows("Dockerfile", HEREDOC) == [
        ("alpine", "3.19", 2, "base"),
        ("python", "3.12", 18, "base"),
    ]


def test_dockerfile_heredoc_false_accept_closed(make_repo):
    repo = make_repo({"Dockerfile": HEREDOC})
    sha = git(repo, "rev-parse", "HEAD").strip()
    for pkg, ver in (("redis", "7"), ("evil", "1"), ("mysql", "8"), ("a", "1"), ("b", "1")):
        dep = DependencyRef(manifest_path="Dockerfile", package=pkg, version_spec=ver, commit=sha)
        assert verify_dependency(repo, dep).status == "MISMATCH", pkg


def test_dockerfile_unterminated_heredoc_consumes_rest():
    text = "FROM alpine:3.19\nRUN <<EOF\nFROM redis:7\n"
    assert _rows("Dockerfile", text) == [("alpine", "3.19", 1, "base")]


def test_dockerfile_shift_operator_is_not_heredoc_marker():
    # `<<` followed by a non-word (or a space) is not a heredoc.
    text = "FROM alpine:3.19\nRUN echo $((1 << 2))\nFROM python:3.12\n"
    assert _rows("Dockerfile", text) == [
        ("alpine", "3.19", 1, "base"),
        ("python", "3.12", 3, "base"),
    ]


# --------------------------------------------------------------------------- (b) merge-key blowup


def _merge_chain(levels: int) -> str:
    out = ["x-l0: &l0\n  image: base:1\n"]
    for i in range(1, levels + 1):
        out.append(f"x-l{i}: &l{i}\n  <<: [*l{i - 1}, *l{i - 1}]\n  k{i}: v\n")
    out.append(f"services:\n  app:\n    <<: *l{levels}\n")
    return "".join(out)


def test_compose_merge_chain_is_linear():
    text = _merge_chain(40)
    t = time.perf_counter()
    rows = _rows("docker-compose.yml", text)
    assert time.perf_counter() - t < 1.0
    assert rows == [("base", "1", 2, "service:app")]


def test_merge_memo_keeps_precedence():
    text = (
        "x-a: &a\n  image: a:1\n"
        "x-b: &b\n  <<: *a\n  image: b:1\n"
        "services:\n"
        "  one:\n    <<: [*b, *a]\n"
        "  two:\n    <<: [*a, *b]\n"
        "  three:\n    <<: *b\n    image: c:1\n"
    )
    assert _rows("compose.yaml", text) == [
        ("b", "1", 5, "service:one"),
        ("a", "1", 2, "service:two"),
        ("c", "1", 13, "service:three"),
    ]


# --------------------------------------------------------------------------- (c) gradle multi-line


def test_gradle_kotlin_multiline_literal_and_named_args():
    text = (
        "dependencies {\n"
        "    implementation(\n"
        '        "org.example:thing:1.0"\n'
        "    )\n"
        "    testImplementation(\n"
        '        group = "org.junit.jupiter",\n'
        '        name = "junit-jupiter",\n'
        '        version = "5.10.2",\n'
        "    )\n"
        "    api(platform(\n"
        '        "software.amazon.awssdk:bom:2.25.0"))\n'
        '    runtimeOnly("org.postgresql:postgresql:42.7.3")\n'
        "}\n"
    )
    assert _rows("build.gradle.kts", text) == [
        ("org.example:thing", "1.0", 3, None),
        ("org.junit.jupiter:junit-jupiter", "5.10.2", 6, "test"),
        ("software.amazon.awssdk:bom", "2.25.0", 11, None),
        ("org.postgresql:postgresql", "42.7.3", 12, None),
    ]


def test_gradle_groovy_multiline_map_notation():
    text = (
        "dependencies {\n"
        "    implementation group: 'org.apache.commons',\n"
        "                   name: 'commons-lang3',\n"
        "                   version: '3.14.0'\n"
        "}\n"
    )
    assert _rows("build.gradle", text) == [("org.apache.commons:commons-lang3", "3.14.0", 2, None)]


def test_gradle_multiline_comment_between_is_still_ignored():
    text = 'dependencies {\n    implementation(\n        // "x:y:1"\n        "a:b:2"\n    )\n}\n'
    assert _rows("build.gradle.kts", text) == [("a:b", "2", 4, None)]


# --------------------------------------------------------------------------- (d) PEP 508 URL ';'


@pytest.mark.parametrize(
    "req,expected",
    [
        (
            "pkg @ https://x.invalid/pkg.whl?version=1;build=2",
            ("pkg", "@ https://x.invalid/pkg.whl?version=1;build=2"),
        ),
        (
            "pkg @ https://x.invalid/pkg.whl?version=1;build=2 ; python_version >= '3.10'",
            ("pkg", "@ https://x.invalid/pkg.whl?version=1;build=2"),
        ),
        (
            "pkg[extra] @ git+https://x.invalid/r.git@v1;x",
            ("pkg", "@ git+https://x.invalid/r.git@v1;x"),
        ),
        ("pkg>=1;python_version<'3.12'", ("pkg", ">=1")),
    ],
)
def test_direct_reference_semicolon_is_part_of_url(req, expected):
    assert parse_requirement(req) == expected


def test_direct_reference_semicolon_in_requirements_and_pyproject(make_repo):
    url = "https://x.invalid/pkg.whl?version=1;build=2"
    req = f"pkg @ {url}\n"
    pyproject = f"[project]\ndependencies = [\"pkg @ {url} ; os_name == 'posix'\"]\n"
    assert _rows("requirements.txt", req) == [("pkg", f"@ {url}", 1, None)]
    assert _rows("pyproject.toml", pyproject) == [("pkg", f"@ {url}", 2, None)]
    repo = make_repo({"requirements.txt": req})
    sha = git(repo, "rev-parse", "HEAD").strip()
    base = {"manifest_path": "requirements.txt", "package": "pkg", "commit": sha}
    good = DependencyRef(version_spec=f"@ {url}", **base)
    assert verify_dependency(repo, good).status == "VERIFIED"
    truncated = DependencyRef(version_spec="@ https://x.invalid/pkg.whl?version=1", **base)
    assert verify_dependency(repo, truncated).status == "MISMATCH"
