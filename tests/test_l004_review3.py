"""L-004: regression tests for Codex review round 3 on PR #10 (findings a-c)."""

from __future__ import annotations

import time
import tracemalloc

import pytest

from conftest import git
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import parse_manifest
from driftwarden.models import DependencyRef


def _rows(path: str, text: str):
    res = parse_manifest(path, text)
    assert res.errors == [], res.errors
    return [(r.package, r.version_spec, r.line, r.scope) for r in res.refs]


# ------------------------------------------------------------------------ (a) maven property bomb


def _pom(props: str, version: str = "${v}") -> str:
    return (
        "<project><groupId>g</groupId><artifactId>root</artifactId>\n"
        f"<properties>{props}</properties>\n"
        "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>"
        f"<version>{version}</version></dependency></dependencies></project>\n"
    )


def _bounded(text: str):
    tracemalloc.start()
    t = time.perf_counter()
    try:
        res = parse_manifest("pom.xml", text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert time.perf_counter() - t < 1.0
    assert peak < 50 * 1024 * 1024
    return res


def test_maven_self_referencing_property_bomb_is_bounded():
    res = _bounded(_pom("<v>" + "${v}" * 10 + "</v>"))
    assert res.refs == [] and res.errors and "cycle" in res.errors[0]


def test_maven_chained_property_bomb_hits_size_budget():
    props = "<p0>xxxxxxxxxx</p0>" + "".join(
        f"<p{i}>" + f"${{p{i - 1}}}" * 10 + f"</p{i}>" for i in range(1, 12)
    )
    res = _bounded(_pom(props, "${p11}"))
    assert res.refs == [] and res.errors and "budget" in res.errors[0]


def test_maven_mutual_cycle_is_an_error():
    res = _bounded(_pom("<a>${b}</a><b>${a}</b>", "${a}"))
    assert res.refs == [] and "cycle" in res.errors[0]


def test_maven_nested_properties_still_resolve():
    rows = _rows("pom.xml", _pom("<major>2</major><v>${major}.${minor}.1</v><minor>3</minor>"))
    assert rows == [("g:a", "2.3.1", 3, None)]
    rows = _rows("pom.xml", _pom("", "${undefined.prop}"))
    assert rows == [("g:a", "${undefined.prop}", 3, None)]  # unknown: kept verbatim


# --------------------------------------------------------------------------- (b) quoted "<<EOF"


@pytest.mark.parametrize(
    "run",
    [
        'RUN echo "<<EOF"',
        "RUN echo '<<EOF'",
        "RUN echo $((1<<EOF))",
        'RUN echo "a \\" <<EOF"',
        "RUN x=$(( (1 <<EOF) )) && echo",
    ],
)
def test_dockerfile_quoted_or_arith_heredoc_marker_is_not_heredoc(run):
    text = f"FROM alpine:3\n{run}\nFROM redis:7\n"
    assert _rows("Dockerfile", text) == [
        ("alpine", "3", 1, "base"),
        ("redis", "7", 3, "base"),
    ]


def test_dockerfile_real_heredoc_after_quoted_marker():
    text = 'FROM alpine:3\nRUN echo "<<X" && cat <<EOF\nFROM evil:1\nEOF\nFROM redis:7\n'
    assert _rows("Dockerfile", text) == [
        ("alpine", "3", 1, "base"),
        ("redis", "7", 5, "base"),
    ]


def test_dockerfile_real_unterminated_heredoc_still_consumes_to_eof():
    text = "FROM alpine:3\nRUN <<EOF\nFROM redis:7\n"
    assert _rows("Dockerfile", text) == [("alpine", "3", 1, "base")]


def test_dockerfile_quoted_marker_verifies_following_image(make_repo):
    repo = make_repo({"Dockerfile": 'FROM alpine:3\nRUN echo "<<EOF"\nFROM redis:7\n'})
    sha = git(repo, "rev-parse", "HEAD").strip()
    dep = DependencyRef(manifest_path="Dockerfile", package="redis", version_spec="7", commit=sha)
    assert verify_dependency(repo, dep).status == "VERIFIED"


# --------------------------------------------------------------------------- (c) catalog rich refs


@pytest.mark.parametrize("kind", ["strictly", "require", "prefer"])
def test_version_catalog_ref_to_rich_version(kind):
    text = (
        "[versions]\n"
        f'foo = {{ {kind} = "1.2.3" }}\n'
        "[libraries]\n"
        'a = { module = "g:a", version.ref = "foo" }\n'
        f'b = {{ module = "g:b", version = {{ {kind} = "1.2.3" }} }}\n'
        "[plugins]\n"
        'p = { id = "com.example.p", version.ref = "foo" }\n'
    )
    assert _rows("gradle/libs.versions.toml", text) == [
        ("g:a", "1.2.3", 4, "catalog:a"),
        ("g:b", "1.2.3", 5, "catalog:b"),
        ("com.example.p", "1.2.3", 7, "plugin"),
    ]


def test_version_catalog_rich_precedence_and_missing_ref():
    text = (
        "[versions]\n"
        'foo = { require = "1.0", strictly = "[1.0,2.0)", prefer = "1.5" }\n'
        "[libraries]\n"
        'a = { module = "g:a", version.ref = "foo" }\n'
        'b = { module = "g:b", version.ref = "missing" }\n'
    )
    assert _rows("libs.versions.toml", text) == [
        ("g:a", "[1.0,2.0)", 4, "catalog:a"),  # strictly > require > prefer
        ("g:b", None, 5, "catalog:b"),
    ]
