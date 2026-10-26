"""L-004 / G3: verify_dependency() re-parses the manifest at the cited commit.

* every fixture record verifies at the commit it was taken from;
* the verifier recomputes at *any* commit of a history (bump, add, remove);
* tampering with package, version_spec, commit, manifest_path, line,
  ecosystem or scope is always caught (MISMATCH with a reason);
* malformed manifests never crash a parser or the verifier.
"""

from __future__ import annotations

import json
import random
import shutil
import string
from pathlib import Path

import pytest

from conftest import git
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import (
    PARSERS,
    canonical_package,
    canonical_version,
    detect,
    parse_manifest,
    scan_manifests,
)
from driftwarden.models import WORKTREE, DependencyRef, GroundingResult

POLY = Path(__file__).parent / "fixtures" / "manifest_repos" / "poly"


@pytest.fixture
def poly_repo(tmp_path):
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


def _sha(repo: Path, rev: str = "HEAD") -> str:
    return git(repo, "rev-parse", rev).strip()


def _all_refs(repo: Path, rev: str = "HEAD") -> list[DependencyRef]:
    return [r for res in scan_manifests(repo, rev) for r in res.refs]


# --------------------------------------------------------------------------- positive


def test_every_fixture_record_verifies(poly_repo):
    refs = _all_refs(poly_repo)
    assert len(refs) == 69
    for ref in refs:
        r = verify_dependency(poly_repo, ref)
        assert r.status == "VERIFIED", r.reason
        assert r.check_id == "G3"


def test_llm_shaped_provenance_without_line_verifies(poly_repo):
    """G3 provenance is (manifest_path, package, version_spec, commit) only."""
    head = _sha(poly_repo)
    claims = [
        ("requirements.txt", "sqlalchemy", "== 2.0.29"),  # PEP 503 name + spacing
        ("pyproject.toml", "pytest-cov", None),
        ("services/web/package.json", "react", ">=18"),
        ("services/billing/pom.xml", "org.apache.kafka:kafka-clients", "3.7.0"),
        ("services/gateway/go.mod", "google.golang.org/grpc", "v1.63.2"),
        ("services/api/Api.csproj", "serilog.aspnetcore", "8.0.1"),
        ("docker-compose.yml", "docker.io/library/postgres", "16.2"),
        ("infra/terraform/main.tf", "registry.terraform.io/hashicorp/aws", "~> 5.40"),
        ("deploy/k8s/app.yaml", "ghcr.io/acme/api", "1.4.2"),
    ]
    for path, pkg, ver in claims:
        dep = DependencyRef(manifest_path=path, package=pkg, version_spec=ver, commit=head)
        r = verify_dependency(poly_repo, dep, subject=pkg)
        assert r.status == "VERIFIED", r.reason
        assert r.subject == pkg


def test_worktree_commit(poly_repo):
    dep = DependencyRef(
        manifest_path="services/gateway/go.mod",
        package="github.com/gin-gonic/gin",
        version_spec="v1.9.1",
        commit=WORKTREE,
    )
    assert verify_dependency(poly_repo, dep).status == "VERIFIED"
    (poly_repo / "services/gateway/go.mod").write_text("module x\n", encoding="utf-8")
    r = verify_dependency(poly_repo, dep)
    assert r.status == "MISMATCH" and "not declared" in r.reason
    # ... while the committed fact still verifies at HEAD.
    assert verify_dependency(
        poly_repo, dep.model_copy(update={"commit": _sha(poly_repo)})
    ).status == ("VERIFIED")


def test_result_goes_into_ledger(poly_repo, tmp_path):
    ref = _all_refs(poly_repo)[0]
    ledger = Ledger(tmp_path / "out", run_id="t")
    ledger.append(verify_dependency(poly_repo, ref))
    rec = json.loads(ledger.path.read_text().splitlines()[0])
    assert rec["check_id"] == "G3" and rec["status"] == "VERIFIED"
    assert rec["provenance"]["package"] == ref.package
    back = GroundingResult.model_validate({k: v for k, v in rec.items() if k != "run_id"})
    assert isinstance(back.provenance, DependencyRef)
    assert ledger.summary()["by_check"]["G3"] == {"VERIFIED": 1, "MISMATCH": 0}


# --------------------------------------------------------------------------- history


@pytest.fixture
def history_repo(make_repo):
    """c1: requests==2.30 + react ^17; c2: bump both, add flask; c3: drop requests."""
    repo = make_repo(
        {
            "requirements.txt": "requests==2.30.0\n",
            "package.json": '{\n  "dependencies": {\n    "react": "^17.0.2"\n  }\n}\n',
        }
    )
    (repo / "requirements.txt").write_text("requests==2.31.0\nflask>=3\n", encoding="utf-8")
    (repo / "package.json").write_text(
        '{\n  "dependencies": {\n    "react": "^18.2.0"\n  }\n}\n', encoding="utf-8"
    )
    git(repo, "commit", "-q", "-am", "bump")
    (repo / "requirements.txt").write_text("flask>=3\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "drop requests")
    shas = git(repo, "rev-list", "--reverse", "HEAD").split()
    return repo, shas


def test_recomputes_at_every_commit(history_repo):
    repo, (c1, c2, c3) = history_repo
    truth = {
        c1: {("requests", "==2.30.0"), ("react", "^17.0.2")},
        c2: {("requests", "==2.31.0"), ("flask", ">=3"), ("react", "^18.2.0")},
        c3: {("flask", ">=3"), ("react", "^18.2.0")},
    }
    for c, facts in truth.items():
        assert {(r.package, r.version_spec) for r in _all_refs(repo, c)} == facts
    paths = {"requests": "requirements.txt", "flask": "requirements.txt", "react": "package.json"}
    every_fact = set().union(*truth.values())
    for c, facts in truth.items():
        for pkg, ver in every_fact:
            dep = DependencyRef(manifest_path=paths[pkg], package=pkg, version_spec=ver, commit=c)
            r = verify_dependency(repo, dep)
            expected = "VERIFIED" if (pkg, ver) in facts else "MISMATCH"
            assert r.status == expected, f"{pkg} {ver} @{c[:7]}: {r.reason}"


def test_mismatch_reasons_are_specific(history_repo):
    repo, (c1, c2, c3) = history_repo
    dep = DependencyRef(
        manifest_path="requirements.txt", package="requests", version_spec="==2.31.0", commit=c2
    )
    r = verify_dependency(repo, dep.model_copy(update={"commit": c1}))
    assert "does not match" in r.reason and "==2.30.0" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"commit": c3}))
    assert "not declared" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"commit": "f" * 40}))
    assert "unknown commit" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"line": 2}))
    assert "declared at line 1, not line 2" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"ecosystem": "npm"}))
    assert "declared as ecosystem pypi" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"scope": "dev"}))
    assert "scope 'dev' does not match" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"manifest_path": "nope.txt"}))
    assert "file missing at commit" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"manifest_path": "../x/requirements.txt"}))
    assert "not repo-relative" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"commit": None}))
    assert "no commit" in r.reason
    r = verify_dependency(repo, dep.model_copy(update={"package": " "}))
    assert "package is empty" in r.reason


def test_non_manifest_path_is_mismatch(make_repo):
    repo = make_repo({"README.md": "requests==2.31.0\n"})
    dep = DependencyRef(
        manifest_path="README.md", package="requests", version_spec="==2.31.0", commit=_sha(repo)
    )
    r = verify_dependency(repo, dep)
    assert r.status == "MISMATCH" and "not a recognised dependency manifest" in r.reason


# --------------------------------------------------------------------------- tamper


def _other_version(ref: DependencyRef, declared: set[str | None], rng: random.Random) -> list:
    """Version mutations that are guaranteed false for this package in this manifest."""
    eco = ref.ecosystem
    out: list[str | None] = []
    base = ref.version_spec or "1.0"
    for cand in (
        base + ".1",
        "9" + base,
        base.replace(".", "", 1) if "." in base else base + "0",
        None,
        "0.0.0-tampered",
        "".join(rng.choice(string.digits + ".") for _ in range(5)),
    ):
        if canonical_version(eco, cand) not in {canonical_version(eco, d) for d in declared}:
            out.append(cand)
    return out


def _tamper_cases(repo: Path, rng: random.Random) -> list[tuple[str, DependencyRef]]:
    results = scan_manifests(repo)
    head = _sha(repo)
    root = _sha(repo, "HEAD~1")
    by_path = {res.path: res.refs for res in results}
    cases: list[tuple[str, DependencyRef]] = []
    for res in results:
        names = {canonical_package(r.ecosystem, r.package) for r in res.refs}
        for ref in res.refs:
            same = [
                r
                for r in res.refs
                if canonical_package(r.ecosystem, r.package)
                == canonical_package(ref.ecosystem, ref.package)
                and r.ecosystem == ref.ecosystem
            ]
            declared = {r.version_spec for r in same}
            # Each mutation is tried with and without the line (LLM provenance has none).
            for keep_line in (True, False):
                base = ref if keep_line else ref.model_copy(update={"line": None})
                tag = "line" if keep_line else "noline"
                # package
                for mutated in (
                    ref.package + "x",
                    "x" + ref.package,
                    ref.package[:-1] if len(ref.package) > 1 else ref.package + "zz",
                    "".join(rng.choice(string.ascii_lowercase) for _ in range(8)),
                ):
                    if canonical_package(ref.ecosystem, mutated) not in names:
                        cases.append(
                            (f"package/{tag}", base.model_copy(update={"package": mutated}))
                        )
                # version_spec
                for v in _other_version(ref, declared, rng):
                    cases.append((f"version/{tag}", base.model_copy(update={"version_spec": v})))
                # commit: unknown, before the manifest existed, truncated garbage
                for c in ("0" * 40, rng.randbytes(20).hex(), root, head[:7] + "zz", ""):
                    cases.append((f"commit/{tag}", base.model_copy(update={"commit": c})))
                # manifest_path: another manifest that does not declare this exact fact
                for other, orefs in by_path.items():
                    if other == res.path:
                        continue
                    if any(
                        canonical_package(o.ecosystem, o.package)
                        == canonical_package(o.ecosystem, ref.package)
                        and canonical_version(o.ecosystem, o.version_spec)
                        == canonical_version(o.ecosystem, ref.version_spec)
                        and (not keep_line or o.line == ref.line)
                        and o.scope == ref.scope
                        and o.ecosystem == ref.ecosystem
                        for o in orefs
                    ):
                        continue
                    cases.append((f"path/{tag}", base.model_copy(update={"manifest_path": other})))
                    break
                # ecosystem
                wrong = "npm" if ref.ecosystem != "npm" else "pypi"
                cases.append((f"ecosystem/{tag}", base.model_copy(update={"ecosystem": wrong})))
                # scope
                cases.append((f"scope/{tag}", base.model_copy(update={"scope": "tampered"})))
            # line (only meaningful with a line)
            lines = {r.line for r in same if r.version_spec == ref.version_spec}
            for delta in (1, -1, 100):
                if ref.line is not None and ref.line + delta not in lines:
                    cases.append(("line", ref.model_copy(update={"line": ref.line + delta})))
    return cases


def test_g3_tamper_all_mutations_caught(poly_repo, capsys):
    rng = random.Random(4004)
    cases = _tamper_cases(poly_repo, rng)
    by_kind: dict[str, list[int]] = {}
    missed = []
    for kind, dep in cases:
        r = verify_dependency(poly_repo, dep)
        tally = by_kind.setdefault(kind.split("/")[0], [0, 0])
        tally[1] += 1
        if r.status == "MISMATCH":
            tally[0] += 1
            assert r.reason
        else:
            missed.append((kind, dep))
    caught = sum(v[0] for v in by_kind.values())
    with capsys.disabled():
        detail = ", ".join(f"{k} {c}/{t}" for k, (c, t) in sorted(by_kind.items()))
        print(f"\nG3 tamper: {caught}/{len(cases)} caught ({detail})")
    assert not missed, missed[:5]
    assert len(cases) >= 1500
    assert set(by_kind) == {"package", "version", "commit", "path", "ecosystem", "scope", "line"}


def test_tampered_file_content_changes_commit(history_repo):
    """Editing the manifest after the claim is made does not re-validate the old claim."""
    repo, (_c1, _c2, c3) = history_repo
    dep = DependencyRef(
        manifest_path="requirements.txt", package="flask", version_spec=">=3", commit=c3
    )
    assert verify_dependency(repo, dep).status == "VERIFIED"
    (repo / "requirements.txt").write_text("flask>=4\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "flask 4")
    new = _sha(repo)
    assert verify_dependency(repo, dep).status == "VERIFIED"  # still true at c3
    assert verify_dependency(repo, dep.model_copy(update={"commit": new})).status == "MISMATCH"


# --------------------------------------------------------------------------- malformed


MALFORMED = {
    "requirements.txt": [
        "\x00\x01\x02",
        "==1.0\n",
        "[extra]\n",
        "-e\n",
        "-e#egg=x\n",  # regression: found by fuzzing (IndexError)
        "pkg ===\n",
        "\\\n",
    ],
    "pyproject.toml": ["[project\n", 'dependencies = "x"\n', "[project]\ndependencies = 3\n"],
    "package.json": ["{", "[]", '{"dependencies": [1, 2]}', '{"dependencies": {"": "1"}}', "null"],
    "pom.xml": ["<project>", "<notpom/>", "", "<?xml?>", "<project><dependency></project>"],
    "build.gradle": ['implementation("', "dependencies {", "/* unterminated", "plugins {\n"],
    "libs.versions.toml": ["[libraries]\nx = 3\n", "[libraries\n", "[libraries]\nx = {}\n"],
    "go.mod": ["require (\n", "!!!\n", "require\n", "require x\n"],
    "App.csproj": ["<Project>", "<Other/>", '<Project><PackageReference Include=""/></Project>'],
    "packages.config": ["<packages><package/></packages>", "<x/>"],
    "Dockerfile": ["FROM\n", "FROM --platform=x\n", "\\\n", "ARG\nFROM ${\n", "COPY --from=\n"],
    "docker-compose.yml": [": :\n", "services: 3\n", "services:\n  a: [1]\n", "", "- a\n- b\n"],
    "main.tf": ["terraform {\n", 'x = "unterminated\n', "}}}\n", "<<EOF\nnever closed\n", "]\n"],
    "k8s.yaml": ["apiVersion: v1\nkind: Pod\nspec: {containers: [", "apiVersion: v1\nkind: [\n"],
}


@pytest.mark.parametrize("path,text", [(p, t) for p, texts in MALFORMED.items() for t in texts])
def test_malformed_manifest_does_not_crash(path, text):
    res = parse_manifest(path, text)
    assert res.kind is not None
    # Failures are reported as manifest errors, never as an internal parser bug.
    assert not any(e.startswith("parser error") for e in res.errors), res.errors


def test_yaml_alias_bomb_and_recursion_are_safe():
    bomb = "apiVersion: v1\nkind: List\na: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\n" + "".join(
        f"d{i}: &d{i} [*{'c' if i == 0 else f'd{i - 1}'}, *{'c' if i == 0 else f'd{i - 1}'}]\n"
        for i in range(20)
    )
    res = parse_manifest("bomb.yaml", bomb)
    assert res.errors == [] and res.refs == []
    recursive = "apiVersion: v1\nkind: Pod\nspec: &s\n  containers:\n  - image: a:1\n  more: *s\n"
    res = parse_manifest("rec.yaml", recursive)
    assert [(r.package, r.version_spec) for r in res.refs] == [("a", "1")]


@pytest.mark.parametrize(
    "path,text",
    [
        ("package.json", "[" * 100_000),
        ("k8s.yaml", "apiVersion: v1\nkind: Pod\nspec: " + "[" * 50_000),
        ("main.tf", "a {\n" * 20_000),
        ("main.tf", "x = " + "{ y = " * 20_000),
        ("pom.xml", "<project>" + "<a>" * 20_000),
    ],
)
def test_deeply_nested_input_is_an_error_not_a_crash(path, text):
    res = parse_manifest(path, text)
    assert res.errors and res.refs == []


def _fuzz_texts(rng: random.Random) -> list[tuple[str, str]]:
    out = []
    for f in sorted(POLY.rglob("*")):
        if not f.is_file() or parse_manifest(f.name, "").kind is None and f.suffix != ".yaml":
            continue
        rel = f.relative_to(POLY).as_posix()
        text = f.read_text(encoding="utf-8")
        for cut in range(0, len(text), max(1, len(text) // 25)):
            out.append((rel, text[:cut]))
        for _ in range(25):
            chars = list(text)
            for _ in range(rng.randint(1, 8)):
                i = rng.randrange(len(chars))
                chars[i] = rng.choice("{}[]()<>\"'=:#\\\n-$@ " + string.ascii_letters)
            out.append((rel, "".join(chars)))
    return out


def test_fuzzed_manifests_never_crash():
    rng = random.Random(404)
    texts = _fuzz_texts(rng)
    assert len(texts) > 500
    for rel, text in texts:
        res = parse_manifest(rel, text)
        assert not any(e.startswith("parser error") for e in res.errors), (rel, res.errors, text)


def test_every_parser_kind_covered_by_malformed_cases():
    kinds = {detect(p).kind for p in MALFORMED}
    assert kinds == {p.kind for p in PARSERS}


def test_verifier_on_malformed_manifest_commit(make_repo):
    repo = make_repo({"package.json": '{"dependencies": {"react": "^18.2.0"}}\n'})
    good = _sha(repo)
    (repo / "package.json").write_text('{"dependencies": {"react": "^18.2.0"', encoding="utf-8")
    git(repo, "commit", "-q", "-am", "break it")
    bad = _sha(repo)
    dep = DependencyRef(
        manifest_path="package.json", package="react", version_spec="^18.2.0", commit=good
    )
    assert verify_dependency(repo, dep).status == "VERIFIED"
    r = verify_dependency(repo, dep.model_copy(update={"commit": bad}))
    assert r.status == "MISMATCH" and "could not be parsed" in r.reason


def test_big_manifest_is_refused_not_parsed():
    res = parse_manifest("requirements.txt", "a==1\n" * 500_000)
    assert res.refs == [] and "larger than" in res.errors[0]
