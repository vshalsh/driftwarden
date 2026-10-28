"""L-030 system tests (Sonnet, independent of the developer's suite).

Black-box over the public judge / detector / gate entry points: nesting and case, lookalike
names, mixed occurrences, manifests inside vendor/, boundary imports, the ``external/``
recall limit (measured, a known limit and not a defect), a forged verdict, and judge vs
detector agreement. No network, offline provider only.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from driftwarden.index.vendored import VENDORED_DIRS, is_vendored
from driftwarden.judge import Judge, load_snapshot, verify_evidence
from driftwarden.judge.judge import gate
from driftwarden.models import WORKTREE, Claim, Provenance, Verdict
from driftwarden.undocumented import detect as detect_mod
from driftwarden.undocumented import detect_undocumented

PLAIN = "x = 1\n"
REQ = "import requests\n"


def _git(repo: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


@pytest.fixture
def repo_of(tmp_path):
    n = [0]

    def build(files: dict[str, str], symlinks: dict[str, str] | None = None) -> Path:
        n[0] += 1
        repo = tmp_path / f"r{n[0]}"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "commit.gpgsign", "false")
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        for rel, target in (symlinks or {}).items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, p)
        _git(repo, "add", "-A", "-f")
        _git(repo, "commit", "-q", "-m", "c")
        return repo

    return build


def mk(kind: str, rule: dict) -> Claim:
    return Claim(
        id="T.c1",
        kind=kind,  # type: ignore[arg-type]
        subject="x",
        rule=rule,
        source=Provenance(
            path="docs/adr/0001-x.md", line_start=1, line_end=1, commit=WORKTREE, quote="text"
        ),
        decision_id="T",
        origin="rule",
    )


def judge(repo: Path, kind: str, rule: dict) -> Verdict:
    return Judge(repo, mode="offline").judge(mk(kind, rule))


def forbid_requests(repo: Path) -> Verdict:
    return judge(repo, "forbid", {"forbid": ["requests"]})


def paths(v: Verdict) -> list[str]:
    return sorted(e.ref.path for e in v.evidence)


def verified(repo: Path, v: Verdict) -> None:
    assert v.grounding == "VERIFIED", v.reasons
    for ev in v.evidence:
        assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=v.commit))


# ----------------------------------------------------------- nesting and case


@pytest.mark.parametrize(
    "path",
    [
        "vendor/x.py",
        "a/b/vendor/x.py",
        "a/b/c/d/node_modules/p/q/r/x.js",
        "vendor/vendor/x.py",
        "src/third_party/x/y.py",
        "a/external/b.py",
    ],
)
def test_vendored_dir_at_any_depth_is_vendored(path):
    assert is_vendored(path)


@pytest.mark.parametrize(
    "path",
    ["Vendor/x.py", "VENDOR/x.py", "Node_Modules/x.js", "pods/x.yaml", "External/x.py"],
)
def test_case_is_exact_so_other_casings_are_not_vendored(path):
    """What the code does: segment match is case-sensitive. Sensible: ``Pods/`` is CocoaPods
    while ``pods/`` is typically k8s manifests; ``Vendor/`` (PHP/.NET namespaces) is project
    code more often than not. Trade-off: on a case-insensitive filesystem a real vendor tree
    committed as ``Vendor/`` is judged as project code (precision loss, not a crash)."""
    assert not is_vendored(path)


def test_pods_capitalised_is_vendored_lowercase_is_not():
    assert is_vendored("ios/Pods/Foo/a.swift")
    assert not is_vendored("deploy/pods/web.yaml")


def test_nested_vendor_dir_in_judge(repo_of):
    repo = repo_of({"app/a.py": PLAIN, "a/b/vendor/x/lib.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "HOLDING" and v.evidence == []


def test_capitalised_vendor_dir_is_project_code_in_judge(repo_of):
    repo = repo_of({"app/a.py": PLAIN, "Vendor/lib.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "VIOLATED" and paths(v) == ["Vendor/lib.py"]


def test_a_directory_path_counts_only_by_its_parents():
    """Documented behaviour: ``vendor`` itself is not inside vendor/, ``vendor/lib`` is."""
    assert not is_vendored("vendor")
    assert is_vendored("vendor/lib")


# ----------------------------------------------------------- lookalikes


@pytest.mark.parametrize(
    "path",
    [
        "vendor_utils/x.py",
        "my-vendor/x.py",
        "vendorx/x.py",
        "avendor/x.py",
        "src/vendoring/x.py",
        "vendor.py",
        "src/vendor.py",
        "vendor",  # a file literally named vendor
        "src/vendor",
        "node_modules.py",
        "external.py",
        "externals/x.py",
        "third_party.py",
        "thirdparty_notes/x.py",
    ],
)
def test_lookalikes_are_not_vendored(path):
    assert not is_vendored(path)


def test_vendors_plural_is_vendored_by_the_shared_set():
    """The brief listed ``vendors/`` among non-vendored lookalikes. The code (and the detector
    before L-030) treat ``vendors`` as vendored (Composer-style). Pre-existing detector
    behaviour, now shared; pinned here and reported as an observation."""
    assert "vendors" in VENDORED_DIRS
    assert is_vendored("vendors/x.py")


@pytest.mark.parametrize(
    "name",
    ["vendor_utils/x.py", "my-vendor/x.py", "vendor.py", "src/vendoring/x.py", "externals/x.py"],
)
def test_lookalike_import_is_still_evidence(repo_of, name):
    repo = repo_of({"app/a.py": PLAIN, name: REQ})
    v = forbid_requests(repo)
    assert v.status == "VIOLATED", (name, v.rationale)
    assert paths(v) == [name]
    verified(repo, v)


def test_a_file_literally_named_vendor_is_not_vendored_and_extensionless_is_unparsed(repo_of):
    """``vendor`` the file is not inside vendor/. (An extensionless file has no language, so
    it yields no import evidence either way; asserted so nobody mistakes that for the rule.)"""
    repo = repo_of({"app/a.py": PLAIN, "vendor": REQ})
    assert not is_vendored("vendor")
    assert forbid_requests(repo).status == "HOLDING"


def test_windows_style_paths_are_not_split_on_backslash():
    """Snapshot paths come from git and are always POSIX; the predicate splits only on ``/``.
    A backslash path never arises from a real checkout (git normalises), so it is never
    judged vendored; this pins the behaviour so a change is deliberate."""
    assert not is_vendored("vendor\\x.py")
    assert not is_vendored("a\\node_modules\\x.js")
    assert is_vendored("a/node_modules/x.js")


def test_symlink_into_vendor_is_not_followed(repo_of):
    """A tracked symlink ``app/lib -> ../vendor/lib`` is a link entry, not a copy: vendored
    content is reachable only under vendor/ and is dropped; the link is never cited."""
    repo = repo_of(
        {"app/a.py": PLAIN, "vendor/lib/x.py": REQ}, symlinks={"app/lib": "../vendor/lib"}
    )
    v = forbid_requests(repo)
    assert v.status == "HOLDING", (v.status, v.rationale, paths(v))
    assert not any(p.startswith("app/lib") for p in paths(v))


# ----------------------------------------------------------- mixed occurrences


def test_vendored_plus_real_is_violated_citing_only_real(repo_of):
    repo = repo_of({"app/a.py": REQ, "vendor/a.py": REQ, "node_modules/x/b.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "VIOLATED"
    assert paths(v) == ["app/a.py"]
    assert any("vendored" in n for n in v.notes)
    verified(repo, v)


def test_vendored_plus_test_only_is_drifting(repo_of):
    repo = repo_of({"app/a.py": PLAIN, "tests/test_a.py": REQ, "vendor/a.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "DRIFTING", v.rationale
    assert paths(v) == ["tests/test_a.py"]


def test_vendored_plus_dev_dependency_is_drifting(repo_of):
    repo = repo_of(
        {
            "app/a.py": PLAIN,
            "requirements-dev.txt": "requests==2.31.0\n",
            "vendor/py/requirements.txt": "requests==1.0\n",
        }
    )
    v = forbid_requests(repo)
    assert v.status == "DRIFTING", v.rationale
    assert paths(v) == ["requirements-dev.txt"]


def test_vendored_plus_test_plus_real_is_violated(repo_of):
    repo = repo_of({"app/a.py": REQ, "tests/test_a.py": REQ, "vendor/a.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "VIOLATED" and "app/a.py" in paths(v)
    assert "vendor/a.py" not in paths(v)


def test_real_code_beside_lookalike_dirs_is_not_lost(repo_of):
    """No new false negative: production code in lookalike-named folders next to vendor/."""
    repo = repo_of({"src/vendoring/a.py": REQ, "vendor_utils/b.py": REQ, "vendor/c.py": REQ})
    v = forbid_requests(repo)
    assert v.status == "VIOLATED"
    assert paths(v) == ["src/vendoring/a.py", "vendor_utils/b.py"]


# ----------------------------------------------------------- manifests inside vendor/

PKG = '{\n  "name": "s",\n  "dependencies": {\n    "twilio": "^4.0.0"\n  }\n}\n'


@pytest.mark.parametrize(
    "manifest,text,term",
    [
        ("vendor/x/package.json", PKG, "twilio"),
        ("node_modules/x/package.json", PKG, "twilio"),
        ("third_party/x/requirements.txt", "requests==1.0\n", "requests"),
        (
            "external/x/pyproject.toml",
            '[project]\nname="x"\ndependencies=["requests"]\n',
            "requests",
        ),
        (
            "vendor/x/go.mod",
            "module x\n\nrequire github.com/aws/aws-sdk-go v1.50.0\n",
            "aws-sdk-go",
        ),
        ("vendor/x/docker-compose.yml", "services:\n  d:\n    image: mongo:6\n", "mongodb"),
    ],
)
def test_manifest_inside_vendor_does_not_make_a_dependency_present(repo_of, manifest, text, term):
    repo = repo_of({"app/a.py": PLAIN, manifest: text})
    v = judge(repo, "forbid", {"forbid": [term]})
    assert v.status == "HOLDING", (manifest, v.status, v.rationale)
    assert v.evidence == []


def test_require_is_not_satisfied_by_a_vendored_manifest(repo_of):
    repo = repo_of({"app/a.py": PLAIN, "vendor/x/requirements.txt": "psycopg2==2.9\n"})
    v = judge(repo, "require", {"require": ["psycopg2"]})
    assert not any(is_vendored(p) for p in paths(v))
    assert v.status != "HOLDING" or "vendored" in " ".join(v.notes), v.rationale


# ----------------------------------------------------------- boundary


def test_project_import_of_the_projects_own_module_is_still_a_crossing(repo_of):
    """A vendored module that shares the target's name must not shadow or hide the real
    payments/: app/a.py importing payments still crosses the boundary."""
    repo = repo_of(
        {
            "payments/__init__.py": "",
            "payments/core.py": PLAIN,
            "billing/b.py": "from payments import core\n",
            "vendor/pay/payments.py": PLAIN,
            "app/a.py": "import payments\n",
        }
    )
    v = judge(repo, "boundary", {"target": ["payments/"], "allowed_in": ["billing/"]})
    assert v.status == "VIOLATED", v.rationale
    assert paths(v) == ["app/a.py"]


def test_project_code_importing_a_vendored_module_is_no_crossing(repo_of):
    """app/a.py reaches into a vendored copy named like the boundary target: the edge's
    target is vendored, so it is not a crossing of the project's payments/."""
    repo = repo_of(
        {
            "payments/__init__.py": "",
            "payments/core.py": PLAIN,
            "billing/b.py": "from payments import core\n",
            "vendor/payments/__init__.py": "",
            "vendor/payments/core.py": PLAIN,
            "app/a.py": "from vendor.payments import core\n",
        }
    )
    v = judge(repo, "boundary", {"target": ["payments/"], "allowed_in": ["billing/"]})
    assert v.status == "HOLDING", v.rationale
    assert not any(is_vendored(p) for p in paths(v))
    assert "app/a.py" not in paths(v)
    assert any("vendored" in n for n in v.notes)


def test_vendored_code_importing_project_code_is_no_crossing(repo_of):
    repo = repo_of(
        {
            "payments/__init__.py": "",
            "payments/core.py": PLAIN,
            "billing/b.py": "from payments import core\n",
            "vendor/plugin/p.py": "from payments import core\n",
            "node_modules/q/q.py": "import payments\n",
        }
    )
    v = judge(repo, "boundary", {"target": ["payments/"], "allowed_in": ["billing/"]})
    assert v.status == "HOLDING", v.rationale
    assert not any(is_vendored(p) for p in paths(v))


def test_vendored_importer_beside_a_real_crossing(repo_of):
    repo = repo_of(
        {
            "payments/__init__.py": "",
            "payments/core.py": PLAIN,
            "app/a.py": "from payments import core\n",
            "vendor/plugin/p.py": "from payments import core\n",
        }
    )
    v = judge(repo, "boundary", {"target": ["payments/"], "allowed_in": ["billing/"]})
    assert v.status == "VIOLATED" and paths(v) == ["app/a.py"]
    verified(repo, v)


def test_technology_boundary_ignores_vendored_importers(repo_of):
    repo = repo_of(
        {
            "adapters/s3.py": "import boto3\n",
            "vendor/x/y.py": "import boto3\n",
            "third_party/z.py": "import boto3\n",
        }
    )
    v = judge(repo, "boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]})
    assert v.status == "HOLDING"
    assert paths(v) == ["adapters/s3.py"]  # the allowed use, never the vendored importers
    assert any("vendor/x/y.py" in n for n in v.notes)


# ----------------------------------------------------------- recall guard: external/


def test_project_folder_named_external_is_now_ignored_known_limit(repo_of):
    """KNOWN LIMIT, not a defect. A first-party ``external/`` (integration code for external
    services) is dropped from evidence, so a violation there is a false negative. The
    ``index/vendored.py`` docstring states this trade-off ("precision over recall"), so the
    docs do not claim otherwise. It is not silent: the verdict note names the file."""
    repo = repo_of({"app/a.py": PLAIN, "external/stripe_client.py": "import boto3\n"})
    v = judge(repo, "forbid", {"forbid": ["boto3"]})
    assert v.status == "HOLDING"  # the false negative, recorded
    assert any("external/stripe_client.py" in n for n in v.notes)


def test_recall_impact_every_set_member_hides_a_violation_but_only_vendored_names(repo_of):
    """Impact measurement: one violation per name in VENDORED_DIRS plus one in src/. Only the
    src/ one is seen. The set has 13 names; of these the ones a team could plausibly use for
    first-party code are vendor, vendors, external, third_party/third-party/thirdparty."""
    files = {"app/ok.py": PLAIN, "src/real.py": REQ}
    for d in sorted(VENDORED_DIRS):
        files[f"{d}/m.py"] = REQ
    repo = repo_of(files)
    v = forbid_requests(repo)
    assert paths(v) == ["src/real.py"]
    assert {"vendor", "vendors", "external", "third_party", "third-party", "thirdparty"} <= (
        VENDORED_DIRS
    )
    assert len(VENDORED_DIRS) == 13  # growing the set widens the recall limit: do it knowingly


# ----------------------------------------------------------- gate tamper


def _forged(repo: Path, vendored_path: str, quote: str) -> Verdict:
    """A genuine VIOLATED verdict (its VERIFIED G2 records and grounding left as they were)
    whose evidence citation is swapped to a vendored path with a verbatim quote."""
    v = forbid_requests(repo)
    assert v.status == "VIOLATED" and v.grounding == "VERIFIED"
    ev = v.evidence[0]
    ref = ev.ref.model_copy(
        update={"path": vendored_path, "line_start": 1, "line_end": 1, "quote": quote}
    )
    data = v.model_dump()
    data["evidence"] = [ev.model_copy(update={"ref": ref}).model_dump()]
    return Verdict.model_validate(data)


def test_forged_verdict_citing_vendored_path_with_verified_record_is_refused(repo_of):
    repo = repo_of({"app/a.py": REQ, "vendor/lib/a.py": REQ})
    forged = _forged(repo, "vendor/lib/a.py", "import requests")
    assert forged.grounding == "VERIFIED" and forged.status == "VIOLATED"
    # the quote really is verbatim there, so only the vendored rule can stop it
    rs = verify_evidence(repo, forged.evidence[0], commit=forged.commit)
    assert all(r.status == "VERIFIED" for r in rs)
    g = gate(forged, repo)
    assert g.status == "UNKNOWN" and g.grounding == "MISMATCH"
    assert any("vendored" in r for r in g.reasons)


@pytest.mark.parametrize("p", ["node_modules/q/a.py", "a/b/third_party/a.py", "external/a.py"])
def test_forged_citation_refused_for_each_vendored_dir(repo_of, p):
    repo = repo_of({"app/a.py": REQ, p: REQ})
    g = gate(_forged(repo, p, "import requests"), repo)
    assert g.status == "UNKNOWN" and g.grounding == "MISMATCH"


def test_gate_still_passes_an_honest_verdict(repo_of):
    repo = repo_of({"app/a.py": REQ, "vendor/lib/a.py": REQ})
    g = gate(forbid_requests(repo), repo)
    assert g.status == "VIOLATED" and g.grounding == "VERIFIED", g.reasons


def test_gate_does_not_refuse_a_lookalike_path(repo_of):
    repo = repo_of({"vendor_utils/a.py": REQ})
    g = gate(forbid_requests(repo), repo)
    assert g.status == "VIOLATED" and g.grounding == "VERIFIED", g.reasons


# ----------------------------------------------------------- judge / detector agreement

AGREE_PATHS = [
    "app/x.py",
    "vendor/x.py",
    "a/b/vendor/x.py",
    "vendors/x.py",
    "Vendor/x.py",
    "node_modules/x.py",
    "external/x.py",
    "src/external/x.py",
    "externals/x.py",
    "third_party/x.py",
    "third-party/x.py",
    "thirdparty/x.py",
    "ios/Pods/x.py",
    "deploy/pods/x.py",
    "vendor_utils/x.py",
    ".venv/lib/x.py",
    "venv/x.py",
    "site-packages/x.py",
    "bower_components/x.py",
    "jspm_packages/x.py",
    "vendor.py",
]


def test_detector_reexports_the_one_predicate():
    assert detect_mod.is_vendored is is_vendored
    assert detect_mod.VENDORED_DIRS is VENDORED_DIRS


@pytest.mark.parametrize("path", AGREE_PATHS)
def test_judge_and_detector_treat_each_path_identically(repo_of, path):
    """Same single-file repo, same technology: the judge counts it iff the detector reports
    it, and both agree with the shared predicate."""
    repo = repo_of({"app/ok.py": PLAIN, path: "import twilio\n"})
    judged = judge(repo, "forbid", {"forbid": ["twilio"]}).status == "VIOLATED"
    scan = detect_undocumented(repo, decisions=[])
    techs = {f.technology for f in [*scan.findings, *scan.could_not_verify]}
    assert judged == ("twilio" in techs) == (not is_vendored(path)), path


def test_snapshot_still_lists_vendored_files_but_evidence_does_not(repo_of):
    """Vendored files stay in the snapshot (the index is unchanged); only evidence drops them."""
    repo = repo_of({"app/a.py": PLAIN, "vendor/x.py": REQ})
    assert "vendor/x.py" in load_snapshot(repo).files
