"""L-030: vendored / third-party code is not evidence (Sonnet's L-015 benchmark, D1).

A forbidden import or dependency found only under ``vendor/``, ``third_party/``,
``third-party/``, ``node_modules/``, ``external/`` ... was judged VIOLATED and was
cited as boundary evidence, while the undocumented detector already skipped those
trees. Both now use one predicate (``driftwarden.index.vendored.is_vendored``).

Semantics (documented in ``judge.evidence``): vendored-only is HOLDING with a
"not counted" note, never DRIFTING or VIOLATED; no verdict cites a vendored file.

No network, no API key: the LLM path uses the offline provider with a scripted reply.
The benchmark cases are rebuilt here as small fixtures (bench/ is not on main).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from driftwarden.config import Config
from driftwarden.index import vendored as vendored_mod
from driftwarden.index.vendored import VENDORED_DIRS, is_vendored
from driftwarden.judge import Judge, collect_evidence, load_snapshot, verify_evidence
from driftwarden.judge.judge import gate
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.models import WORKTREE, Claim, Evidence, Provenance, Verdict
from driftwarden.undocumented import detect as detect_mod
from driftwarden.undocumented import detect_undocumented

F_ = "import os\n\nVALUE = os.sep\n"
REQ = "import requests\n"


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def make_repo(tmp_path):
    n = [0]

    def build(files: dict[str, str]) -> Path:
        n[0] += 1
        repo = tmp_path / f"r{n[0]}"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "commit.gpgsign", "false")
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        _git(repo, "add", "-A", "-f")
        _git(repo, "commit", "-q", "-m", "c")
        return repo

    return build


def claim(kind: str, rule: dict, *, subject: str = "x", quote: str = "text") -> Claim:
    return Claim(
        id="T.c1",
        kind=kind,  # type: ignore[arg-type]
        subject=subject,
        rule=rule,
        source=Provenance(
            path="docs/adr/0001-x.md", line_start=1, line_end=1, commit=WORKTREE, quote=quote
        ),
        decision_id="T",
        origin="rule",
    )


def offline(repo: Path, c: Claim, config: Config | None = None) -> Verdict:
    return Judge(repo, mode="offline", config=config).judge(c)


def grounded(repo: Path, v: Verdict) -> None:
    assert v.grounding == "VERIFIED", v.reasons
    for ev in v.evidence:
        assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=v.commit))


def cited(v: Verdict) -> list[str]:
    return [e.ref.path for e in v.evidence]


def no_vendored_cite(v: Verdict) -> None:
    assert not any(is_vendored(p) for p in cited(v)), cited(v)


def noted(v: Verdict) -> bool:
    return any("vendored third-party code" in n for n in v.notes)


# ------------------------------------------------------------------ predicate


@pytest.mark.parametrize(
    "path",
    [
        "vendor/x.js",
        "vendor/sms-shim/index.js",
        "third_party/numpy_stub/__init__.py",
        "third-party/lib/a.go",
        "thirdparty/a.py",
        "node_modules/aws-sdk/index.js",
        "external/abseil/a.cc",
        "src/vendor/lib/a.py",
        "services/api/node_modules/x/package.json",
        "app/.venv/lib/site-packages/requests/__init__.py",
        "ios/Pods/Foo/a.swift",
        "vendors/a.php",
        "vendor/lib",  # a directory inside vendor/
    ],
)
def test_predicate_vendored(path):
    assert is_vendored(path)


@pytest.mark.parametrize(
    "path",
    [
        "vendor.py",
        "vendor",  # the vendored directory itself is not inside one
        "src/vendoring/a.py",
        "src/my_vendor/a.py",
        "external.py",
        "src/externals/a.py",
        "k8s/pods/web.yaml",  # case is exact: pods/ is not CocoaPods' Pods/
        "app/a.py",
        "tests/test_vendor.py",
        "",
    ],
)
def test_predicate_not_vendored(path):
    assert not is_vendored(path)


def test_ticket_directories_are_all_recognised():
    for d in ("vendor", "third_party", "third-party", "node_modules", "external"):
        assert d in VENDORED_DIRS
        assert is_vendored(f"{d}/pkg/file.py")


def test_one_predicate_shared_by_judge_and_detector():
    from driftwarden.judge import evidence as evidence_mod

    assert detect_mod.is_vendored is vendored_mod.is_vendored
    assert evidence_mod.is_vendored is vendored_mod.is_vendored
    assert detect_mod.VENDORED_DIRS is vendored_mod.VENDORED_DIRS


# ------------------------------------------------------------------ dependency claims


PKG = '{\n  "name": "app",\n  "dependencies": {\n    "express": "^4.18.0"\n  }\n}\n'
PKG_TWILIO = '{\n  "name": "shim",\n  "dependencies": {\n    "twilio": "^4.0.0"\n  }\n}\n'


def test_dependency_vendored_only_is_holding_with_a_note(make_repo):
    repo = make_repo(
        {
            "package.json": PKG,
            "vendor/sms-shim/package.json": PKG_TWILIO,
            "third_party/py/requirements.txt": "requests==2.31.0\n",
        }
    )
    for term in ("twilio", "requests"):
        v = offline(repo, claim("forbid", {"forbid": [term]}))
        assert v.status == "HOLDING", (term, v.rationale)
        assert v.evidence == []
        assert noted(v), v.notes
        assert "vendored occurrence(s) not counted" in v.rationale
        grounded(repo, v)


def test_dependency_vendored_plus_real_is_violated_citing_real_only(make_repo):
    repo = make_repo(
        {
            "requirements.txt": "requests==2.31.0\n",
            "vendor/py/requirements.txt": "requests==2.0.0\n",
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "VIOLATED", v.rationale
    assert cited(v) == ["requirements.txt"]
    assert v.evidence[0].dependency is not None
    assert noted(v)
    grounded(repo, v)


def test_dev_dependency_plus_vendored_is_drifting_citing_dev_only(make_repo):
    """The existing non-production rule is unchanged: the team's own dev manifest
    still makes the claim DRIFTING; the vendored copy is not part of it."""
    repo = make_repo(
        {
            "requirements-dev.txt": "requests==2.31.0\n",
            "third_party/x/requirements.txt": "requests==2.0.0\n",
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "DRIFTING", v.rationale
    assert cited(v) == ["requirements-dev.txt"]
    grounded(repo, v)


# ------------------------------------------------------------------ import claims


@pytest.mark.parametrize("vdir", ["vendor", "third_party", "third-party", "external", "src/vendor"])
def test_import_vendored_only_is_holding(make_repo, vdir):
    repo = make_repo({"app/a.py": F_, f"{vdir}/lib/a.py": REQ})
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "HOLDING", v.rationale
    assert v.evidence == [] and noted(v)
    assert any(f"{vdir}/lib/a.py:1" in n for n in v.notes), v.notes


def test_import_vendored_plus_real_is_violated_citing_real_only(make_repo):
    repo = make_repo({"app/a.py": REQ, "vendor/lib/a.py": REQ, "third_party/b.py": REQ})
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "VIOLATED"
    assert cited(v) == ["app/a.py"]
    grounded(repo, v)


def test_action_import_vendored_only_is_holding(make_repo):
    repo = make_repo({"app/a.py": F_, "vendor/lib/a.py": REQ})
    v = offline(repo, claim("forbid", {"forbid": ["requests"], "action": "import"}))
    assert v.status == "HOLDING", v.rationale


def test_test_import_plus_vendored_is_drifting_citing_test_only(make_repo):
    repo = make_repo({"app/a.py": F_, "tests/test_a.py": REQ, "vendor/lib/a.py": REQ})
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "DRIFTING"
    assert cited(v) == ["tests/test_a.py"]


def test_only_and_require_ignore_vendored_alternatives(make_repo):
    repo = make_repo({"app/db.py": "import psycopg2\n", "vendor/m/db.py": "import pymongo\n"})
    v = offline(repo, claim("only", {"only": ["PostgreSQL"], "category": "datastore"}))
    assert v.status == "HOLDING", v.rationale
    no_vendored_cite(v)
    r = offline(repo, claim("require", {"require": ["PostgreSQL"], "for": "datastore"}))
    assert r.status == "HOLDING", r.rationale
    no_vendored_cite(r)
    only_vendored = make_repo({"app/a.py": F_, "vendor/m/db.py": "import pymongo\n"})
    u = offline(only_vendored, claim("require", {"require": ["PostgreSQL"], "for": "datastore"}))
    assert u.status == "UNKNOWN", u.rationale  # absence, nothing citable: not VIOLATED


# ------------------------------------------------------------------ boundary claims


def test_boundary_technology_vendored_only_outside_is_holding(make_repo):
    repo = make_repo({"adapters/s3.py": "import boto3\n", "vendor/aws/shim.py": "import boto3\n"})
    v = offline(repo, claim("boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]}))
    assert v.status == "HOLDING", v.rationale
    no_vendored_cite(v)
    assert noted(v)


def test_boundary_technology_vendored_plus_real_cites_real_only(make_repo):
    repo = make_repo(
        {
            "adapters/s3.py": "import boto3\n",
            "app/upload.py": "import boto3\n",
            "vendor/aws/shim.py": "import boto3\n",
        }
    )
    v = offline(repo, claim("boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]}))
    assert v.status == "VIOLATED"
    assert cited(v) == ["app/upload.py"]
    grounded(repo, v)


def test_boundary_local_target_import_from_vendored_code_is_no_crossing(make_repo):
    repo = make_repo(
        {
            "payments/__init__.py": "",
            "payments/core.py": F_,
            "billing/b.py": "from payments import core\n",
            "vendor/plugin/p.py": "from payments import core\n",
        }
    )
    v = offline(repo, claim("boundary", {"target": ["payments/"], "allowed_in": ["billing/"]}))
    assert v.status == "HOLDING", v.rationale
    no_vendored_cite(v)
    assert noted(v)


def test_boundary_local_target_vendored_plus_real_cites_real_only(make_repo):
    repo = make_repo(
        {
            "payments/__init__.py": "",
            "payments/core.py": F_,
            "billing/b.py": "from payments import core\n",
            "app/a.py": "from payments import core\n",
            "third_party/plugin/p.py": "from payments import core\n",
        }
    )
    v = offline(repo, claim("boundary", {"target": ["payments/"], "allowed_in": ["billing/"]}))
    assert v.status == "VIOLATED"
    assert cited(v) == ["app/a.py"]
    grounded(repo, v)


def test_boundary_vendored_copy_of_the_target_is_not_the_target(make_repo):
    """A vendored package that happens to share the target's name is not the
    repository's own code: "payments" names payments/ only, not ambiguously both."""
    repo = make_repo(
        {
            "payments/__init__.py": "",
            "payments/core.py": F_,
            "vendor/lib/payments/__init__.py": "",
            "billing/b.py": "from payments import core\n",
            "app/a.py": "from payments import core\n",
        }
    )
    v = offline(repo, claim("boundary", {"target": ["payments"], "allowed_in": ["billing/"]}))
    assert v.status == "VIOLATED", v.rationale
    assert cited(v) == ["app/a.py"]


# ------------------------------------------------------------------ infra claims


COMPOSE_MONGO = "services:\n  db:\n    image: mongo:6\n"
COMPOSE_PG = "services:\n  db:\n    image: postgres:16\n"


def test_infra_vendored_only_is_holding(make_repo):
    repo = make_repo(
        {
            "docker-compose.yml": COMPOSE_PG,
            "vendor/mongo-kit/docker-compose.yml": COMPOSE_MONGO,
            "third_party/mongo/Dockerfile": "FROM mongo:6\n",
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["MongoDB"]}))
    assert v.status == "HOLDING", v.rationale
    assert noted(v)


def test_infra_vendored_plus_real_is_violated_citing_real_only(make_repo):
    repo = make_repo(
        {
            "docker-compose.yml": COMPOSE_MONGO,
            "vendor/mongo-kit/docker-compose.yml": COMPOSE_MONGO,
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["MongoDB"]}))
    assert v.status == "VIOLATED"
    assert cited(v) == ["docker-compose.yml"]
    assert v.evidence[0].kind == "infra"
    grounded(repo, v)


# ------------------------------------------------------------------ the four benchmark cases


def _nodeapi(make_repo) -> Path:
    return make_repo(
        {
            "package.json": (
                '{\n  "name": "nodeapi",\n  "dependencies": {\n    "express": "^4.18.0",\n'
                '    "aws-sdk": "^2.1500.0"\n  }\n}\n'
            ),
            "src/server.ts": "import express from 'express';\n",
            "src/adapters/s3.ts": "import AWS from 'aws-sdk';\nexport const s3 = new AWS.S3();\n",
            "src/routes/upload.ts": "import AWS from 'aws-sdk';\nexport const up = AWS;\n",
            "vendor/aws-sdk-shim/index.js": "module.exports = require('aws-sdk');\n",
            "vendor/sms-shim/index.js": "module.exports = require('twilio');\n",
        }
    )


def _datahub(make_repo) -> Path:
    return make_repo(
        {
            "pyproject.toml": '[project]\nname = "datahub"\ndependencies = ["fastapi>=0.110"]\n',
            "src/datahub/web.py": "import fastapi\n",
            "third_party/numpy_stub/__init__.py": "import numpy\n",
        }
    )


def _fleetgate(make_repo) -> Path:
    return make_repo(
        {
            "go.mod": (
                "module example.com/fleetgate\n\ngo 1.22\n\n"
                "require github.com/aws/aws-sdk-go v1.50.0\n"
            ),
            "internal/cloud/s3.go": (
                'package cloud\n\nimport (\n\t"github.com/aws/aws-sdk-go/aws"\n)\n\n'
                "var _ = aws.String\n"
            ),
            "cmd/fleetgate/export.go": (
                'package main\n\nimport (\n\t"github.com/aws/aws-sdk-go/aws"\n)\n\n'
                "var _ = aws.String\n"
            ),
            "third_party/awsmock/mock.go": (
                'package awsmock\n\nimport "github.com/aws/aws-sdk-go/aws"\n\nvar _ = aws.String\n'
            ),
        }
    )


def test_bench_nodeapi_adr0016_vendored_twilio_is_not_violated(make_repo):
    repo = _nodeapi(make_repo)
    v = offline(repo, claim("forbid", {"forbid": ["Twilio"]}, quote="We will not use Twilio."))
    assert v.status == "HOLDING", v.rationale
    assert noted(v) and any("vendor/sms-shim/index.js:1" in n for n in v.notes)


def test_bench_datahub_adr0008_vendored_numpy_is_not_violated(make_repo):
    repo = _datahub(make_repo)
    v = offline(repo, claim("forbid", {"forbid": ["numpy"]}, quote="We will not use NumPy."))
    assert v.status == "HOLDING", v.rationale
    assert any("third_party/numpy_stub/__init__.py:1" in n for n in v.notes)


def test_bench_nodeapi_adr0005_stays_violated_without_vendored_cite(make_repo):
    repo = _nodeapi(make_repo)
    c = claim("boundary", {"target": ["cloud SDK"], "allowed_in": ["src/adapters/"]})
    v = offline(repo, c)
    assert v.status == "VIOLATED", v.rationale
    assert cited(v) == ["src/routes/upload.ts"]
    no_vendored_cite(v)
    grounded(repo, v)


def test_bench_fleetgate_adr0004_stays_violated_without_vendored_cite(make_repo):
    repo = _fleetgate(make_repo)
    c = claim("boundary", {"target": ["cloud SDKs"], "allowed_in": ["internal/cloud/"]})
    v = offline(repo, c)
    assert v.status == "VIOLATED", v.rationale
    assert cited(v) == ["cmd/fleetgate/export.go"]
    assert v.evidence[0].ref.line_start == 4
    no_vendored_cite(v)
    grounded(repo, v)


def test_bench_cases_at_worktree_too(make_repo):
    """WORKTREE snapshots select files the same way, so they agree."""
    repo = _nodeapi(make_repo)
    j = Judge(repo, commit=WORKTREE, mode="offline")
    assert j.judge(claim("forbid", {"forbid": ["Twilio"]})).status == "HOLDING"
    b = j.judge(claim("boundary", {"target": ["cloud SDK"], "allowed_in": ["src/adapters/"]}))
    assert b.status == "VIOLATED" and cited(b) == ["src/routes/upload.ts"]


# ------------------------------------------------------------------ detector agrees


def test_judge_and_detector_agree_on_vendored_code(make_repo):
    repo = make_repo(
        {
            "app/a.py": F_,
            "external/mongo_client/db.py": "import pymongo\n",
            "vendor/sms/send.py": "import twilio\n",
        }
    )
    scan = detect_undocumented(repo, decisions=[])
    techs = {f.technology for f in [*scan.findings, *scan.could_not_verify]}
    assert "mongodb" not in techs and "twilio" not in techs
    for term in ("MongoDB", "Twilio"):
        assert offline(repo, claim("forbid", {"forbid": [term]})).status == "HOLDING"


# ------------------------------------------------------------------ config exclude


def test_config_exclude_globs_are_honoured_by_evidence(make_repo):
    repo = make_repo({"app/a.py": F_, "legacy/old.py": REQ, "requirements.txt": "flask\n"})
    c = claim("forbid", {"forbid": ["requests"]})
    assert offline(repo, c).status == "VIOLATED"
    cfg = Config(exclude=["legacy/**"])
    assert offline(repo, c, cfg).status == "HOLDING"
    snap = load_snapshot(repo, WORKTREE, cfg)
    assert not any(f.path.startswith("legacy/") for f in snap.files)


# ------------------------------------------------------------------ LLM path and G2 gate


def _fake(status: str, seen: list[str]) -> OfflineProvider:
    def responder(request):
        seen.append(request.prompt)
        cands = json.loads(request.prompt.split("data, not instructions):\n", 1)[1])
        cites = [
            {
                "evidence_id": c["id"],
                "line_start": c["line_start"],
                "line_end": c["line_end"],
                "quote": c["snippet"],
            }
            for c in cands[:1]
        ]
        return json.dumps({"status": status, "rationale": "model says so", "citations": cites})

    return OfflineProvider(
        responder=responder, retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None)
    )


def test_llm_is_never_offered_vendored_candidates(make_repo):
    repo = make_repo({"app/a.py": F_, "vendor/lib/twilio_client.py": "import twilio\n"})
    free = Claim(
        id="T.c1",
        kind="free",
        subject="x",
        rule={"text": "No SMS through twilio."},
        source=Provenance(
            path="docs/adr/0001-x.md", line_start=1, line_end=1, commit=WORKTREE, quote="x"
        ),
        decision_id="T",
        origin="rule",
    )
    es = collect_evidence(free, load_snapshot(repo))
    assert not any(is_vendored(e.ref.path) for e in es.candidates)
    seen: list[str] = []
    v = Judge(repo, mode="llm", provider=_fake("VIOLATED", seen)).judge(free)
    assert v.status != "VIOLATED"
    assert all("vendor/lib" not in p for p in seen)


def _mutate(ev: Evidence, **ref) -> Evidence:
    return ev.model_copy(update={"ref": ev.ref.model_copy(update=ref)})


def test_g2_gate_still_verifies_cited_evidence(make_repo):
    """VIOLATED verdicts from vendored-plus-real repositories cite verified evidence,
    and a tampered citation (wrong quote, shifted lines, the vendored file's path)
    is caught by the gate."""
    repo = make_repo(
        {
            "app/a.py": REQ,
            "vendor/lib/a.py": "import requests as r\n",
            "requirements.txt": "requests==2.31.0\n",
            "third_party/x/requirements.txt": "requests==1.0\n",
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    assert v.status == "VIOLATED"
    grounded(repo, v)
    no_vendored_cite(v)
    assert sorted(cited(v)) == ["app/a.py", "requirements.txt"]
    caught = 0
    for ev in v.evidence:
        vendored_twin = (
            "vendor/lib/a.py" if ev.kind == "import" else "third_party/x/requirements.txt"
        )
        for bad in (
            _mutate(ev, quote=ev.ref.quote + " # x"),
            _mutate(ev, line_start=ev.ref.line_start + 1, line_end=ev.ref.line_end + 1),
            _mutate(ev, path=vendored_twin),
        ):
            data = v.model_dump()
            data["evidence"] = [bad]
            g = gate(Verdict.model_validate(data), repo)
            assert g.status == "UNKNOWN" and g.grounding == "MISMATCH", bad
            caught += 1
    assert caught == 3 * len(v.evidence)


def test_gate_refuses_a_verbatim_citation_of_vendored_code(make_repo):
    """Defence in depth: even a quote that is verbatim at the cited vendored lines
    (``import requests`` inside ``import requests as r``) is not a fact about this
    repository's code; the gate turns it into Could not verify."""
    repo = make_repo({"app/a.py": REQ, "vendor/lib/a.py": "import requests as r\n"})
    v = offline(repo, claim("forbid", {"forbid": ["requests"]}))
    (ev,) = v.evidence
    bad = _mutate(ev, path="vendor/lib/a.py")
    assert all(r.status == "VERIFIED" for r in verify_evidence(repo, bad, commit=v.commit))
    data = v.model_dump()
    data["evidence"] = [bad]
    g = gate(Verdict.model_validate(data), repo)
    assert g.status == "UNKNOWN" and g.grounding == "MISMATCH"
    assert any("vendored third-party code" in r for r in g.reasons)
    assert g.proposed_status == "VIOLATED"
