"""L-026: regression tests for the judge defects found by Sonnet's L-025 system test.

Each test names its defect (D-L025-n, see DEFECTS in tests/test_l025_system.py). The
rule is the project's: precision over recall, fail closed (UNKNOWN), never a false
VIOLATED or HOLDING, and every cited item still passes G2/G3.
No network, no API key: the LLM path uses the offline provider with a scripted reply.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from functools import cache
from pathlib import Path

import pytest

from driftwarden.claims import match_sentence
from driftwarden.grounding.verify import verify_dependency
from driftwarden.index.manifests import parse_manifest
from driftwarden.judge import Judge, verify_evidence
from driftwarden.judge.catalog import literal_technology
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.models import WORKTREE, Claim, Provenance, Verdict

F_ = "import os\n\nVALUE = os.sep\n"


@cache
def fs_case_sensitive() -> bool:
    """True when the filesystem holding test repositories keeps ``Payments/`` and
    ``payments/`` apart (Linux); False on case-insensitive ones (default macOS APFS,
    Windows NTFS), where a case-twin fixture collapses into one directory."""
    with tempfile.TemporaryDirectory(prefix="driftwarden-case-") as tmp:
        (Path(tmp) / "Probe").mkdir()
        try:
            (Path(tmp) / "probe").mkdir()
        except FileExistsError:
            return False
        return len(list(Path(tmp).iterdir())) == 2


needs_case_sensitive_fs = pytest.mark.skipif(
    not fs_case_sensitive(),
    reason="case-insensitive filesystem (e.g. macOS): Payments/ and payments/ cannot both "
    "exist on disk, so the twin fixture collapses; the same fail-closed path is covered "
    "on every platform by the *_listed_twin test, which injects the twin into the "
    "snapshot's directory listing",
)
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
        _git(repo, "add", "-A")
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


def from_sentence(sentence: str) -> list[Claim]:
    return [
        Claim(
            id=f"T.c{i}",
            kind=m.kind,
            subject=m.subject,
            rule=m.rule,
            source=Provenance(
                path="docs/adr/0001-x.md", line_start=1, line_end=1, commit=WORKTREE, quote=sentence
            ),
            decision_id="T",
            origin="rule",
            pattern=m.pattern,
        )
        for i, m in enumerate(match_sentence(sentence), 1)
    ]


def offline(repo: Path, c: Claim) -> Verdict:
    return Judge(repo, mode="offline").judge(c)


def grounded(repo: Path, v: Verdict) -> None:
    assert v.grounding == "VERIFIED", v.reasons
    for ev in v.evidence:
        assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=v.commit))


# ------------------------------------------------------------------ D1: case of bare targets


@pytest.mark.parametrize("target", ["Payments", "PAYMENTS", "payments"])
def test_d1_bare_directory_target_ignores_case(make_repo, target):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": "from payments import core\n", "billing/b.py": F_}
    )
    v = offline(repo, claim("boundary", {"target": [target], "allowed_in": ["billing/"]}))
    assert v.status == "VIOLATED", v.rationale
    assert v.evidence[0].ref.path == "app/a.py"
    grounded(repo, v)


def test_d1_sentence_initial_target_from_the_rule_library(make_repo):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_}
    )
    (c,) = from_sentence("Payments may be imported only from billing/.")
    assert c.rule["target"] == ["Payments"]
    assert offline(repo, c).status == "VIOLATED"
    clean = make_repo(
        {"payments/core.py": F_, "app/a.py": F_, "billing/b.py": "import payments.core\n"}
    )
    assert offline(clean, c).status == "HOLDING"


def test_d1_capitalised_allowed_path_is_the_existing_directory(make_repo):
    repo = make_repo({"adapters/s3.py": "import boto3\n", "app/a.py": F_})
    v = offline(repo, claim("boundary", {"target": ["boto3"], "allowed_in": ["Adapters/"]}))
    assert v.status == "HOLDING", v.rationale


def test_d1_two_spellings_of_the_target_fail_closed(make_repo):
    repo = make_repo(
        {
            "Payments/x.py": F_,
            "lib/payments/core.py": F_,
            "app/a.py": F_,
            "billing/b.py": F_,
        }
    )
    v = offline(repo, claim("boundary", {"target": ["PAYMENTS"], "allowed_in": ["billing/"]}))
    assert v.status == "UNKNOWN" and "differ only in case" in v.rationale


# ------------------------------------------------------------------ D3 / D11: Terraform literals


def test_d3_provider_block_without_source_is_hashicorp(make_repo):
    repo = make_repo({"infra/main.tf": 'provider "random" {}\n'})
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status == "VIOLATED"
    assert v.evidence[0].dependency is not None
    grounded(repo, v)


def test_d3_no_implicit_source_when_the_module_declares_a_non_hashicorp_provider(make_repo):
    repo = make_repo(
        {
            "infra/versions.tf": "terraform {\n  required_providers {\n    random = {\n"
            '      source = "mycorp/random"\n    }\n  }\n}\n',
            "infra/main.tf": 'provider "random" {}\n',
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status != "VIOLATED", v.rationale


@pytest.mark.parametrize(
    "term", ["registry.terraform.io/hashicorp/random", "registry.opentofu.org/hashicorp/random"]
)
def test_d11_registry_host_in_the_term_is_canonicalised(make_repo, term):
    tf = (
        "terraform {\n  required_providers {\n    random = {\n"
        '      source = "hashicorp/random"\n    }\n  }\n}\n'
    )
    repo = make_repo({"infra/main.tf": tf})
    v = offline(repo, claim("forbid", {"forbid": [term]}))
    assert v.status == "VIOLATED"
    grounded(repo, v)


def test_d11_only_the_registry_host_is_stripped():
    assert literal_technology("registry.terraform.io/hashicorp/random").id == "hashicorp/random"
    assert literal_technology("hashicorp/random").id == "hashicorp/random"


# ------------------------------------------------------------------ D4: model vs fail-closed net


def _fake(status: str) -> OfflineProvider:
    def responder(request):
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


NET = {
    "between": (
        {"svc_a/a.py": "import kafka\n", "svc_b/b.py": "import pika\n"},
        "only",
        {"only": ["Kafka"], "between": "Services"},
    ),
    "call": (
        {"app/a.py": REQ, "adapters/h.py": REQ},
        "boundary",
        {"target": ["requests"], "allowed_in": ["adapters/"], "action": "call"},
    ),
    "forbid-access": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "action": "access"}),
    "unless": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "unless": "in tests"}),
    "actor": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "actor": ["Handlers"]}),
    "purpose": (
        {"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"},
        "only",
        {"only": ["Redis"], "category": "session storage"},
    ),
}


@pytest.mark.parametrize("name", sorted(NET))
@pytest.mark.parametrize("model_status", ["VIOLATED", "HOLDING", "DRIFTING"])
def test_d4_model_cannot_decide_a_fail_closed_unknown(make_repo, name, model_status):
    files, kind, rule = NET[name]
    repo = make_repo(files)
    c = claim(kind, rule)
    assert offline(repo, c).status == "UNKNOWN"
    v = Judge(repo, mode="llm", provider=_fake(model_status)).judge(c)
    assert v.status == "UNKNOWN", (v.status, v.rationale)
    assert v.proposed_status == model_status
    assert "failed closed" in v.rationale
    grounded(repo, v)


def test_d4_model_still_decides_claims_the_rules_cannot_map(make_repo):
    """Not over-blocked: a free-form claim has no fail-closed qualifier; a cited,
    verified model verdict is accepted (origin llm)."""
    repo = make_repo({"app/a.py": REQ})
    c = Claim(
        id="T.c1",
        kind="free",
        subject="x",
        rule={"text": "No outbound HTTP from app code."},
        source=Provenance(
            path="docs/adr/0001-x.md", line_start=1, line_end=1, commit=WORKTREE, quote="x"
        ),
        decision_id="T",
        origin="rule",
    )
    v = Judge(repo, mode="llm", provider=_fake("VIOLATED")).judge(c)
    assert v.origin == "llm"
    if v.evidence:  # a keyword candidate was offered and cited
        assert v.status == "VIOLATED"
        grounded(repo, v)


# ------------------------------------------------------------------ D5: generic subject "services"


def test_d5_services_with_a_services_directory_needs_both_readings_to_agree(make_repo):
    (c,) = from_sentence("Services must not import requests.")
    inside = make_repo({"services/a.py": REQ, "libs/b.py": F_})
    assert offline(inside, c).status == "VIOLATED"
    libs_only = make_repo({"services/a.py": F_, "libs/b.py": REQ})
    v = offline(libs_only, c)
    assert v.status == "UNKNOWN" and "ambiguous" in v.rationale, v.rationale
    grounded(libs_only, v)
    clean = make_repo({"services/a.py": F_, "libs/b.py": F_})
    assert offline(clean, c).status == "HOLDING"


def test_d5_services_without_a_services_directory_is_the_whole_codebase(make_repo):
    (c,) = from_sentence("Services must not import requests.")
    repo = make_repo({"svc_a/a.py": F_, "libs/b.py": REQ})
    assert offline(repo, c).status == "VIOLATED"


def test_d5_require_on_services_is_never_held_by_other_code(make_repo):
    claims = from_sentence("All services must use structlog for logging.")
    repo = make_repo({"services/a.py": F_, "other/b.py": "import structlog\n"})
    assert all(offline(repo, c).status != "HOLDING" for c in claims)


# ------------------------------------------------------------------ D6: acting-subject verbs


@pytest.mark.parametrize(
    "sentence",
    [
        "Handlers never import requests.",
        "Handlers don't import requests.",
        "Handlers don’t import requests.",
        "Handlers won't import requests.",
        "Handlers shouldn't import requests.",
        "Handlers mustn't import requests.",
        "Handlers cannot import requests.",
        "Handlers can't import requests.",
    ],
)
def test_d6_adverb_and_contraction_subjects_are_actors(make_repo, sentence):
    claims = from_sentence(sentence)
    assert claims
    other_only = make_repo({"handlers/a.py": F_, "other/b.py": REQ})
    assert all(offline(other_only, c).status == "HOLDING" for c in claims)
    inside = make_repo({"handlers/a.py": REQ, "other/b.py": F_})
    assert any(offline(inside, c).status == "VIOLATED" for c in claims)


# ------------------------------------------------------------------ D7: purpose phrases


@pytest.mark.parametrize(
    "sentence",
    [
        "We use only Redis for session storage.",
        "PostgreSQL is the only relational datastore.",
        "Only Kafka may be used for service-to-service communication.",
    ],
)
def test_d7_unknown_purpose_never_widens_to_the_whole_category(make_repo, sentence):
    repo = make_repo(
        {
            "app/a.py": "import redis\nimport psycopg2\nimport kafka\n",
            "app/b.py": "import pymemcache\nimport pymongo\nimport pika\n",
        }
    )
    for c in from_sentence(sentence):
        v = offline(repo, c)
        assert v.status == "UNKNOWN" and "not a catalog category" in v.rationale, v.rationale


def test_d7_require_with_unknown_purpose_fails_closed(make_repo):
    repo = make_repo({"app/a.py": "import loguru\n"})
    c = claim("require", {"require": ["structlog"], "for": "audit logging"})
    v = offline(repo, c)
    assert v.status == "UNKNOWN" and "not a catalog category" in v.rationale


def test_d7_catalog_categories_stay_decisive(make_repo):
    repo = make_repo({"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"})
    (c,) = from_sentence("We use only Redis for caching.")
    v = offline(repo, c)
    assert v.status == "VIOLATED"
    grounded(repo, v)


# ------------------------------------------------------------------ D9: Terraform JSON

TF_JSON = """{
  "terraform": {
    "required_version": ">= 1.5",
    "required_providers": {
      "random": {"source": "hashicorp/random", "version": "~> 3.5"},
      "aws": "~> 5.0"
    }
  },
  "module": {
    "vpc": {
      "source": "terraform-aws-modules/vpc/aws",
      "version": "5.1.0"
    },
    "local": {"source": "./modules/x"}
  },
  "provider": {
    "google": {"project": "p"}
  }
}
"""


def test_d9_tf_json_is_parsed_like_hcl():
    refs = parse_manifest("infra/main.tf.json", TF_JSON).refs
    got = {(r.ecosystem, r.package, r.version_spec, r.line, r.scope) for r in refs}
    assert got == {
        ("terraform", "terraform", ">= 1.5", 3, "core"),
        ("terraform-provider", "hashicorp/random", "~> 3.5", 5, None),
        ("terraform-provider", "hashicorp/aws", "~> 5.0", 6, None),
        ("terraform-module", "terraform-aws-modules/vpc/aws", "5.1.0", 11, "module:vpc"),
        ("terraform-provider", "google", None, 17, "provider-block"),
    }


def test_d9_malformed_tf_json_is_an_error_not_a_crash():
    res = parse_manifest("main.tf.json", "{not json")
    assert res.errors and not res.refs


@pytest.mark.parametrize("term", ["hashicorp/random", "AWS", "terraform-aws-modules/vpc/aws"])
def test_d9_forbidden_provider_in_tf_json_is_violated_and_g3_verified(make_repo, term):
    repo = make_repo({"infra/main.tf.json": TF_JSON})
    v = offline(repo, claim("forbid", {"forbid": [term]}))
    assert v.status == "VIOLATED", v.rationale
    grounded(repo, v)
    dep = v.evidence[0].dependency
    assert dep is not None and verify_dependency(repo, dep).status == "VERIFIED"
    tampered = dep.model_copy(update={"line": (dep.line or 0) + 1})
    assert verify_dependency(repo, tampered).status != "VERIFIED"


# ------------------------------------------------------------------ D10: module-file targets


def test_d10_bare_target_naming_a_module_file(make_repo):
    repo = make_repo({"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_})
    c = claim("boundary", {"target": ["payments"], "allowed_in": ["billing/"]})
    v = offline(repo, c)
    assert v.status == "VIOLATED", v.rationale
    assert v.evidence[0].ref.path == "app/a.py"
    grounded(repo, v)
    inside = make_repo({"payments.py": F_, "app/a.py": F_, "billing/b.py": "import payments\n"})
    assert offline(inside, c).status == "HOLDING"


# ------------------------------------------------------------------ PR #20 review (Codex P2s)


@needs_case_sensitive_fs
def test_d1_case_twin_directories_stay_unknown_with_a_model(make_repo):
    """Payments/ + payments/, target PAYMENTS: the rules fail closed, and a model citing
    the verifiable `import payments.core` line must not turn that into a verdict."""
    repo = make_repo(
        {"Payments/x.py": F_, "payments/core.py": F_, "app/a.py": "import payments.core\n"}
    )
    c = claim("boundary", {"target": ["PAYMENTS"], "allowed_in": ["billing/"]})
    assert offline(repo, c).status == "UNKNOWN"
    for status in ("VIOLATED", "HOLDING"):
        v = Judge(repo, mode="llm", provider=_fake(status)).judge(c)
        assert v.status == "UNKNOWN", (status, v.rationale)
        assert v.proposed_status in (None, "UNKNOWN", status)


TF_RP_LOCAL = (
    "terraform {\n  required_providers {\n    random = {\n"
    '      source = "hashicorp/null"\n    }\n  }\n}\n'
)


@pytest.mark.parametrize("split", [False, True])
def test_d3_declared_local_name_is_never_the_implicit_source(make_repo, split):
    """`random = { source = "hashicorp/null" }` + `provider "random" {}` configures null."""
    files = (
        {"infra/versions.tf": TF_RP_LOCAL, "infra/main.tf": 'provider "random" {}\n'}
        if split
        else {"infra/main.tf": TF_RP_LOCAL + 'provider "random" {}\n'}
    )
    repo = make_repo(files)
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status == "HOLDING", v.rationale
    null = offline(repo, claim("forbid", {"forbid": ["hashicorp/null"]}))
    assert null.status == "VIOLATED"
    grounded(repo, null)


def test_d3_declared_local_name_in_tf_json(make_repo):
    repo = make_repo(
        {
            "infra/versions.tf.json": '{"terraform": {"required_providers": '
            '{"random": {"source": "hashicorp/null"}}}}\n',
            "infra/main.tf": 'provider "random" {}\n',
        }
    )
    assert offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]})).status == "HOLDING"


def test_d3_undeclared_local_name_next_to_other_declarations_is_implicit(make_repo):
    """Other required_providers (any source) do not hide an undeclared provider block."""
    repo = make_repo(
        {
            "infra/versions.tf": "terraform {\n  required_providers {\n    acme = {\n"
            '      source = "mycorp/acme"\n    }\n  }\n}\n',
            "infra/main.tf": 'provider "random" {}\n',
        }
    )
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status == "VIOLATED", v.rationale
    grounded(repo, v)
    dep = v.evidence[0].dependency
    assert dep is not None and dep.package == "random"
    assert verify_dependency(repo, dep).status == "VERIFIED"


def test_d3_unreadable_terraform_file_blocks_inference(make_repo):
    repo = make_repo(
        {"infra/versions.tf": "terraform {\n", "infra/main.tf": 'provider "random" {}\n'}
    )
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status != "VIOLATED"


def test_d1_listed_twin_stays_unknown_offline_and_with_a_model(make_repo, monkeypatch):
    """Platform-independent twin: the repository has payments/ only; the snapshot's
    directory listing also reports Payments/ (what a case-sensitive checkout shows).
    resolve_dir/_boundary must fail closed, and the model must not decide it."""
    from driftwarden.judge import evidence

    repo = make_repo({"payments/core.py": F_, "app/a.py": "import payments.core\n"})
    real = evidence.Snapshot.directories
    monkeypatch.setattr(evidence.Snapshot, "directories", lambda self: real(self) | {"Payments"})
    c = claim("boundary", {"target": ["PAYMENTS"], "allowed_in": ["billing/"]})
    v = offline(repo, c)
    assert v.status == "UNKNOWN" and "differ only in case" in v.rationale, v.rationale
    for status in ("VIOLATED", "HOLDING"):
        m = Judge(repo, mode="llm", provider=_fake(status)).judge(c)
        assert m.status == "UNKNOWN", (status, m.rationale)
    # control: the exact spelling still resolves and decides
    exact = offline(repo, claim("boundary", {"target": ["payments"], "allowed_in": ["billing/"]}))
    assert exact.status == "VIOLATED", exact.rationale


TF_JSON_ACME = '{"terraform": {"required_providers": {"acme": {"source": "mycorp/acme"}}}}\n'
ENCODED = {
    "utf-8-bom": TF_JSON_ACME.encode("utf-8-sig"),
    "crlf": TF_JSON_ACME.replace("\n", "\r\n").encode("utf-8"),
    "utf-16-bom": TF_JSON_ACME.encode("utf-16"),
}


@pytest.mark.parametrize("encoding", sorted(ENCODED))
def test_d3_encoded_tf_json_does_not_disable_implicit_inference(make_repo, encoding):
    """A .tf.json that parse_manifest reads (BOM / CRLF / UTF-16, normalised by
    _prepare) is not "unreadable" for the local-name lookup: `provider "random" {}`
    with no `random` declaration is still hashicorp/random (PR #20 review)."""
    repo = make_repo({"infra/main.tf": 'provider "random" {}\n'})
    (repo / "infra/versions.tf.json").write_bytes(ENCODED[encoding])
    _git(repo, "add", "infra/versions.tf.json")
    _git(repo, "commit", "-q", "-m", "encoded tf.json")
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/acme"]}))
    assert v.status == "HOLDING"  # the declaration is mycorp/acme, parsed through encoding
    acme = offline(repo, claim("forbid", {"forbid": ["mycorp/acme"]}))
    assert acme.status == "VIOLATED", acme.rationale
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status == "VIOLATED", v.rationale
    grounded(repo, v)
    dep = v.evidence[0].dependency
    assert dep is not None and dep.package == "random"
    assert verify_dependency(repo, dep).status == "VERIFIED"


def test_d3_garbage_tf_json_still_blocks_inference(make_repo):
    repo = make_repo({"infra/main.tf": 'provider "random" {}\n'})
    (repo / "infra/versions.tf.json").write_bytes(b"\xff\xfe\x00\x01\x02garbage{")
    _git(repo, "add", "infra/versions.tf.json")
    _git(repo, "commit", "-q", "-m", "garbage tf.json")
    v = offline(repo, claim("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status != "VIOLATED", v.rationale
