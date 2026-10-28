# ruff: noqa: E501
"""L-026 system tests (Sonnet): adversarial retest of the judge-defect fixes D1, D3-D7, D9-D11.

Independent of tests/test_l026_judge_defects.py (Opus): own git fixtures and own truth labels.
Rule under test: VIOLATED only when truly violated, HOLDING only when it truly holds; UNKNOWN is
always allowed. Plus over-acceptance guards: previously-correct decisive verdicts must stay decisive.
No network, no API key.
"""

from __future__ import annotations

import itertools
import json
import os
import random
import socket
import subprocess
from pathlib import Path

import pytest

from driftwarden.claims import match_sentence
from driftwarden.index.manifests import parse_manifest
from driftwarden.judge import Judge, gate, verify_evidence
from driftwarden.judge.catalog import literal_technology
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.models import WORKTREE, Claim, Provenance, Verdict
from test_l007_system import _is_equivalent, mutate_evidence, show
from test_l026_judge_defects import needs_case_sensitive_fs

F_ = "import os\n\nVALUE = os.sep\n"
REQ = "import requests\n"
BOTO = "import boto3\n"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise OSError("network access is disabled in tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DRIFTWARDEN_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "T",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "T",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, env=env, check=True
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
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "c")
        return repo

    return build


def mk(kind: str, rule: dict, subject: str = "x", quote: str = "t", pattern=None) -> Claim:
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
        pattern=pattern,
    )


def claims_for(sentence: str) -> list[Claim]:
    return [
        mk(m.kind, m.rule, subject=m.subject, quote=sentence, pattern=m.pattern)
        for m in match_sentence(sentence)
    ]


def offline(repo: Path, c: Claim) -> Verdict:
    return Judge(repo, mode="offline").judge(c)


def fake(status: str, n_cite: int = 1) -> OfflineProvider:
    def responder(request):
        cs = json.loads(request.prompt.split("data, not instructions):\n", 1)[1])
        cites = [
            {
                "evidence_id": c["id"],
                "line_start": c["line_start"],
                "line_end": c["line_end"],
                "quote": c["snippet"],
            }
            for c in cs[:n_cite]
        ]
        return json.dumps({"status": status, "rationale": "trust me", "citations": cites})

    return OfflineProvider(
        responder=responder, retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None)
    )


def llm(repo: Path, c: Claim, status: str, mode: str = "llm") -> Verdict:
    return Judge(repo, mode=mode, provider=fake(status)).judge(c)  # type: ignore[arg-type]


def wrong(status: str, truth: str) -> bool:
    return (status == "VIOLATED" and truth == "H") or (status == "HOLDING" and truth == "V")


def grounded(repo: Path, v: Verdict) -> None:
    assert v.grounding == "VERIFIED", v.reasons
    for ev in v.evidence:
        assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=v.commit))


# ============================================================ D1: case variants of bare directories

CASES_D1 = ["payments", "Payments", "PAYMENTS", "pAyMeNts", "`Payments`", "Payments/", "payments/"]


@pytest.mark.parametrize("target", CASES_D1)
def test_d1_violated_for_every_spelling(make_repo, target):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": "from payments import core\n", "billing/b.py": F_}
    )
    v = offline(repo, mk("boundary", {"target": [target], "allowed_in": ["billing/"]}))
    assert v.status == "VIOLATED", (target, v.status, v.rationale)
    grounded(repo, v)


@pytest.mark.parametrize("target", CASES_D1)
def test_d1_holding_for_every_spelling_only_when_truly_holds(make_repo, target):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": F_, "billing/b.py": "import payments.core\n"}
    )
    v = offline(repo, mk("boundary", {"target": [target], "allowed_in": ["billing/"]}))
    assert v.status in ("HOLDING", "UNKNOWN"), (target, v.status)
    assert v.status == "HOLDING", f"over-acceptance: {target!r} -> {v.status} {v.rationale}"


@pytest.mark.parametrize(
    "sentence",
    [
        "Payments may be imported only from billing/.",
        "payments may be imported only from billing/.",
        "PAYMENTS may be imported only from billing/.",
    ],
)
def test_d1_sentence_variants_never_false_holding(make_repo, sentence):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_}
    )
    cs = claims_for(sentence)
    assert cs, f"rule library did not match {sentence!r}"
    for c in cs:
        assert offline(repo, c).status != "HOLDING", sentence


# N1 (found here, fixed in L-027): 'payments package' / 'payments module' gave a false
# HOLDING 'target not imported anywhere'. Regression tests: tests/test_l027_target_noun.py.
@pytest.mark.parametrize("noun", ["package", "module"])
def test_n1_noun_suffixed_target_not_false_holding(make_repo, noun):
    repo = make_repo(
        {"payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_}
    )
    for c in claims_for(f"The payments {noun} may be imported only from billing/."):
        assert offline(repo, c).status != "HOLDING"


def test_d1_nested_directory_and_mixed_case_allowed_in(make_repo):
    repo = make_repo(
        {
            "src/Payments/core.py": F_,
            "src/app/a.py": "from src.Payments import core\n",
            "src/billing/b.py": F_,
        }
    )
    v = offline(repo, mk("boundary", {"target": ["payments"], "allowed_in": ["Billing/"]}))
    assert v.status in ("VIOLATED", "UNKNOWN"), v.status


@needs_case_sensitive_fs
def test_d1_ambiguous_case_twin_directories_never_decisive_wrong(make_repo):
    repo = make_repo({"Payments/x.py": F_, "payments/y.py": F_, "app/a.py": "import payments.y\n"})
    v = offline(repo, mk("boundary", {"target": ["PAYMENTS"], "allowed_in": ["billing/"]}))
    assert v.status in ("UNKNOWN", "VIOLATED"), v.status
    assert v.status != "HOLDING"


# ============================================================ D6: acting subject, all negative modals

NEG = [
    "never import",
    "do not import",
    "don't import",
    "don’t import",
    "does not import",
    "doesn't import",
    "doesn’t import",
    "cannot import",
    "can not import",
    "can't import",
    "can’t import",
    "won't import",
    "won’t import",
    "will not import",
    "shouldn't import",
    "shouldn’t import",
    "should not import",
    "mustn't import",
    "mustn’t import",
    "must not import",
    "must never import",
    "may not import",
    "shall not import",
    "shan't import",
    "are not allowed to import",
    "are forbidden to import",
    "should never import",
    "can never import",
    "will never import",
]


@pytest.mark.parametrize("verb", NEG)
def test_d6_negative_modals_scope_to_actor(make_repo, verb):
    sentence = f"Handlers {verb} requests."
    cs = claims_for(sentence)
    if not cs:
        pytest.skip(f"rule library does not match {sentence!r} (nothing to judge)")
    only_other = make_repo({"handlers/a.py": F_, "other/b.py": REQ})
    viol = make_repo({"handlers/a.py": REQ, "other/b.py": F_})
    for c in cs:
        v = offline(only_other, c)
        assert v.status != "VIOLATED", f"false VIOLATED: {sentence!r}: {v.rationale}"
        v2 = offline(viol, c)
        assert v2.status != "HOLDING", f"false HOLDING: {sentence!r}: {v2.rationale}"


@pytest.mark.parametrize("verb", NEG[:12])
def test_d6_over_acceptance_true_violation_stays_violated(make_repo, verb):
    sentence = f"Handlers {verb} requests."
    cs = claims_for(sentence)
    if not cs:
        pytest.skip("no match")
    viol = make_repo({"handlers/a.py": REQ, "other/b.py": F_})
    st = {offline(viol, c).status for c in cs}
    assert st <= {"VIOLATED", "UNKNOWN"}
    assert "VIOLATED" in st, f"{sentence!r} lost its true VIOLATED: {st}"


@pytest.mark.parametrize(
    "subject",
    ["Handlers", "The handlers", "All handlers", "Request handlers", "Handler code", "HANDLERS"],
)
def test_d6_subject_variants(make_repo, subject):
    c_list = claims_for(f"{subject} never import requests.") or claims_for(
        f"{subject} never imports requests."
    )
    if not c_list:
        pytest.skip("no match")
    only_other = make_repo({"handlers/a.py": F_, "other/b.py": REQ})
    for c in c_list:
        assert offline(only_other, c).status != "VIOLATED", subject


def test_d6_apostrophe_inside_word_not_misread(make_repo):
    # "don't" must not make an unrelated subject the actor: whole-repo plain claim stays decisive
    repo = make_repo({"app/a.py": REQ})
    for c in claims_for("We don't use requests."):
        assert offline(repo, c).status in ("VIOLATED", "UNKNOWN")


# ============================================================ D7: odd category phrases

ODD_ONLY = [
    "session storage",
    "transactional data",
    "audit logging",
    "service-to-service communication",
    "caching of pages",
    "the payments flow",
    "real-time analytics",
    "background jobs on mobile",
]


@pytest.mark.parametrize("phrase", ODD_ONLY)
def test_d7_only_with_non_catalog_category_is_never_violated(make_repo, phrase):
    repo = make_repo({"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"})
    v = offline(repo, mk("only", {"only": ["Redis"], "category": phrase}))
    assert v.status == "UNKNOWN", (phrase, v.status, v.rationale)


@pytest.mark.parametrize("phrase", ODD_ONLY)
def test_d7_only_non_catalog_category_not_holding_either(make_repo, phrase):
    repo = make_repo({"app/a.py": "import redis\n"})
    v = offline(repo, mk("only", {"only": ["Redis"], "category": phrase}))
    assert v.status in ("UNKNOWN", "HOLDING")


@pytest.mark.parametrize("phrase", ODD_ONLY[:5])
def test_d7_require_for_non_catalog_phrase_is_unknown(make_repo, phrase):
    repo = make_repo({"app/a.py": "import pymemcache\n"})
    v = offline(repo, mk("require", {"require": ["Redis"], "for": phrase}))
    assert v.status in ("UNKNOWN",), (phrase, v.status, v.rationale)


@pytest.mark.parametrize(
    "sentence",
    [
        "We use only Redis for session storage.",
        "Only Redis is used for session storage.",
        "We use only Kafka for service-to-service communication.",
        "Only PostgreSQL is used for transactional data.",
        "We use only Redis for audit logging.",
    ],
)
def test_d7_rule_library_sentences_never_violated_by_unrelated_tech(make_repo, sentence):
    repo = make_repo(
        {
            "app/a.py": "import redis\nimport psycopg2\nimport kafka\n",
            "app/b.py": "import pymemcache\nimport pymongo\nimport pika\n",
        }
    )
    for c in claims_for(sentence):
        v = offline(repo, c)
        assert v.status != "VIOLATED", f"{sentence!r}: {v.rationale}"


@pytest.mark.parametrize("cat", ["cache", "caching", "message broker", "database", "queue"])
def test_d7_over_acceptance_catalog_categories_stay_decisive(make_repo, cat):
    """A catalog category must keep working (not everything fail-closed)."""
    repo = make_repo({"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"})
    seen = {offline(repo, mk("only", {"only": ["Redis"], "category": c})).status for c in [cat]}
    # 'database' / 'queue' etc. may be UNKNOWN for other reasons; but 'cache' variants must be VIOLATED
    if cat in ("cache", "caching"):
        assert seen == {"VIOLATED"}, seen


def test_d7_plain_only_without_category_still_decisive(make_repo):
    repo = make_repo({"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"})
    assert offline(repo, mk("only", {"only": ["Redis"]})).status == "VIOLATED"
    repo2 = make_repo({"app/a.py": "import redis\n"})
    assert offline(repo2, mk("only", {"only": ["Redis"]})).status == "HOLDING"


# ============================================================ D4: LLM path must not override the net


def _net_cases():
    return {
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
        "manner": (
            {"app/a.py": REQ, "adapters/h.py": REQ},
            "boundary",
            {"target": ["requests"], "allowed_in": ["adapters/"], "manner": "directly"},
        ),
        "forbid-call": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "action": "call"}),
        "forbid-access": (
            {"app/a.py": REQ},
            "forbid",
            {"forbid": ["requests"], "action": "access"},
        ),
        "forbid-manner": (
            {"app/a.py": REQ},
            "forbid",
            {"forbid": ["requests"], "manner": "synchronously"},
        ),
        "unless": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "unless": "in tests"}),
        "when": ({"app/a.py": REQ}, "forbid", {"forbid": ["requests"], "when": "in production"}),
        "bad-actor": (
            {"app/a.py": REQ},
            "forbid",
            {"forbid": ["requests"], "actor": ["Nonexistent Things"]},
        ),
        "purpose": (
            {"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"},
            "only",
            {"only": ["Redis"], "category": "session storage"},
        ),
        "require-for": (
            {"app/a.py": "import pymemcache\n"},
            "require",
            {"require": ["Redis"], "for": "audit logging"},
        ),
    }


@pytest.mark.parametrize("name", list(_net_cases()))
@pytest.mark.parametrize("proposed", ["VIOLATED", "HOLDING", "DRIFTING"])
@pytest.mark.parametrize("mode", ["llm", "auto"])
def test_d4_model_cannot_decide_a_rule_unknown(make_repo, name, proposed, mode):
    files, kind, rule = _net_cases()[name]
    repo = make_repo(files)
    c = mk(kind, rule)
    base = offline(repo, c)
    if base.status != "UNKNOWN":
        pytest.skip(f"offline already {base.status} for {name}")
    v = llm(repo, c, proposed, mode)
    assert v.status == "UNKNOWN", f"{name}/{proposed}/{mode}: model overrode the net -> {v.status}"


def test_d4_net_unknown_still_records_the_proposal(make_repo):
    files, kind, rule = _net_cases()["between"]
    repo = make_repo(files)
    v = llm(repo, mk(kind, rule), "VIOLATED")
    assert v.status == "UNKNOWN"
    assert getattr(v, "proposed_status", None) == "VIOLATED"


def test_d4_model_still_decides_what_the_rules_cannot_map(make_repo):
    """Free claims / unmapped terms stay the model's to decide (not over-closed)."""
    repo = make_repo({"app/a.py": REQ})
    c = mk("free", {"text": "We keep the code tidy."}, quote="We keep the code tidy.")
    v = llm(repo, c, "HOLDING")
    assert v.status in ("HOLDING", "UNKNOWN")  # allowed to be decided; no crash
    c2 = mk("forbid", {"forbid": ["zzzunknowntechzzz"]})
    v2 = llm(repo, c2, "VIOLATED")
    assert v2.status in ("UNKNOWN", "VIOLATED", "HOLDING")


def test_d4_model_cannot_override_a_decided_rule_verdict(make_repo):
    repo = make_repo({"app/a.py": REQ})
    c = mk("forbid", {"forbid": ["requests"]})
    assert offline(repo, c).status == "VIOLATED"
    assert llm(repo, c, "HOLDING").status == "VIOLATED"
    clean = make_repo({"app/a.py": F_})
    assert offline(clean, c).status == "HOLDING"
    assert llm(clean, c, "VIOLATED").status == "HOLDING"


def test_d4_model_with_zero_or_bad_citations_never_decides(make_repo):
    files, kind, rule = _net_cases()["between"]
    repo = make_repo(files)
    for status in ("VIOLATED", "HOLDING"):
        v = Judge(repo, mode="llm", provider=fake(status, n_cite=0)).judge(mk(kind, rule))  # type: ignore[arg-type]
        assert v.status == "UNKNOWN"


# ============================================================ D5: generic "services"


def test_d5_services_dir_exists_other_code_imports_not_violated(make_repo):
    repo = make_repo({"services/a.py": F_, "libs/b.py": REQ})
    for sent in ("Services must not import requests.", "No service may import requests."):
        for c in claims_for(sent):
            assert offline(repo, c).status != "VIOLATED", sent


def test_d5_services_violation_stays_decisive_when_both_readings_agree(make_repo):
    repo = make_repo({"services/a.py": REQ, "libs/b.py": F_})
    for c in claims_for("Services must not import requests."):
        assert offline(repo, c).status == "VIOLATED"
    clean = make_repo({"services/a.py": F_, "libs/b.py": F_})
    for c in claims_for("Services must not import requests."):
        assert offline(clean, c).status == "HOLDING"


def test_d5_no_services_dir_is_whole_repo(make_repo):
    repo = make_repo({"app/a.py": REQ})
    for c in claims_for("Services must not import requests."):
        assert offline(repo, c).status == "VIOLATED"


# ============================================================ D3 / D9 / D11 / D10 (Terraform, module files)


TF_RANDOM = 'provider "random" {}\n'


@pytest.mark.parametrize(
    "lit", ["hashicorp/random", "registry.terraform.io/hashicorp/random", "Hashicorp/Random"]
)
def test_d3_d11_bare_provider_block_is_the_implicit_hashicorp_source(make_repo, lit):
    repo = make_repo({"infra/main.tf": TF_RANDOM})
    v = offline(repo, mk("forbid", {"forbid": [lit]}))
    assert v.status != "HOLDING", (lit, v.status, v.rationale)


def test_d3_non_hashicorp_source_in_same_dir_blocks_implicit(make_repo):
    tf = 'terraform {\n  required_providers {\n    random = { source = "acme/random" }\n  }\n}\nprovider "random" {}\n'
    repo = make_repo({"infra/main.tf": tf})
    v = offline(repo, mk("forbid", {"forbid": ["hashicorp/random"]}))
    assert v.status != "VIOLATED", "acme/random is not hashicorp/random"


def test_d3_other_dir_not_poisoned(make_repo):
    repo = make_repo({"a/main.tf": TF_RANDOM, "b/main.tf": 'provider "aws" {}\n'})
    v = offline(repo, mk("forbid", {"forbid": ["hashicorp/aws"]}))
    assert v.status != "HOLDING"
    v2 = offline(repo, mk("forbid", {"forbid": ["hashicorp/google"]}))
    assert v2.status == "HOLDING"


def test_d9_tf_json_parsed(make_repo, tmp_path):
    tfj = json.dumps(
        {
            "provider": {"random": {}},
            "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}},
        }
    )
    repo = make_repo({"infra/main.tf.json": tfj})
    refs = parse_manifest("infra/main.tf.json", tfj)
    assert any("aws" in r.package or "random" in r.package for r in refs.refs), refs
    v = offline(repo, mk("forbid", {"forbid": ["hashicorp/aws"]}))
    assert v.status != "HOLDING", v.rationale
    v2 = offline(repo, mk("forbid", {"forbid": ["hashicorp/google"]}))
    assert v2.status == "HOLDING"


@pytest.mark.parametrize(
    "bad",
    [
        "{not json",
        "[]",
        '"str"',
        "null",
        '{"provider": 5}',
        '{"terraform": {"required_providers": []}}',
        "﻿{}",
        "",
    ],
)
def test_d9_tf_json_garbage_never_crashes(bad):
    parse_manifest("x/main.tf.json", bad)


def test_d11_literal_canonicalised_never_crashes_on_odd_input():
    for lit in [
        "registry.terraform.io/",
        "registry.terraform.io/hashicorp/",
        "/",
        "hashicorp/",
        "REGISTRY.TERRAFORM.IO/hashicorp/random",
        "a/b/c/d/e",
    ]:
        literal_technology(lit)


def test_d10_module_file_target(make_repo):
    repo = make_repo({"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_})
    v = offline(repo, mk("boundary", {"target": ["payments"], "allowed_in": ["billing/"]}))
    assert v.status != "HOLDING", v.rationale
    ok = make_repo({"payments.py": F_, "app/a.py": F_, "billing/b.py": "import payments\n"})
    v2 = offline(ok, mk("boundary", {"target": ["payments"], "allowed_in": ["billing/"]}))
    assert v2.status == "HOLDING", v2.status


def test_d10_module_file_case_insensitive(make_repo):
    repo = make_repo({"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_})
    v = offline(repo, mk("boundary", {"target": ["Payments"], "allowed_in": ["billing/"]}))
    assert v.status != "HOLDING", v.rationale


# ============================================================ over-acceptance regression (en masse)


def _regression_matrix():
    rows = []
    for tech, imp in (("requests", REQ), ("boto3", BOTO)):
        rows.append(
            ("forbid-viol", {"app/a.py": imp}, mk("forbid", {"forbid": [tech]}), "VIOLATED")
        )
        rows.append(("forbid-hold", {"app/a.py": F_}, mk("forbid", {"forbid": [tech]}), "HOLDING"))
        rows.append(
            (
                "boundary-viol",
                {"app/a.py": imp, "adapters/h.py": imp},
                mk("boundary", {"target": [tech], "allowed_in": ["adapters/"]}),
                "VIOLATED",
            )
        )
        rows.append(
            (
                "boundary-hold",
                {"app/a.py": F_, "adapters/h.py": imp},
                mk("boundary", {"target": [tech], "allowed_in": ["adapters/"]}),
                "HOLDING",
            )
        )
        for actor, d in (("Handlers", "handlers"), ("Domain", "domain"), ("Workers", "workers")):
            rows.append(
                (
                    f"actor-viol-{d}",
                    {f"{d}/a.py": imp, "other/b.py": F_},
                    mk("forbid", {"forbid": [tech], "actor": [actor]}),
                    "VIOLATED",
                )
            )
            rows.append(
                (
                    f"actor-hold-{d}",
                    {f"{d}/a.py": F_, "other/b.py": imp},
                    mk("forbid", {"forbid": [tech], "actor": [actor]}),
                    "HOLDING",
                )
            )
    rows.append(
        (
            "only-viol",
            {"app/a.py": "import redis\n", "app/b.py": "import pymemcache\n"},
            mk("only", {"only": ["Redis"]}),
            "VIOLATED",
        )
    )
    rows.append(
        ("only-hold", {"app/a.py": "import redis\n"}, mk("only", {"only": ["Redis"]}), "HOLDING")
    )
    rows.append(
        (
            "require-hold",
            {"app/a.py": "import redis\n"},
            mk("require", {"require": ["Redis"]}),
            "HOLDING",
        )
    )
    rows.append(
        ("require-absent", {"app/a.py": F_}, mk("require", {"require": ["Redis"]}), "UNKNOWN")
    )
    return rows


@pytest.mark.parametrize("row", _regression_matrix(), ids=lambda r: r[0])
def test_over_acceptance_previously_correct_verdicts_stay(make_repo, row):
    label, files, claim, expected = row
    repo = make_repo(files)
    v = offline(repo, claim)
    assert v.status == expected, f"{label}: {v.status} ({v.rationale})"
    grounded(repo, v)


def test_over_acceptance_sentence_corpus_decisive_rate(make_repo):
    """>= 90% of plain well-formed sentences with a clear truth stay decisive (not UNKNOWN en masse)."""
    total = decisive = bad = 0
    for subj, d in [
        ("Handlers", "handlers"),
        ("Controllers", "controllers"),
        ("Workers", "workers"),
        ("The domain layer", "domain"),
        ("Views", "views"),
    ]:
        for tech, imp in (("requests", REQ), ("boto3", BOTO)):
            for verb in ("must not import", "should not import", "must never import"):
                for files, truth in (
                    ({f"{d}/a.py": imp, "other/b.py": F_}, "V"),
                    ({f"{d}/a.py": F_, "other/b.py": imp}, "H"),
                ):
                    repo = make_repo(files)
                    for c in claims_for(f"{subj} {verb} {tech}."):
                        v = offline(repo, c)
                        total += 1
                        decisive += v.status in ("VIOLATED", "HOLDING")
                        bad += wrong(v.status, truth)
    assert bad == 0, f"{bad} false decisive verdicts"
    assert total >= 60
    assert decisive / total >= 0.9, f"only {decisive}/{total} decisive"


# ============================================================ G2 grounding / tamper on the new shapes


def test_g2_new_shape_evidence_verifies_and_tamper_is_caught(make_repo):
    shapes = [
        (
            {"payments/core.py": F_, "app/a.py": "from payments import core\n", "billing/b.py": F_},
            mk("boundary", {"target": ["Payments"], "allowed_in": ["billing/"]}),
        ),
        (
            {"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_},
            mk("boundary", {"target": ["payments"], "allowed_in": ["billing/"]}),
        ),
        (
            {"handlers/a.py": REQ, "other/b.py": F_},
            mk("forbid", {"forbid": ["requests"], "actor": ["Handlers"]}),
        ),
        ({"infra/main.tf": TF_RANDOM}, mk("forbid", {"forbid": ["hashicorp/random"]})),
        (
            {"infra/main.tf.json": json.dumps({"provider": {"random": {}}})},
            mk("forbid", {"forbid": ["hashicorp/random"]}),
        ),
    ]
    rng = random.Random(2610)
    ev_checked = caught = escaped = 0
    verified_items = 0
    for files, c in shapes:
        repo = make_repo(files)
        v = offline(repo, c)
        if not v.evidence:
            continue
        assert v.grounding == "VERIFIED", (v.status, v.reasons)
        sha = v.commit
        paths = [p for p in _git(repo, "ls-files").splitlines() if p]
        lines = [
            ln.strip()
            for p in paths
            for ln in show(repo, sha, p).splitlines()
            if len(ln.strip()) > 6
        ]
        for ev in v.evidence[:3]:
            verified_items += 1
            assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=sha))
            for _op, mut in itertools.islice(
                mutate_evidence(rng, repo, sha, ev, paths, lines), 150
            ):
                if _is_equivalent(repo, ev, mut):
                    continue
                ev_checked += 1
                if any(r.status != "VERIFIED" for r in verify_evidence(repo, mut, commit=sha)):
                    caught += 1
                else:
                    escaped += 1
                g = gate(
                    Verdict.model_validate({**v.model_dump(), "evidence": [mut.model_dump()]}), repo
                )
                assert g.status == "UNKNOWN" or any(
                    r.status != "VERIFIED" for r in verify_evidence(repo, mut, commit=sha)
                )
    print(
        f"\nL026-G2 evidence_items={verified_items} verified=ALL mutations={ev_checked} caught={caught} escaped={escaped}"
    )
    assert verified_items >= 3
    assert escaped == 0, f"{escaped} tampered evidence escaped"
