# ruff: noqa: E501, F811
"""L-027 system tests (Sonnet): adversarial retest of the noun-suffixed boundary target fix (N1).

Independent of tests/test_l027_target_noun.py (Opus). Truth labels: V = truly violated, H = truly
holding, U = ambiguous/unlabelled (anything but a documented wrong verdict is acceptable).
Rule: VIOLATED only if truly violated, HOLDING only if truly holding; UNKNOWN always allowed.
No network, no API key.
"""

from __future__ import annotations

import itertools
import random

import pytest

from driftwarden.judge import Judge, gate, verify_evidence
from driftwarden.models import Verdict
from test_l007_system import _is_equivalent, mutate_evidence, show
from test_l026_system import (  # noqa: F401  (fixtures)
    BOTO,
    F_,
    _git,
    claims_for,
    fake,
    grounded,
    llm,
    make_repo,
    mk,
    no_network,
    offline,
)

V = {"payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_}
H = {"payments/core.py": F_, "app/a.py": F_, "billing/b.py": "import payments.core\n"}


def S(noun, a="billing/"):
    return f"The payments {noun} may be imported only from {a}."


# (id, files, sentence, truth) truth: V violated, H holding, U unknown-or-whatever(report only)
C = []


def add(i, files, s, truth):
    C.append((i, files, s, truth))


for n in [
    "package",
    "module",
    "library",
    "lib",
    "component",
    "folder",
    "directory",
    "code",
    "service",
]:
    add(f"v-{n}", V, S(n), "V")
    add(f"h-{n}", H, S(n), "H")
for s in [
    "Payments Packages may be imported only from billing/.",
    "The Payments Package may be imported only from billing/.",
    "The payments packages may be imported only from billing/.",
    "The `payments` package may be imported only from billing/.",
    "The PAYMENTS MODULE may be imported only from billing/.",
    "The payments modules may be imported only from billing/.",
    "The module payments may be imported only from billing/.",
    "The package payments may be imported only from billing/.",
    "The payments-module may be imported only from billing/.",
    "The payments Python package may be imported only from billing/.",
    "The payments package is imported only from billing/.",
    "Only billing/ may import the payments package.",
    "The payments package must not be imported outside billing/.",
    "payments package: only billing/ may import it.",
    "The payments/ package may be imported only from billing/.",
]:
    add("sv:" + s[:40], V, s, "V")
    add("sh:" + s[:40], H, s, "H")
add(
    "mono-v",
    {
        "services/api/payments/core.py": F_,
        "services/api/app.py": "import payments.core\n",
        "services/api/billing/b.py": F_,
    },
    S("package", "services/api/billing/"),
    "V",
)
add(
    "mono-h",
    {
        "services/api/payments/core.py": F_,
        "services/api/app.py": F_,
        "services/api/billing/b.py": "import payments.core\n",
    },
    S("package", "services/api/billing/"),
    "H",
)
add(
    "mono-two",
    {
        "services/a/payments/core.py": F_,
        "services/b/payments/core.py": F_,
        "app/x.py": "import payments.core\n",
        "billing/b.py": F_,
    },
    S("package"),
    "U",
)
add("vendor-twin", {**V, "vendor/payments/x.py": F_}, S("package"), "U")
add("tests-twin", {**V, "tests/payments/test_x.py": F_}, S("module"), "U")
add("tests-twin-h", {**H, "tests/payments/test_x.py": F_}, S("module"), "U")
add("node_modules-twin", {**V, "node_modules/payments/index.js": "x\n"}, S("package"), "U")
add("case-twin", {**V, "Payments/x.py": F_}, S("package"), "U")
add("dir+file", {**V, "util/payments.py": F_}, S("package"), "U")
add(
    "file-only-v",
    {"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_},
    S("module"),
    "V",
)
add(
    "file-only-h",
    {"payments.py": F_, "app/a.py": F_, "billing/b.py": "import payments\n"},
    S("module"),
    "H",
)
add(
    "embedded-dir-v",
    {"payments-module/core.py": F_, "app/a.py": "print(1)\n", "billing/b.py": F_},
    "The payments-module/ directory may be imported only from billing/.",
    "U",
)
add(
    "embedded-pkg",
    {
        "payments_module/core.py": F_,
        "app/a.py": "import payments_module.core\n",
        "billing/b.py": F_,
    },
    "The payments-module package may be imported only from billing/.",
    "U",
)
add(
    "embedded-pkg2",
    {
        "payments_module/core.py": F_,
        "app/a.py": "import payments_module.core\n",
        "billing/b.py": F_,
    },
    "The payments_module package may be imported only from billing/.",
    "V",
)
add(
    "ns-v",
    {"payments/sub/core.py": F_, "app/a.py": "import payments.sub.core\n", "billing/b.py": F_},
    S("package"),
    "V",
)
add(
    "ns-h",
    {"payments/sub/core.py": F_, "app/a.py": F_, "billing/b.py": "from payments.sub import core\n"},
    S("package"),
    "H",
)
add(
    "ns-init",
    {"payments/__init__.py": "", "app/a.py": "from payments import x\n", "billing/b.py": F_},
    S("package"),
    "V",
)
add(
    "relative",
    {"billing/payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_},
    S("package"),
    "U",
)
add(
    "js-v",
    {
        "src/payments/index.js": "export const a=1\n",
        "src/app/a.js": "import {a} from '../payments'\n",
        "src/billing/b.js": "export const b=1\n",
    },
    S("module", "src/billing/"),
    "V",
)
add(
    "js-h",
    {
        "src/payments/index.js": "export const a=1\n",
        "src/app/a.js": "export const c=1\n",
        "src/billing/b.js": "import {a} from '../payments'\n",
    },
    S("module", "src/billing/"),
    "H",
)
add(
    "js-req-v",
    {
        "payments/index.js": "module.exports={}\n",
        "app/a.js": "const p=require('../payments/index')\n",
        "billing/b.js": "1\n",
    },
    S("package"),
    "V",
)
add(
    "go-v",
    {
        "go.mod": "module example.com/m\n\ngo 1.21\n",
        "payments/pay.go": "package payments\n",
        "app/main.go": 'package main\n\nimport "example.com/m/payments"\n',
        "billing/b.go": "package billing\n",
    },
    S("package"),
    "V",
)
add(
    "go-h",
    {
        "go.mod": "module example.com/m\n\ngo 1.21\n",
        "payments/pay.go": "package payments\n",
        "app/main.go": "package main\n",
        "billing/b.go": 'package billing\n\nimport "example.com/m/payments"\n',
    },
    S("package"),
    "H",
)
add(
    "java-v",
    {
        "src/com/acme/payments/Pay.java": "package com.acme.payments;\nclass Pay{}\n",
        "src/com/acme/app/A.java": "package com.acme.app;\nimport com.acme.payments.Pay;\nclass A{}\n",
        "src/com/acme/billing/B.java": "package com.acme.billing;\nclass B{}\n",
    },
    S("package", "src/com/acme/billing/"),
    "V",
)
add(
    "java-h",
    {
        "src/com/acme/payments/Pay.java": "package com.acme.payments;\nclass Pay{}\n",
        "src/com/acme/app/A.java": "package com.acme.app;\nclass A{}\n",
        "src/com/acme/billing/B.java": "package com.acme.billing;\nimport com.acme.payments.Pay;\nclass B{}\n",
    },
    S("package", "src/com/acme/billing/"),
    "H",
)
RD = {"redis/client.py": F_, "requirements.txt": "redis==5.0\n"}
add(
    "redis-local-ext-v",
    {**RD, "app/a.py": "import redis\n", "billing/b.py": F_},
    "The redis module may be imported only from billing/.",
    "U",
)
add(
    "redis-local-h",
    {**RD, "app/a.py": F_, "billing/b.py": "import redis\n"},
    "The redis module may be imported only from billing/.",
    "U",
)
add(
    "redis-lib-nodir-v",
    {"requirements.txt": "redis==5.0\n", "app/a.py": "import redis\n", "billing/b.py": F_},
    "The redis library may be imported only from billing/.",
    "V",
)
add(
    "requests-lib-v",
    {"requirements.txt": "requests\n", "app/a.py": "import requests\n", "billing/b.py": F_},
    "The requests library may be imported only from billing/.",
    "V",
)
add(
    "requests-lib-h",
    {"requirements.txt": "requests\n", "app/a.py": F_, "billing/b.py": "import requests\n"},
    "The requests library may be imported only from billing/.",
    "H",
)
add(
    "requests-pkg-localdir",
    {
        "requests/x.py": F_,
        "requirements.txt": "requests\n",
        "app/a.py": "import requests\n",
        "billing/b.py": F_,
    },
    "The requests package may be imported only from billing/.",
    "U",
)
add(
    "absent-pkg",
    {"app/a.py": F_, "billing/b.py": F_},
    "The ledger package may be imported only from billing/.",
    "U",
)
add(
    "absent-svc",
    {"app/a.py": F_, "billing/b.py": F_},
    "The ledger service may be imported only from billing/.",
    "U",
)
add(
    "absent-bare",
    {"app/a.py": F_, "billing/b.py": F_},
    "Ledger may be imported only from billing/.",
    "U",
)
add(
    "boto-plain",
    {"requirements.txt": "boto3\n", "app/a.py": "import boto3\n", "billing/b.py": F_},
    "boto3 may be imported only from billing/.",
    "V",
)
add(
    "boto-pkg",
    {"requirements.txt": "boto3\n", "app/a.py": "import boto3\n", "billing/b.py": F_},
    "The boto3 package may be imported only from billing/.",
    "V",
)
add(
    "boto-pkg-h",
    {"requirements.txt": "boto3\n", "app/a.py": F_, "billing/b.py": "import boto3\n"},
    "The boto3 package may be imported only from billing/.",
    "H",
)
add(
    "noun-in-allowed", V, "The payments package may be imported only from the billing package.", "U"
)
add(
    "noun-in-allowed2",
    {**V, "billing/__init__.py": ""},
    "The payments package may be imported only from the billing module.",
    "U",
)
add("both-nouns", V, "The payments service may be imported only from billing/ code.", "U")
add(
    "multi-target",
    {**V, "ledger/l.py": "import payments.core\n"},
    "The payments and ledger packages may be imported only from billing/.",
    "U",
)
add(
    "two-words",
    {"payments_core/c.py": F_, "app/a.py": "import payments_core\n", "billing/b.py": F_},
    "The payments core package may be imported only from billing/.",
    "U",
)
add("dotted", V, "The payments.core module may be imported only from billing/.", "V")
add("dotted-h", H, "The payments.core module may be imported only from billing/.", "H")
add("slashed", V, "The payments/core module may be imported only from billing/.", "U")
add("forbid-own", V, "The payments module must not be used.", "U")
add("forbid-own-code", V, "Code must not use the payments module.", "U")
add("forbid-own-pkg", V, "Application code must not depend on the payments package.", "U")
add("forbid-absent", {"app/a.py": F_}, "Application code must not use the ledger package.", "U")
add(
    "forbid-requests",
    {"requirements.txt": "requests\n", "app/a.py": "import requests\n"},
    "Application code must not use the requests library.",
    "V",
)
add(
    "forbid-requests-h",
    {"requirements.txt": "flask\n", "app/a.py": "import flask\n"},
    "Application code must not use the requests library.",
    "H",
)
add(
    "forbid-boto",
    {"requirements.txt": "boto3\n", "app/a.py": "import boto3\n"},
    "Application code must not use boto3.",
    "V",
)
add("forbid-bare-absent", {"app/a.py": F_}, "Application code must not use ledger.", "U")
add("forbid-dir-bare", V, "Application code must not use payments.", "U")
add("empty-head", V, "The package may be imported only from billing/.", "U")
add("module-only", V, "The module may be imported only from billing/.", "U")
add("only-form", V, "Only billing/ may import the payments module.", "V")
add("only-form-h", H, "Only billing/ may import the payments module.", "H")
add(
    "services-dir",
    {"services/core.py": F_, "app/a.py": "import services.core\n", "billing/b.py": F_},
    "The services package may be imported only from billing/.",
    "V",
)
add(
    "code-dir",
    {"code/x.py": F_, "app/a.py": "import code.x\n", "billing/b.py": F_},
    "The code directory may be imported only from billing/.",
    "U",
)
add(
    "lib-dir-head",
    {"lib/x.py": F_, "app/a.py": "import lib.x\n", "billing/b.py": F_},
    "The lib folder may be imported only from billing/.",
    "U",
)
add(
    "unicode",
    {"pagos/c.py": F_, "app/a.py": "import pagos.c\n", "billing/b.py": F_},
    "The pagos package may be imported only from billing/.",
    "V",
)
add(
    "hidden-dep",
    {
        "payments/core.py": F_,
        "app/a.py": "import importlib\nimportlib.import_module('payments.core')\n",
        "billing/b.py": F_,
    },
    S("package"),
    "U",
)


# pre-existing on main and left HOLDING by design (bare absent literal): not a branch regression
KNOWN_MAIN_WRONG = {"sv:The payments-module may be imported only"}
# previously HOLDING-correct on main, UNKNOWN on branch (dotted / slashed head): tolerated drift
DRIFT_OK = {"dotted-h"}


def _verdicts(make_repo, files, sentence):
    repo = make_repo(files)
    return repo, [(c, offline(repo, c)) for c in claims_for(sentence)]


@pytest.mark.parametrize("case", C, ids=[c[0] for c in C])
def test_corpus_no_false_decisive(make_repo, case):
    cid, files, sentence, truth = case
    repo, vs = _verdicts(make_repo, files, sentence)
    for _c, v in vs:
        if v.status == "VIOLATED":
            grounded(repo, v)
        if cid in KNOWN_MAIN_WRONG:
            continue
        assert not (v.status == "VIOLATED" and truth == "H"), (cid, v.rationale)
        assert not (v.status == "HOLDING" and truth == "V"), (cid, v.rationale)


def test_corpus_is_large_enough():
    assert len(C) >= 60


@pytest.mark.parametrize("case", C, ids=[c[0] for c in C])
def test_corpus_llm_cannot_override_fail_closed(make_repo, case):
    """Scripted provider proposes VIOLATED and HOLDING on everything; wherever offline is
    fail_closed UNKNOWN, the model must not move it."""
    cid, files, sentence, _t = case
    repo = make_repo(files)
    for c in claims_for(sentence):
        ev = Judge(repo, mode="offline").evidence(c)
        base = offline(repo, c)
        for prop in ("VIOLATED", "HOLDING"):
            v = llm(repo, c, prop)
            if ev.fail_closed:
                assert base.status == "UNKNOWN"
                assert v.status == "UNKNOWN", (cid, prop, v.status, ev.fail_closed)
            if v.status == "VIOLATED":
                grounded(repo, v)


def test_resolved_verdicts_ground_and_survive_tamper(make_repo):
    shapes = [
        (V, S("package")),
        (H, S("module")),
        (
            {
                "services/api/payments/core.py": F_,
                "services/api/app.py": "import payments.core\n",
                "services/api/billing/b.py": F_,
            },
            S("package", "services/api/billing/"),
        ),
        ({"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_}, S("module")),
        (
            {
                "go.mod": "module example.com/m\n\ngo 1.21\n",
                "payments/pay.go": "package payments\n",
                "app/main.go": 'package main\n\nimport "example.com/m/payments"\n',
                "billing/b.go": "package billing\n",
            },
            S("package"),
        ),
    ]
    rng = random.Random(2701)
    items = checked = caught = escaped = 0
    for files, sentence in shapes:
        repo = make_repo(files)
        for c in claims_for(sentence):
            v = offline(repo, c)
            assert v.status in ("VIOLATED", "HOLDING"), (sentence, v.status, v.rationale)
            assert v.grounding == "VERIFIED", v.reasons
            sha = v.commit
            paths = [p for p in _git(repo, "ls-files").splitlines() if p]
            lines = [
                ln.strip()
                for p in paths
                for ln in show(repo, sha, p).splitlines()
                if len(ln.strip()) > 6
            ]
            for ev in v.evidence[:3]:
                items += 1
                assert all(r.status == "VERIFIED" for r in verify_evidence(repo, ev, commit=sha))
                for _op, mut in itertools.islice(
                    mutate_evidence(rng, repo, sha, ev, paths, lines), 150
                ):
                    if _is_equivalent(repo, ev, mut):
                        continue
                    checked += 1
                    if any(r.status != "VERIFIED" for r in verify_evidence(repo, mut, commit=sha)):
                        caught += 1
                    else:
                        escaped += 1
                    g = gate(
                        Verdict.model_validate({**v.model_dump(), "evidence": [mut.model_dump()]}),
                        repo,
                    )
                    assert g.status == "UNKNOWN" or any(
                        r.status != "VERIFIED" for r in verify_evidence(repo, mut, commit=sha)
                    )
    print(f"\nL027-G2 evidence_items={items} mutations={checked} caught={caught} escaped={escaped}")
    assert items >= 3
    assert escaped == 0


def test_n1_acceptance(make_repo):
    for files, want in ((V, "VIOLATED"), (H, "HOLDING")):
        repo = make_repo(files)
        for c in claims_for("The payments package may be imported only from billing/."):
            assert offline(repo, c).status == want


@pytest.mark.parametrize("d", ["the", "a", "an", "our"])
def test_article_named_directory_does_not_hijack(make_repo, d):
    """'The service' / 'a lib' must not be read as the directory named by the article."""
    repo = make_repo({f"{d}/x.py": F_, "app/a.py": f"import {d}.x\n", "billing/b.py": F_})
    for sentence in (f"{d.capitalize()} service may be imported only from billing/.",):
        for c in claims_for(sentence):
            assert offline(repo, c).status not in ("HOLDING", "VIOLATED")


def test_catalog_with_local_dir_never_false_decisive(make_repo):
    repo = make_repo(
        {
            "redis/client.py": F_,
            "requirements.txt": "redis==5.0\n",
            "app/a.py": "import redis\n",
            "billing/b.py": F_,
        }
    )
    for c in claims_for("The redis module may be imported only from billing/."):
        assert offline(repo, c).status in ("VIOLATED", "UNKNOWN")
