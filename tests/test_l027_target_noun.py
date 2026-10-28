# ruff: noqa: E501, F811
"""L-027 (Opus): boundary targets with a trailing generic noun (N1 from the L-026 system test).

"The payments package may be imported only from billing/." named payments/ but gave a false
HOLDING ('target not imported anywhere'). The noun is dropped only when the remaining name
names exactly one directory or module file; otherwise the claim fails closed. A boundary
target that names nothing the evidence can see (no directory, module file, catalog
technology or known package) is never HOLDING. No network, no API key.
"""

from __future__ import annotations

import pytest

from driftwarden.judge import Judge
from driftwarden.judge.evidence import local_targets, target_noun_head
from test_l026_judge_defects import needs_case_sensitive_fs
from test_l026_system import (  # noqa: F401  (fixtures)
    BOTO,
    F_,
    REQ,
    claims_for,
    grounded,
    llm,
    make_repo,
    mk,
    no_network,
    offline,
)

NOUNS = [
    "package",
    "module",
    "library",
    "lib",
    "component",
    "folder",
    "directory",
    "code",
    "service",
    "services",
]

VIOL = {"payments/core.py": F_, "app/a.py": "import payments.core\n", "billing/b.py": F_}
HOLD = {"payments/core.py": F_, "app/a.py": F_, "billing/b.py": "import payments.core\n"}


def boundary(target: str, allowed: str = "billing/"):
    return mk("boundary", {"target": [target], "allowed_in": [allowed]})


def fail_closed(repo, c) -> str | None:
    return Judge(repo, mode="offline").evidence(c).fail_closed


# ------------------------------------------------------------------ the N1 sentences


@pytest.mark.parametrize("noun", NOUNS)
def test_sentence_with_noun_is_violated(make_repo, noun):
    repo = make_repo(VIOL)
    cs = claims_for(f"The payments {noun} may be imported only from billing/.")
    assert cs
    for c in cs:
        v = offline(repo, c)
        assert v.status == "VIOLATED", (noun, v.status, v.rationale)
        grounded(repo, v)


@pytest.mark.parametrize("noun", NOUNS)
def test_sentence_with_noun_holds_when_it_truly_holds(make_repo, noun):
    repo = make_repo(HOLD)
    for c in claims_for(f"The payments {noun} may be imported only from billing/."):
        v = offline(repo, c)
        assert v.status == "HOLDING", (noun, v.status, v.rationale)


@pytest.mark.parametrize(
    "target", ["Payments package", "`payments` module", "PAYMENTS library", "our payments lib"]
)
def test_noun_target_spellings(make_repo, target):
    assert offline(make_repo(VIOL), boundary(target)).status == "VIOLATED"
    assert offline(make_repo(HOLD), boundary(target)).status == "HOLDING"


def test_noun_target_module_file(make_repo):
    repo = make_repo({"payments.py": F_, "app/a.py": "import payments\n", "billing/b.py": F_})
    assert offline(repo, boundary("payments module")).status == "VIOLATED"
    ok = make_repo({"payments.py": F_, "app/a.py": F_, "billing/b.py": "import payments\n"})
    assert offline(ok, boundary("payments module")).status == "HOLDING"


# ------------------------------------------------------------------ nested directories


def test_single_nested_directory_resolves(make_repo):
    repo = make_repo(
        {
            "src/payments/core.py": F_,
            "src/app/a.py": "from src.payments import core\n",
            "src/billing/b.py": F_,
        }
    )
    v = offline(repo, boundary("payments package"))
    assert v.status == "VIOLATED", v.rationale


@pytest.mark.parametrize(
    "files",
    [
        {
            "a/payments/x.py": F_,
            "b/payments/y.py": F_,
            "app/m.py": "import a.payments.x\n",
            "billing/b.py": F_,
        },
        {
            "payments/x.py": F_,
            "payments/payments/y.py": F_,
            "app/m.py": "import payments.x\n",
            "billing/b.py": F_,
        },
        {
            "payments/x.py": F_,
            "payments.py": F_,
            "app/m.py": "import payments\n",
            "billing/b.py": F_,
        },
    ],
    ids=["two-nested", "nested-twin", "dir-and-module"],
)
@pytest.mark.parametrize("noun", ["package", "module", "library"])
def test_several_candidates_fail_closed(make_repo, files, noun):
    repo = make_repo(files)
    c = boundary(f"payments {noun}")
    assert offline(repo, c).status == "UNKNOWN"
    assert fail_closed(repo, c)
    for proposed in ("HOLDING", "VIOLATED"):
        assert llm(repo, c, proposed).status == "UNKNOWN"


@needs_case_sensitive_fs
def test_case_twins_fail_closed(make_repo):
    repo = make_repo(
        {
            "Payments/x.py": F_,
            "payments/y.py": F_,
            "app/a.py": "import payments.y\n",
            "billing/b.py": F_,
        }
    )
    c = boundary("payments package")
    assert offline(repo, c).status == "UNKNOWN"
    assert fail_closed(repo, c)


# ------------------------------------------------------------------ targets that name nothing


@pytest.mark.parametrize(
    "target",
    ["ledger package", "the ledger module", "ledger service", "ledger code", "acme/ledger lib"],
)
def test_nonexistent_target_is_unknown_never_holding(make_repo, target):
    repo = make_repo({"app/a.py": F_, "billing/b.py": F_})
    c = boundary(target)
    v = offline(repo, c)
    assert v.status == "UNKNOWN", (target, v.status, v.rationale)
    assert fail_closed(repo, c)
    assert llm(repo, c, "HOLDING").status == "UNKNOWN"


@pytest.mark.parametrize("target", ["ledger", "github.com/x/ledger"])
def test_bare_absent_package_name_keeps_its_decisive_verdict(make_repo, target):
    """A bare package-shaped name that nothing imports stays HOLDING: every import was
    scanned (guarded by test_l025_system / test_l007_judge over-acceptance tests)."""
    repo = make_repo({"app/a.py": F_, "billing/b.py": F_})
    assert offline(repo, boundary(target)).status == "HOLDING"


def test_nonexistent_noun_sentence_is_unknown(make_repo):
    repo = make_repo({"app/a.py": F_, "billing/b.py": F_})
    for noun in NOUNS:
        for c in claims_for(f"The ledger {noun} may be imported only from billing/."):
            assert offline(repo, c).status == "UNKNOWN", noun


def test_unimported_module_file_is_not_holding(make_repo):
    repo = make_repo({"payments.py": F_, "app/a.py": F_, "billing/b.py": F_})
    assert offline(repo, boundary("payments module")).status != "HOLDING"


# ------------------------------------------------------------------ known packages stay decisive


@pytest.mark.parametrize("target", ["tinydep", "the tinydep library", "tinydep package"])
def test_manifest_known_literal_stays_decisive(make_repo, target):
    viol = make_repo(
        {
            "requirements.txt": "tinydep==1.0\n",
            "app/a.py": "import tinydep\n",
            "adapters/h.py": "import tinydep\n",
        }
    )
    assert offline(viol, boundary(target, "adapters/")).status == "VIOLATED"
    hold = make_repo(
        {"requirements.txt": "tinydep==1.0\n", "app/a.py": F_, "adapters/h.py": "import tinydep\n"}
    )
    assert offline(hold, boundary(target, "adapters/")).status == "HOLDING"
    unused = make_repo({"requirements.txt": "tinydep==1.0\n", "app/a.py": F_, "adapters/h.py": F_})
    assert offline(unused, boundary(target, "adapters/")).status == "HOLDING"


@pytest.mark.parametrize("tech,imp", [("requests", REQ), ("boto3", BOTO)])
@pytest.mark.parametrize("fmt", ["{}", "the {} library", "{} package", "the {} module"])
def test_catalog_technology_with_noun_unchanged(make_repo, tech, imp, fmt):
    target = fmt.format(tech)
    viol = make_repo({"app/a.py": imp, "adapters/h.py": imp})
    v = offline(viol, boundary(target, "adapters/"))
    assert v.status == "VIOLATED", (target, v.rationale)
    grounded(viol, v)
    hold = make_repo({"app/a.py": F_, "adapters/h.py": imp})
    assert offline(hold, boundary(target, "adapters/")).status == "HOLDING"
    absent = make_repo({"app/a.py": F_, "adapters/h.py": F_})
    # requests is a catalog technology: its absence is evidence, with or without the
    # noun. boto3 is a literal name: bare, it keeps its old verdict; "the boto3
    # library" that nothing in the repository knows fails closed.
    expected = "HOLDING" if tech == "requests" or fmt == "{}" else "UNKNOWN"
    assert offline(absent, boundary(target, "adapters/")).status == expected


def test_bare_directory_targets_unchanged(make_repo):
    assert offline(make_repo(VIOL), boundary("payments")).status == "VIOLATED"
    assert offline(make_repo(HOLD), boundary("payments")).status == "HOLDING"
    assert offline(make_repo(VIOL), boundary("payments/")).status == "VIOLATED"


# ------------------------------------------------------------------ forbid of the repository's own code


def test_forbid_of_own_code_never_false_holding(make_repo):
    repo = make_repo({"payments/core.py": F_, "app/a.py": "import payments.core\n"})
    for term in ("payments", "the payments module", "payments package"):
        c = mk("forbid", {"forbid": [term]})
        assert offline(repo, c).status != "HOLDING", term
        assert fail_closed(repo, c)


def test_forbid_absent_package_and_catalog_unchanged(make_repo):
    repo = make_repo({"app/a.py": F_})
    assert offline(repo, mk("forbid", {"forbid": ["left-pad"]})).status == "HOLDING"
    assert offline(repo, mk("forbid", {"forbid": ["requests"]})).status == "HOLDING"
    assert (
        offline(
            make_repo({"app/a.py": REQ}), mk("forbid", {"forbid": ["the requests library"]})
        ).status
        == "VIOLATED"
    )


# ------------------------------------------------------------------ helpers


@pytest.mark.parametrize(
    "term,head",
    [
        ("payments package", "payments"),
        ("The payments module", "payments"),
        ("`payments` library", "payments"),
        ("payments services", "payments"),
        ("payments", None),
        ("payments core package", None),
        ("package", None),
        ("payments packager", None),
    ],
)
def test_target_noun_head(term, head):
    assert target_noun_head(term) == head


def test_local_targets_counts_distinct_paths(make_repo):
    repo = make_repo({"a/payments/x.py": F_, "b/Payments/y.py": F_, "c/other/z.py": F_})
    snap = Judge(repo, mode="offline").snapshot
    assert local_targets("payments", snap) == ["a/payments", "b/Payments"]
    assert local_targets("b/payments", snap) == ["b/Payments"]
    assert local_targets("ledger", snap) == []
