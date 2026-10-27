"""L-006: claim structuring (rule library, front-matter hints, LLM path) and the G1 gate.

No network and no API key anywhere in here: the LLM path uses OfflineProvider
with a scripted responder, and sockets are disabled for every test.
"""

from __future__ import annotations

import json
import random
import re
import socket

import pytest
from pydantic import ValidationError

from driftwarden.claims import (
    CLAIMS_SCHEMA,
    PATTERNS,
    RULES,
    build_prompt,
    extract_rule_claims,
    match_sentence,
    resolve_mode,
    structure_decision,
    structure_scan,
)
from driftwarden.claims.rules import clean_term, sentence_spans, split_list
from driftwarden.discover.adr import parse_adr, scan_adrs
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import verify_source_quote
from driftwarden.llm import OfflineProvider, RetryPolicy
from driftwarden.llm.schema import validate_json
from driftwarden.models import WORKTREE, Claim, Provenance, rule_errors

# ------------------------------------------------------------------ fixtures / fakes


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise OSError("network access is disabled in tests")

    class BlockedSocket(socket.socket):
        def connect(self, *_a, **_k):
            blocked()

    monkeypatch.setattr(socket, "socket", BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def basic(fixture_repo):
    repo = fixture_repo("basic")
    return repo, scan_adrs(repo)


def scripted(fn, attempts: int = 2) -> OfflineProvider:
    """A fake provider: ``fn(adr_id, request) -> list[claim dicts]`` (or a raw string)."""

    def responder(request):
        adr_id = re.search(r"^ADR id: (.+)$", request.prompt, re.M).group(1)
        reply = fn(adr_id, request)
        return reply if isinstance(reply, str) else json.dumps({"claims": reply})

    return OfflineProvider(
        responder=responder, retry=RetryPolicy(max_attempts=attempts, sleep=lambda _s: None)
    )


def as_llm(claim: Claim, **over) -> dict:
    d = {
        "kind": claim.kind,
        "subject": claim.subject,
        "rule": dict(claim.rule),
        "quote": claim.source.quote,
        "line_start": claim.source.line_start,
        "line_end": claim.source.line_end,
    }
    d.update(over)
    return d


def kinds(matches):
    return [(m.pattern, m.kind) for m in matches]


# ------------------------------------------------------------------ rule library


def test_library_has_at_least_12_distinct_typed_patterns():
    ids = [p.id for p in RULES]
    assert len(ids) == len(set(ids)) >= 12
    assert set(PATTERNS) == set(ids)
    assert {p.kind for p in RULES} == {"forbid", "require", "only", "boundary"}
    for p in RULES:
        assert p.examples and p.non_examples, f"{p.id} needs positive and negative tests"


@pytest.mark.parametrize(
    "pattern,sentence",
    [(p.id, ex) for p in RULES for ex in p.examples],
)
def test_pattern_positive(pattern, sentence):
    ms = match_sentence(sentence)
    assert pattern in [m.pattern for m in ms], (sentence, kinds(ms))
    m = next(m for m in ms if m.pattern == pattern)
    assert m.kind == PATTERNS[pattern].kind
    assert rule_errors(m.kind, m.rule) == []
    assert m.subject.strip()


@pytest.mark.parametrize(
    "pattern,sentence",
    [(p.id, ex) for p in RULES for ex in p.non_examples],
)
def test_pattern_negative(pattern, sentence):
    assert pattern not in [m.pattern for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence,kind,subject,rule",
    [
        (
            "PostgreSQL is the only datastore.",
            "only",
            "datastore",
            {"only": ["PostgreSQL"], "category": "datastore"},
        ),
        (
            "Services must not import `requests` or `urllib3`.",
            "forbid",
            "services",
            {"forbid": ["requests", "urllib3"], "action": "import"},
        ),
        (
            "No cloud SDK outside `adapters/`.",
            "boundary",
            "cloud sdk",
            {"target": ["cloud SDK"], "allowed_in": ["adapters/"]},
        ),
        (
            "All database access must go through the repository layer.",
            "boundary",
            "database access",
            {"target": ["database access"], "via": ["repository layer"]},
        ),
        (
            "We will use **RabbitMQ** as the message broker.",
            "require",
            "message broker",
            {"require": ["RabbitMQ"], "for": "message broker"},
        ),
        (
            "Services communicate only via the event bus.",
            "only",
            "communication",
            {"only": ["event bus"], "between": "Services"},
        ),
        (
            "We decided that Kafka is the sole message broker.",
            "only",
            "message broker",
            {"only": ["Kafka"], "category": "message broker"},
        ),
        (
            "Only `services/billing/` may access the payments database.",
            "boundary",
            "payments database",
            {
                "target": ["payments database"],
                "allowed_in": ["services/billing/"],
                "action": "access",
            },
        ),
        (
            "Node.js must not be used in the core.",
            "forbid",
            "codebase",
            {"forbid": ["Node.js"], "action": "use", "scope": ["core"]},
        ),
    ],
)
def test_pattern_extracts_exact_rule(sentence, kind, subject, rule):
    (m,) = match_sentence(sentence)
    assert (m.kind, m.subject, m.rule) == (kind, subject, rule)


@pytest.mark.parametrize(
    "sentence",
    [
        "Should PostgreSQL be the only datastore?",
        "We discussed several options.",
        "Python code is formatted with ruff format and linted with ruff check.",
        "This is not allowed.",
        "It must not use globals.",
        "",
        "   ",
    ],
)
def test_no_claim_from_questions_pronouns_or_prose(sentence):
    assert match_sentence(sentence) == []


def test_one_phrase_one_claim_priority():
    # boundary-not-outside wins over forbid-must-not-be-used on the same words
    ms = match_sentence("Cloud SDKs must not be used outside adapters/.")
    assert kinds(ms) == [("boundary-not-outside", "boundary")]
    # only-use-for wins over require-we-will-use
    ms = match_sentence("We will use only Redis for caching.")
    assert kinds(ms) == [("only-use-for", "only")]


def test_two_claims_from_one_sentence():
    ms = match_sentence("PostgreSQL is the only datastore and services must not use MongoDB.")
    assert sorted(k for _, k in kinds(ms)) == ["forbid", "only"]


def test_term_helpers():
    assert split_list("another database, cache-as-database or document store") == [
        "database",
        "cache-as-database",
        "document store",
    ]
    assert clean_term("the adapters/ package") == "adapters/ package"
    assert clean_term("it") is None
    assert clean_term("  the database directly ") == "database"


@pytest.mark.parametrize(
    "sentence",
    ["no " * 3000, "only " * 3000, "all services must " * 800, "We will use " + "x " * 5000],
)
def test_long_adversarial_sentence_is_fast(sentence):
    import time

    t = time.monotonic()
    match_sentence(sentence)
    assert time.monotonic() - t < 3.0


def test_sentence_spans_handles_lines_bullets_fences_abbreviations():
    text = (
        "PostgreSQL is the only datastore, e.g. for\n"
        "orders. Services must not use MongoDB.\n"
        "\n"
        "* Do not use Redis.\n"
        "```\n"
        "Never import pandas.\n"
        "```\n"
        "| No SQL outside db/. |\n"
    )
    got = [text[a:b] for a, b in sentence_spans(text)]
    assert got == [
        "PostgreSQL is the only datastore, e.g. for\norders.",
        "Services must not use MongoDB.",
        "Do not use Redis.",
    ]


# ------------------------------------------------------------------ Claim model


def _prov():
    return Provenance(path="a.md", line_start=1, line_end=1, commit=WORKTREE, quote="q")


def test_claim_model_is_typed():
    c = Claim(
        id="ADR-0001.c1",
        kind="only",
        subject="datastore",
        rule={"only": ["pg"]},
        source=_prov(),
        decision_id="ADR-0001",
    )
    assert c.origin == "rule"
    with pytest.raises(ValidationError):
        Claim(id="x", kind="maybe", subject="s", rule={}, source=_prov(), decision_id="d")
    with pytest.raises(ValidationError):  # rule shape must match kind
        Claim(
            id="x",
            kind="forbid",
            subject="s",
            rule={"only": ["a"]},
            source=_prov(),
            decision_id="d",
        )
    with pytest.raises(ValidationError):
        Claim(
            id="x",
            kind="boundary",
            subject="s",
            rule={"target": ["a"]},
            source=_prov(),
            decision_id="d",
        )
    with pytest.raises(ValidationError):
        Claim(id="x", kind="free", subject=" ", rule={"text": "t"}, source=_prov(), decision_id="d")
    with pytest.raises(ValidationError):  # frozen
        c.kind = "forbid"  # type: ignore[misc]


@pytest.mark.parametrize(
    "kind,rule,ok",
    [
        ("forbid", {"forbid": ["x"]}, True),
        ("forbid", {"forbid": []}, False),
        ("forbid", {"forbid": "x"}, False),
        ("require", {"require": ["x"], "for": "y"}, True),
        ("only", {"only": [""]}, False),
        ("boundary", {"target": ["x"], "via": ["b"]}, True),
        ("boundary", {"target": ["x"], "allowed_in": []}, False),
        ("free", {"text": "x"}, True),
        ("free", {"text": ""}, False),
        ("nope", {}, False),
        ("only", ["x"], False),
    ],
)
def test_rule_errors(kind, rule, ok):
    assert (rule_errors(kind, rule) == []) is ok


# ------------------------------------------------------------------ offline mode on fixtures

EXPECTED_OFFLINE = {
    "ADR-0001": [("require", {"require": ["Architecture Decision Records"]})],
    "ADR-0002": [
        ("only", {"only": ["PostgreSQL"], "category": "datastore"}),
        (
            "forbid",
            {"forbid": ["database", "cache-as-database", "document store"], "action": "add"},
        ),
    ],
    "ADR-0003": [
        ("only", {"only": ["event bus"], "between": "Services"}),
        ("forbid", {"forbid": ["Synchronous service-to-service HTTP calls"]}),
    ],
    "ADR-0004": [("boundary", {"target": ["Cloud provider SDKs"], "allowed_in": ["adapters/"]})],
    "ADR-0005": [("require", {"require": ["FastAPI"]})],
    "ADR-0006": [("require", {"require": ["structlog"]})],
    "ADR-0007": [("require", {"require": ["server-rendered templates"]})],
    "ADR-0008": [("require", {"require": ["in-process LRU cache"]})],
    "ADR-0009": [],
    "ADR-0010": [],
    "ADR-0011": [("require", {"require": ["RabbitMQ"], "for": "message broker"})],
    "ADR-0012": [("require", {"require": ["UTF-8"]})],
}


def test_offline_claims_on_fixture_adrs(basic):
    repo, scan = basic
    sets = structure_scan(scan.decisions, repo, mode="offline")
    got = {cs.decision_id: [(c.kind, c.rule) for c in cs.claims] for cs in sets}
    assert got == EXPECTED_OFFLINE
    for cs in sets:
        assert cs.mode == "offline" and cs.unverified == []
        for n, c in enumerate(cs.claims, 1):
            assert c.id == f"{cs.decision_id}.c{n}"
            assert c.decision_id == cs.decision_id and c.origin == "rule" and c.pattern


def test_g1_every_offline_claim_verifies_and_is_ledgered(basic, tmp_path):
    """G1 grounding test: 100 % of offline claims verify at the ADR's commit and
    point inside the decision section; every result is a ledger row."""
    repo, scan = basic
    ledger = Ledger(tmp_path / "out", run_id="l006-offline")
    sets = structure_scan(scan.decisions, repo, mode="offline", ledger=ledger)
    by_id = {d.id: d for d in scan.decisions}
    claims = [c for cs in sets for c in cs.claims]
    assert len(claims) == 12
    for c in claims:
        d = by_id[c.decision_id]
        assert c.source.path == d.source.path and c.source.commit == d.source.commit == scan.head
        assert d.source.line_start <= c.source.line_start <= c.source.line_end <= d.source.line_end
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
    summary = ledger.write_summary()
    assert summary["by_check"]["G1"] == {"VERIFIED": 12, "MISMATCH": 0}
    assert summary["pass_rate"] == 1.0
    rows = [json.loads(x) for x in ledger.path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 12 and {r["subject"] for r in rows} == {c.id for c in claims}
    assert all(r["check_id"] == "G1" and r["status"] == "VERIFIED" for r in rows)


def test_quote_is_the_sentence_and_spans_lines(basic):
    repo, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0002")
    cs = structure_decision(d, repo, mode="offline")
    c2 = cs.claims[1]
    assert (c2.source.line_start, c2.source.line_end) == (17, 18)
    assert c2.source.quote.startswith("No service may add another database")
    assert c2.source.quote.endswith("supersedes this one.")


def test_emphasis_and_curly_quotes_in_decision_text_verify(basic):
    repo, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0012")
    (c,) = structure_decision(d, repo, mode="offline").claims
    assert "**UTF-8**" in c.source.quote
    assert verify_source_quote(repo, c.source).status == "VERIFIED"


def test_worktree_adr_claims_verify(make_repo):
    adr = "# 1. Datastore\n\n## Decision\n\nPostgreSQL is the only datastore.\n"
    repo = make_repo({"docs/adr/0001-db.md": adr})
    (repo / "docs/adr/0001-db.md").write_text(
        adr + "Services must not import pymongo.\n", encoding="utf-8"
    )
    (d,) = scan_adrs(repo).decisions
    assert d.source.commit == WORKTREE
    cs = structure_decision(d, repo, mode="offline")
    assert [c.kind for c in cs.claims] == ["only", "forbid"] and cs.unverified == []
    assert all(r.status == "VERIFIED" for r in cs.grounding)


# ------------------------------------------------------------------ front-matter hints

HINT_ADR = """---
status: accepted
driftwarden:
  forbid: [requests, urllib3]
  require:
    - httpx
  only: {datastore: [postgresql]}
  boundary:
    - {target: boto3, allowed_in: [adapters/]}
  free: Every service exposes /healthz
---
# Use httpx

## Decision Outcome

We will use httpx for HTTP calls.
"""


def test_front_matter_hints(make_repo):
    repo = make_repo({"docs/adr/0003-http.md": HINT_ADR})
    (d,) = scan_adrs(repo).decisions
    cs = structure_decision(d, repo, mode="offline")
    assert cs.unverified == []
    got = [(c.origin, c.kind, c.rule, c.source.line_start, c.source.line_end) for c in cs.claims]
    assert got == [
        ("rule", "require", {"require": ["httpx"], "for": "HTTP calls"}, 16, 16),
        ("hint", "forbid", {"forbid": ["requests", "urllib3"]}, 4, 4),
        # the hint's global "require httpx" is broader than the prose's "for HTTP calls"
        # and cites other lines: it is kept, never merged into the narrower claim
        ("hint", "require", {"require": ["httpx"]}, 5, 6),
        ("hint", "only", {"only": ["postgresql"], "category": "datastore"}, 7, 7),
        ("hint", "boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]}, 8, 9),
        ("hint", "free", {"text": "Every service exposes /healthz"}, 10, 10),
    ]
    assert not any("duplicate" in n for n in cs.notes)
    assert all(r.status == "VERIFIED" for r in cs.grounding)
    assert (
        cs.claims[4].source.quote == "  boundary:\n    - {target: boto3, allowed_in: [adapters/]}"
    )


def test_bad_hints_are_reported_not_dropped(make_repo):
    adr = HINT_ADR.replace(
        "  forbid: [requests, urllib3]\n", "  forbid: {deps: {nested: 1}}\n  maybe: [x]\n"
    ).replace(
        "  boundary:\n    - {target: boto3, allowed_in: [adapters/]}\n",
        "  boundary: [{target: boto3}]\n",
    )
    repo = make_repo({"docs/adr/0003-http.md": adr})
    (d,) = scan_adrs(repo).decisions
    cs = structure_decision(d, repo, mode="offline")
    reasons = sorted(u.reason for u in cs.unverified)
    assert len(reasons) == 3
    assert any("expected a list" in r for r in reasons)
    assert any("unknown hint kind 'maybe'" in r for r in reasons)
    assert any("allowed_in" in r for r in reasons)
    assert all(u.origin == "hint" and u.source is not None for u in cs.unverified)
    assert [u.id for u in cs.unverified] == ["ADR-0003.u1", "ADR-0003.u2", "ADR-0003.u3"]


def test_invalid_yaml_front_matter_with_hint_is_reported(make_repo):
    adr = (
        "---\nstatus: accepted\ndriftwarden:\n  forbid: [a, b\n---\n"
        "# T\n\nPostgreSQL is the only datastore.\n"
    )
    repo = make_repo({"docs/adr/0001-x.md": adr})
    (d,) = scan_adrs(repo).decisions
    cs = structure_decision(d, repo, mode="offline")
    assert [c.kind for c in cs.claims] == ["only"]
    (u,) = cs.unverified
    assert "not valid YAML" in u.reason


def test_no_hints_without_text():
    d = parse_adr(HINT_ADR, "docs/adr/0003-http.md", WORKTREE)
    assert [c.origin for c in extract_rule_claims(d).claims] == ["rule"]
    assert [c.origin for c in extract_rule_claims(d, HINT_ADR).claims].count("hint") == 5


# ------------------------------------------------------------------ LLM path


def test_mode_resolution():
    off = OfflineProvider()
    assert resolve_mode(None, None) == "offline"
    assert resolve_mode("auto", off) == "offline"
    assert resolve_mode("llm", off) == "llm"
    assert resolve_mode("offline", off) == "offline"
    with pytest.raises(ValueError):
        resolve_mode("llm", None)
    with pytest.raises(ValueError):
        resolve_mode("magic", off)


def test_offline_mode_never_calls_the_model(basic):
    repo, scan = basic
    calls = []
    prov = scripted(lambda a, r: calls.append(a) or [])
    structure_scan(scan.decisions, repo, mode="offline", provider=prov)
    structure_scan(scan.decisions, repo, provider=prov)  # auto + offline provider -> offline
    assert calls == []


def test_prompt_numbers_decision_lines_and_schema_is_valid(basic):
    _, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0002")
    p = build_prompt(d)
    assert "15 | PostgreSQL is the only datastore." in p
    assert "17 | No service may add another database" in p
    assert validate_json({"claims": []}, CLAIMS_SCHEMA) == []
    assert validate_json({"claims": [{"kind": "only"}]}, CLAIMS_SCHEMA)


def test_llm_faithful_claims_verify_merge_and_dedup(basic, tmp_path):
    repo, scan = basic
    offline = {cs.decision_id: cs for cs in structure_scan(scan.decisions, repo, mode="offline")}

    def faithful(adr_id, _req):
        out = [as_llm(c, subject=c.subject.upper()) for c in offline[adr_id].claims]  # dups
        d = next(d for d in scan.decisions if d.id == adr_id)
        if d.decision_text.strip():
            first = d.decision_text.split("\n")[0]
            out.append(
                {
                    "kind": "free",
                    "subject": "decision",
                    "rule": {"text": f"holds: {first[:40]}"},
                    "quote": first,
                    "line_start": d.source.line_start,
                    "line_end": d.source.line_start,
                }
            )
        return out

    ledger = Ledger(tmp_path, run_id="l006-llm")
    sets = structure_scan(
        scan.decisions, repo, mode="llm", provider=scripted(faithful), ledger=ledger
    )
    for cs in sets:
        assert cs.mode == "llm" and cs.unverified == []
        rule_claims = [c for c in cs.claims if c.origin == "rule"]
        llm_claims = [c for c in cs.claims if c.origin == "llm"]
        assert [(c.kind, c.rule) for c in rule_claims] == [
            (c.kind, c.rule) for c in offline[cs.decision_id].claims
        ]
        assert [c.kind for c in llm_claims] == ["free"]  # restated rule claims merged away
        assert [c.id for c in cs.claims] == [
            f"{cs.decision_id}.c{n}" for n in range(1, len(cs.claims) + 1)
        ]
    assert ledger.summary()["pass_rate"] == 1.0


TAMPERS = ("word", "shift_out", "outside_decision", "fabricated", "range_too_short")


def _tamper(claim_dict: dict, how: str, decision, rng: random.Random) -> dict:
    d = dict(claim_dict)
    if how == "word":
        words = d["quote"].split(" ")
        i = rng.randrange(len(words))
        words[i] = words[i] + "zz"
        d["quote"] = " ".join(words)
    elif how == "shift_out":
        d["line_start"] += 100
        d["line_end"] += 100
    elif how == "outside_decision":  # a real line, but from the title / context
        d["quote"] = decision.title
        d["line_start"] = d["line_end"] = 1
    elif how == "fabricated":
        d["quote"] = "MongoDB is the only datastore."
    elif how == "range_too_short":
        d["line_start"] = d["line_end"] = decision.source.line_start - 1 or 1
    return d


def test_g1_tampered_llm_quotes_are_caught_on_every_fixture_claim(basic, tmp_path):
    """G1 grounding test, LLM path: every tampered citation is caught and surfaces as
    an unverified claim with a reason; none becomes a claim."""
    repo, scan = basic
    offline = {cs.decision_id: cs for cs in structure_scan(scan.decisions, repo, mode="offline")}
    by_id = {d.id: d for d in scan.decisions}
    rng = random.Random(6)

    def tampered(adr_id, _req):
        out = []
        for c in offline[adr_id].claims:
            for how in TAMPERS:
                out.append(
                    _tamper(as_llm(c, kind="free", rule={"text": how}), how, by_id[adr_id], rng)
                )
        return out

    ledger = Ledger(tmp_path, run_id="l006-tamper")
    sets = structure_scan(
        scan.decisions, repo, mode="llm", provider=scripted(tampered), ledger=ledger
    )
    total = 0
    for cs in sets:
        assert [c.origin for c in cs.claims] == ["rule"] * len(offline[cs.decision_id].claims)
        assert len(cs.unverified) == len(TAMPERS) * len(offline[cs.decision_id].claims)
        for u in cs.unverified:
            total += 1
            assert u.origin == "llm" and u.reason and u.grounding is not None
            assert u.grounding.status == "MISMATCH" and u.grounding.subject == u.id
            assert u.source is not None and u.source.commit == scan.head
    assert total == 12 * len(TAMPERS)
    summary = ledger.write_summary()
    assert summary["by_check"]["G1"] == {"VERIFIED": 12, "MISMATCH": total}


def test_unverified_reasons_are_specific(basic):
    repo, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0002")

    def reply(_a, _r):
        base = {"kind": "only", "subject": "datastore", "rule": {"only": ["PostgreSQL"]}}
        return [
            {
                **base,
                "quote": "PostgreSQL is the only datastore.",
                "line_start": 14,
                "line_end": 14,
            },
            {
                **base,
                "quote": "PostgreSQL is the only datastore.",
                "line_start": 90,
                "line_end": 90,
            },
            {
                **base,
                "quote": "Operating many datastores is costly.",
                "line_start": 11,
                "line_end": 11,
            },
            {**base, "quote": "MySQL is the only datastore.", "line_start": 15, "line_end": 15},
            {
                **base,
                "kind": "forbid",
                "quote": "PostgreSQL is the only datastore.",
                "line_start": 15,
                "line_end": 15,
            },
        ]

    cs = structure_decision(d, repo, mode="llm", provider=scripted(reply))
    reasons = [u.reason for u in cs.unverified]
    assert len(reasons) == 5
    assert "quote not in cited range; found at lines 15-15" in reasons[0]
    assert "out of bounds" in reasons[1]
    assert "outside the decision text of ADR-0002 (lines 15-18)" in reasons[2]
    assert "not found in cited range or anywhere" in reasons[3]
    assert reasons[4].startswith("malformed rule: forbid rule needs 'forbid'")
    # the malformed one has a VERIFIED citation; the claim is still not accepted
    assert cs.unverified[4].grounding.status == "VERIFIED"
    assert [c.origin for c in cs.claims] == ["rule", "rule"]


def test_model_cannot_choose_path_or_commit(basic):
    repo, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0004")
    seen = []

    def reply(_a, req):
        seen.append(req.prompt)
        c = {
            "kind": "forbid",
            "subject": "x",
            "rule": {"forbid": ["boto3"]},
            "quote": "Business logic stays portable between providers.",
            "line_start": 17,
            "line_end": 17,
        }
        if len(seen) == 1:  # extra keys violate the schema and are retried
            return [{**c, "path": "README.md", "commit": "HEAD"}]
        return [c]

    cs = structure_decision(d, repo, mode="llm", provider=scripted(reply))
    assert len(seen) == 2 and "rejected" in seen[1]
    (u,) = cs.unverified
    assert u.source.path == d.source.path and u.source.commit == d.source.commit
    assert "outside the decision text" in u.reason


def test_llm_failure_keeps_rule_claims_and_says_why(basic):
    repo, scan = basic
    d = next(d for d in scan.decisions if d.id == "ADR-0002")
    cs = structure_decision(d, repo, mode="llm", provider=scripted(lambda a, r: "not json"))
    assert [c.origin for c in cs.claims] == ["rule", "rule"]
    assert any("LLM structuring failed for ADR-0002" in n for n in cs.notes)
    cs = structure_decision(d, repo, mode="llm", provider=OfflineProvider())
    assert len(cs.claims) == 2 and any("offline" in n for n in cs.notes)


def test_empty_llm_reply_and_empty_decision(basic):
    repo, scan = basic
    calls = []
    prov = scripted(lambda a, r: calls.append(a) or [])
    for d in scan.decisions:
        cs = structure_decision(d, repo, mode="llm", provider=prov)
        assert cs.unverified == []
    assert len(calls) == len(scan.decisions)


# ------------------------------------------------------------------ precision guards (L-006 fixes)


@pytest.mark.parametrize(
    "sentence,expected",
    [
        ("We will not use MongoDB.", [("forbid", {"forbid": ["MongoDB"], "action": "use"})]),
        ("We won't use MongoDB.", [("forbid", {"forbid": ["MongoDB"], "action": "use"})]),
        ("We do not use Redis.", [("forbid", {"forbid": ["Redis"], "action": "use"})]),
        ("We will avoid MongoDB.", [("forbid", {"forbid": ["MongoDB"]})]),
        ("Avoid MongoDB.", [("forbid", {"forbid": ["MongoDB"]})]),
        (
            "Services must use neither MongoDB nor Redis.",
            [("forbid", {"forbid": ["MongoDB", "Redis"], "action": "use"})],
        ),
        (
            "Don't use MongoDB, use PostgreSQL.",
            [
                ("forbid", {"forbid": ["MongoDB"], "action": "use"}),
                ("require", {"require": ["PostgreSQL"]}),
            ],
        ),
        ("Use of MongoDB is prohibited.", [("forbid", {"forbid": ["MongoDB"]})]),
        ("We will use PostgreSQL rather than MongoDB.", [("require", {"require": ["PostgreSQL"]})]),
        (
            "Services must not use MongoDB, and PostgreSQL is the only datastore.",
            [
                ("only", {"only": ["PostgreSQL"], "category": "datastore"}),
                ("forbid", {"forbid": ["MongoDB"], "action": "use"}),
            ],
        ),
    ],
)
def test_guarded_patterns_exact_rules(sentence, expected):
    assert [(m.kind, m.rule) for m in match_sentence(sentence)] == expected


@pytest.mark.parametrize(
    "sentence",
    [
        # hedges / conditions / temporary
        "Maybe we will use Redis.",
        "We will probably use Redis.",
        "If we need a cache, we will use Redis.",
        "Where possible, avoid MongoDB.",
        "We should try to avoid MongoDB.",
        "We do not use Redis yet.",
        "We won't use MongoDB for now.",
        # rejected / reported
        "Rejected: we will use MongoDB.",
        "The proposal that services must not use MongoDB was rejected.",
        "Some argued that services must not use MongoDB.",
        "Avoiding MongoDB was discussed and dropped.",
        # negated positives
        "We do not standardise on PostgreSQL.",
        "We have not standardised on PostgreSQL.",
        # alternatives, bounds, no choice
        "We will use Redis or Memcached.",
        "We will use either Redis or Memcached.",
        "PostgreSQL or MySQL is the only datastore.",
        "Services must use Python 3.11 or later.",
        "Services must use Python 3.11+.",
        "Chosen option: none.",
        "Chosen option: Redis or Memcached.",
    ],
)
def test_guarded_sentences_yield_no_claim(sentence):
    assert match_sentence(sentence) == [], [(m.pattern, m.rule) for m in match_sentence(sentence)]


def test_indented_code_is_skipped_but_list_continuation_is_prose():
    text = "Intro.\n\n    Never use Redis.\n    Do not use Kafka.\n\nMore.\n"
    assert [text[a:b] for a, b in sentence_spans(text)] == ["Intro.", "More."]
    text = "- First item.\n\n    Services must not use MongoDB.\n"
    assert [text[a:b] for a, b in sentence_spans(text)] == [
        "First item.",
        "Services must not use MongoDB.",
    ]


def test_dedup_keeps_rule_claims_that_differ_in_qualifiers_or_subject(make_repo):
    body = (
        "Services must not use MongoDB in domain/. Services must not use MongoDB in reports/.\n"
        "Services must not use MongoDB. Handlers must not use MongoDB.\n"
        "Services must not use MongoDB.\n"  # exact restatement: merged
    )
    repo = make_repo({"docs/adr/0001-x.md": f"# 1. X\n\n## Decision\n\n{body}"})
    (d,) = scan_adrs(repo).decisions
    cs = structure_decision(d, repo, mode="offline")
    assert [(c.subject, c.rule.get("scope")) for c in cs.claims] == [
        ("services", ["domain/"]),
        ("services", ["reports/"]),
        ("services", None),
        ("handlers", None),
    ]
    assert "1 duplicate claim(s) merged" in cs.notes


def test_llm_claim_with_conflicting_qualifier_is_not_merged(make_repo):
    q = "Services must not use MongoDB in domain/."
    repo = make_repo({"docs/adr/0001-x.md": f"# 1. X\n\n## Decision\n\n{q}\n"})
    (d,) = scan_adrs(repo).decisions
    line = d.source.line_start
    props = [
        {"kind": "forbid", "subject": "svc", "rule": {"forbid": ["mongodb"]}, "quote": q,
         "line_start": line, "line_end": line},
        {"kind": "forbid", "subject": "svc", "rule": {"forbid": ["mongodb"], "scope": ["api/"]},
         "quote": q, "line_start": line, "line_end": line},
    ]  # fmt: skip
    cs = structure_decision(d, repo, mode="llm", provider=scripted(lambda a, r: props))
    assert [(c.origin, c.rule.get("scope")) for c in cs.claims] == [
        ("rule", ["domain/"]),
        ("llm", ["api/"]),
    ]
    assert "1 duplicate claim(s) merged" in cs.notes


def test_duplicate_hint_key_is_reported_with_its_lines(make_repo):
    text = (
        "---\ndriftwarden:\n  forbid: [alpha]\n  forbid: [beta]\n---\n"
        "# 1. X\n\n## Decision\n\nWe will use Kafka.\n"
    )
    repo = make_repo({"docs/adr/0001-x.md": text})
    (d,) = scan_adrs(repo).decisions
    cs = structure_decision(d, repo, mode="offline")
    assert [c.rule for c in cs.claims if c.origin == "hint"] == [{"forbid": ["beta"]}]
    (u,) = cs.unverified
    assert u.rule == ["alpha"] and "duplicate key 'forbid'" in u.reason
    assert (u.source.line_start, u.source.line_end) == (3, 3)
    assert u.source.quote == "  forbid: [alpha]"


def test_bom_and_deeply_nested_front_matter():
    bom = "﻿---\ndriftwarden:\n  forbid: [mongodb]\n---\n# 1. X\n\n## Decision\n\nWe use Kafka.\n"
    d = parse_adr(bom, "docs/adr/0001-x.md", WORKTREE)
    hints = [c.rule for c in extract_rule_claims(d, bom).claims if c.origin == "hint"]
    assert hints == [{"forbid": ["mongodb"]}]
    deep = "---\ndriftwarden:\n  forbid: " + "[" * 2000 + "x" + "]" * 2000 + "\n---\n# 1. X\n"
    d = parse_adr(deep, "docs/adr/0001-x.md", WORKTREE)
    res = extract_rule_claims(d, deep)  # must not raise
    assert res.claims == [] and "could not be read" in res.rejected[0].reason


def test_schema_allows_out_of_range_lines_so_g1_reports_them():
    item = {"kind": "free", "subject": "s", "rule": {"text": "t"}, "quote": "q"}
    for a in (0, -1):
        claims = [{**item, "line_start": a, "line_end": a}]
        assert validate_json({"claims": claims}, CLAIMS_SCHEMA) == []


# ------------------------------------------------------------------ PR #13 review (Codex P2s)


def test_never_keeps_its_location_qualifier():
    (m,) = match_sentence("Never import pandas in request handlers.")
    assert m.rule == {"forbid": ["pandas"], "action": "import", "scope": ["request handlers"]}
    (m,) = match_sentence("We never use ORMs.")
    assert m.rule == {"forbid": ["ORMs"], "action": "use"}


@pytest.mark.parametrize(
    "sentence",
    [
        "We use no external database.",
        "We will use no ORM.",
        "Services must use none of the cloud SDKs.",
        "We will use nothing but stdlib.",
        "PostgreSQL is not the only datastore.",
    ],
)
def test_negative_noun_phrase_is_not_a_require_or_only(sentence):
    assert [m for m in match_sentence(sentence) if m.kind in ("require", "only")] == []


HINT_FM = "---\n{hint}\n---\n# 1. X\n\n## Decision\n\nPostgreSQL is the only datastore.\n"


def _hint_run(make_repo, hint, name="h"):
    repo = make_repo({"docs/adr/0001-x.md": HINT_FM.format(hint=hint)}, name=name)
    (d,) = scan_adrs(repo).decisions
    return repo, structure_decision(d, repo, mode="offline")


def test_hint_dedup_is_subject_aware(make_repo):
    _, cs = _hint_run(
        make_repo, "driftwarden:\n  require: {services: [structlog], handlers: [structlog]}"
    )
    assert [(c.subject, c.rule) for c in cs.claims if c.origin == "hint"] == [
        ("services", {"require": ["structlog"]}),
        ("handlers", {"require": ["structlog"]}),
    ]


@pytest.mark.parametrize(
    "hint",
    [
        "driftwarden:\n  boundary: [{target: [], allowed_in: [adapters/]}]",
        "driftwarden:\n  boundary: [{target: [''], allowed_in: [adapters/]}]",
        "driftwarden:\n  boundary: [{target: boto3, allowed_in: [], subject: '  '}]",
        "driftwarden:\n  boundary: [{target: {a: 1}, via: null}]",
        "driftwarden:\n  boundary: []",
        "driftwarden:\n  boundary: [null, 3, [x]]",
        "driftwarden:\n  require: {'  ': [structlog]}",
        "driftwarden:\n  require: {null: [x], 3: [y]}",
        "driftwarden:\n  only: {'': [pg]}",
        "driftwarden:\n  only: {datastore: []}",
        "driftwarden:\n  forbid: {}",
        "driftwarden:\n  forbid: [[a], {b: c}]",
        "driftwarden:\n  free: ['', '   ']",
        "driftwarden:\n  free: []",
        "driftwarden:\n  ? [complex, key]\n  : [x]",
        "driftwarden: {forbid: [x]}\n'driftwarden': {forbid: [y]}",
        "driftwarden: []",
        "driftwarden: ''",
    ],
)
def test_malformed_hints_never_raise_and_are_reported(make_repo, hint):
    repo, cs = _hint_run(make_repo, hint)
    assert [c.kind for c in cs.claims if c.origin == "rule"] == ["only"]
    for c in cs.claims:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
    for u in cs.unverified:
        assert u.origin == "hint" and u.reason


def test_empty_boundary_target_is_reported_not_raised(make_repo):
    _, cs = _hint_run(
        make_repo, "driftwarden:\n  boundary: [{target: [], allowed_in: [adapters/]}]"
    )
    (u,) = cs.unverified
    assert "target" in u.reason


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_root_key_cites_the_block_lines(make_repo, quote):
    _, cs = _hint_run(make_repo, f"{quote}driftwarden{quote}:\n  {quote}forbid{quote}: [mongodb]")
    (h,) = [c for c in cs.claims if c.origin == "hint"]
    assert (h.source.line_start, h.source.line_end) == (3, 3)
    assert h.source.quote == f"  {quote}forbid{quote}: [mongodb]"


def test_unlocatable_hint_block_is_unverified_not_cited_as_dashes(make_repo):
    # a flow mapping at the root: the key exists in YAML but not at the start of a line
    _, cs = _hint_run(make_repo, "{driftwarden: {forbid: [mongodb]}}")
    assert not [c for c in cs.claims if c.origin == "hint"]
    (u,) = cs.unverified
    assert "cannot locate" in u.reason
    assert all(c.source.quote.strip() != "---" for c in cs.claims)


def test_whitespace_subject_from_llm_is_unverified_not_a_crash(make_repo):
    q = "PostgreSQL is the only datastore."
    repo = make_repo({"docs/adr/0001-x.md": f"# 1. X\n\n## Decision\n\n{q}\n"})
    (d,) = scan_adrs(repo).decisions
    line = d.source.line_start
    props = [
        {"kind": "free", "subject": "   ", "rule": {"text": "t"}, "quote": q,
         "line_start": line, "line_end": line},
        {"kind": "free", "subject": "ok", "rule": {"text": "u"}, "quote": q,
         "line_start": line, "line_end": line},
    ]  # fmt: skip
    cs = structure_decision(d, repo, mode="llm", provider=scripted(lambda a, r: props))
    assert [c.subject for c in cs.claims if c.origin == "llm"] == ["ok"]
    (u,) = cs.unverified
    assert u.origin == "llm" and "subject" in u.reason


@pytest.mark.parametrize(
    "body",
    [
        "````md\n```\nNever use Redis.\n```\n````\n\nNo SQL outside repo/.",
        "~~~~\n~~~\nNever use Redis.\n~~~\n~~~~\n\nNo SQL outside repo/.",
        "```\n~~~\nNever use Redis.\n~~~\n```\n\nNo SQL outside repo/.",
        "```\nNever use Redis.\n``` not a close\nNever use Kafka.\n```\n\nNo SQL outside repo/.",
    ],
)
def test_fences_close_only_on_a_matching_fence(body):
    spans = [body[a:b] for a, b in sentence_spans(body)]
    assert spans == ["No SQL outside repo/."], spans


# ------------------------------------------------------------------ PR #13 review round 2


@pytest.mark.parametrize(
    "sentence,expected",
    [
        (
            "Services must not use Redis and PostgreSQL is the only datastore.",
            [
                ("only", {"only": ["PostgreSQL"], "category": "datastore"}),
                ("forbid", {"forbid": ["Redis"], "action": "use"}),
            ],
        ),
        (
            "Services must not use Redis and must use PostgreSQL.",
            [("forbid", {"forbid": ["Redis"], "action": "use"})],
        ),
        (
            "Services must not use Redis but may use Memcached.",
            [("forbid", {"forbid": ["Redis"], "action": "use"})],
        ),
        # genuine lists stay lists
        (
            "Services must not use Redis and MongoDB.",
            [("forbid", {"forbid": ["Redis", "MongoDB"], "action": "use"})],
        ),
        (
            "Services must not use Redis and MongoDB in domain/.",
            [("forbid", {"forbid": ["Redis", "MongoDB"], "action": "use", "scope": ["domain/"]})],
        ),
    ],
)
def test_and_starts_a_new_clause_only_before_a_verb(sentence, expected):
    assert [(m.kind, m.rule) for m in match_sentence(sentence)] == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "Services must not import pandas except in tests.",
        "Never use Redis except in tests.",
        "No service may use MongoDB other than the reporting job.",
        "Do not use boto3 apart from the adapters.",
        "Services must use structlog, save for legacy jobs.",
        "MongoDB is forbidden, with the exception of analytics.",
    ],
)
def test_exception_clause_yields_no_unconditional_claim(sentence):
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Services communicate only via Kafka or RabbitMQ.",
        "Services must communicate exclusively through gRPC or REST.",
        "All database access must go through the repository layer or the cache.",
        "We use only Redis or Memcached for caching.",
    ],
)
def test_allowed_alternatives_are_not_cut_short(sentence):
    assert match_sentence(sentence) == [], [(m.pattern, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence,expected",
    [
        (
            "Services must not import boto3 outside adapters/.",
            [
                (
                    "boundary",
                    {"target": ["boto3"], "allowed_in": ["adapters/"], "actor": ["Services"]},
                )
            ],
        ),
        (
            "Never use boto3 outside of `adapters/`.",
            [("boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]})],
        ),
        (
            "No module may import boto3 outside adapters/.",
            [("boundary", {"target": ["boto3"], "allowed_in": ["adapters/"]})],
        ),
    ],
)
def test_active_ban_outside_z_is_a_boundary(sentence, expected):
    assert [(m.kind, m.rule) for m in match_sentence(sentence)] == expected


# The principle: a match must never silently drop a scope, qualifier or list member
# that is in the sentence. Each of these used to yield a broader / narrower claim.
DROPPED_QUALIFIER = [
    "PostgreSQL and Redis are the only datastores.",  # list head before the subject
    "PostgreSQL, Redis and Kafka are the only message stores.",
    "Redis and MongoDB must not be used.",
    "Services and handlers must not use MongoDB.",
    "In adapters/, services must not use MongoDB.",  # leading location
    "Services must use structlog in production.",  # trailing location
    "No module may import boto3 in handlers.",
    "Services must not import pandas in handlers in production.",  # second scope
    "Database drivers may only be imported from the persistence layer in production.",
    "We will use Kafka as the broker within the payments domain.",
]


@pytest.mark.parametrize("sentence", DROPPED_QUALIFIER)
def test_no_match_drops_a_qualifier_or_list_member(sentence):
    assert match_sentence(sentence) == [], [(m.pattern, m.rule) for m in match_sentence(sentence)]


def test_qualifier_guards_keep_ordinary_claims():
    # connectives and clause-level "and" are not list heads; captured scopes are kept
    for s, kinds_ in [
        ("Therefore, services must not use MongoDB.", ["forbid"]),
        ("From today, services must not use MongoDB.", ["forbid"]),
        ("PostgreSQL is the only datastore and services must not use MongoDB.", ["only", "forbid"]),
        ("Services must not use MongoDB in domain/.", ["forbid"]),
        ("Don't use MongoDB, use PostgreSQL.", ["forbid", "require"]),
    ]:
        assert [m.kind for m in match_sentence(s)] == kinds_, s


def test_indented_code_inside_a_list_item_is_skipped():
    text = "- Item one.\n\n      Never use Redis.\n\n  Services must not use MongoDB.\n"
    assert [text[a:b] for a, b in sentence_spans(text)] == [
        "Item one.",
        "Services must not use MongoDB.",
    ]
    text = "1. Item one.\n\n       Never use Redis.\n"  # content column 3, code at 7
    assert [text[a:b] for a, b in sentence_spans(text)] == ["Item one."]


@pytest.mark.parametrize(
    "hint",
    [
        "driftwarden:\n  forbid: [alpha]\ndriftwarden:\n  forbid: [beta]",
        "driftwarden:\n  forbid: [alpha]\n'driftwarden':\n  forbid: [beta]",
        "DriftWarden:\n  forbid: [alpha]\ndriftwarden:\n  forbid: [beta]",
    ],
)
def test_several_root_hint_blocks_are_never_cited_from_the_wrong_block(make_repo, hint):
    """YAML keeps the last of exact duplicates (reported) and both case variants: each
    claim cites the lines of the block it really came from."""
    _, cs = _hint_run(make_repo, hint)
    got = {c.rule["forbid"][0]: c.source.line_start for c in cs.claims if c.origin == "hint"}
    if hint.startswith("DriftWarden"):
        assert got == {"alpha": 3, "beta": 5} and cs.unverified == []
    else:
        assert got == {"beta": 5}
        assert any("duplicate key 'driftwarden'" in u.reason for u in cs.unverified)


# ------------------------------------------------------------------ round 4: clause coverage


@pytest.mark.parametrize(
    "sentence",
    [
        # Codex round 4
        "PostgreSQL is the only datastore for analytics.",
        # ~15 more: leftover actor / purpose / location / member / time / manner clauses
        "PostgreSQL is the only datastore in production.",
        "PostgreSQL is the only datastore (for analytics).",
        "PostgreSQL is the only datastore — for analytics.",
        "For analytics, PostgreSQL is the only datastore.",
        "In production, services must not use MongoDB.",
        "We will use Kafka for billing events only.",
        "Services must not use Redis for sessions.",
        "Redis and Memcached must not be used.",
        "Kafka & RabbitMQ are the only brokers.",
        "Both Kafka and RabbitMQ are our only brokers.",
        "Services must not use Redis on mobile.",
        "Only structlog may be used for logging in the API.",
        "Services must go through the gateway on weekdays.",
        "Services must not import boto3 outside adapters/ in production.",
        "We will use Kafka as the broker for all new services.",
    ],
)
def test_clause_coverage_drops_a_claim_that_leaves_text_uncaptured(sentence):
    assert match_sentence(sentence) == [], [(m.pattern, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence,expected",
    [
        # Codex round 4 (b): a conjunctive "only" subject keeps every member
        (
            "Only Redis and Memcached may be used for caching.",
            [("only", {"only": ["Redis", "Memcached"], "category": "caching"})],
        ),
        # (d) a conjunctive allowed list is captured whole
        (
            "No SQL outside repo/ and db/.",
            [("boundary", {"target": ["SQL"], "allowed_in": ["repo/", "db/"]})],
        ),
        # (e) the actor of "never" is the claim's subject
        (
            "Request handlers never import pandas.",
            [("forbid", {"forbid": ["pandas"], "action": "import"})],
        ),
        # a purpose the pattern captures is kept on the claim ("for"), not dropped
        (
            "Services must use structlog for audit events.",
            [("require", {"require": ["structlog"], "for": "audit events"})],
        ),
        (
            "We will use Terraform for new infrastructure.",
            [("require", {"require": ["Terraform"], "for": "new infrastructure"})],
        ),
        # a trailing manner adverb is captured, not dropped
        (
            "Never call the billing API synchronously.",
            [("forbid", {"forbid": ["billing API"], "action": "call", "manner": "synchronously"})],
        ),
        # universal / boilerplate leftovers do not narrow anything
        (
            "Kafka will be the sole message broker for all services.",
            [("only", {"only": ["Kafka"], "category": "message broker"})],
        ),
        (
            "From today, services must not use MongoDB.",
            [("forbid", {"forbid": ["MongoDB"], "action": "use"})],
        ),
    ],
)
def test_clause_coverage_captures_or_keeps(sentence, expected):
    got = [(m.kind, m.rule) for m in match_sentence(sentence)]
    assert got == expected


def test_never_actor_is_the_subject():
    (m,) = match_sentence("Request handlers never import pandas.")
    assert m.subject == "request handlers"


def test_hint_keys_differing_only_in_case_are_reported(make_repo):
    _, cs = _hint_run(make_repo, "driftwarden:\n  forbid: [a]\n  Forbid: [b]")
    assert not [c for c in cs.claims if c.origin == "hint"]
    assert len(cs.unverified) == 2
    assert all("differing only in case" in u.reason for u in cs.unverified)
    assert {u.source.line_start for u in cs.unverified} == {3, 4}


def test_allowed_list_kept_whole_when_captured_whole():
    # an allowed LOCATION list ("in X or Y" = allowed in either) is captured whole
    for s in (
        "Only adapters/ or infra/ may import boto3.",
        "Cloud SDKs may be imported only from adapters/ or infra/.",
        "Cloud SDKs may be imported only from adapters/ and infra/.",
    ):
        (m,) = match_sentence(s)
        assert m.rule["allowed_in"] == ["adapters/", "infra/"], s
    for s in ("No SQL outside repo/ or db/.", "No SQL outside repo/ and db/."):
        (m,) = match_sentence(s)
        assert m.rule == {"target": ["SQL"], "allowed_in": ["repo/", "db/"]}, s
    (m,) = match_sentence("Services communicate only via Kafka.")
    assert m.rule == {"only": ["Kafka"], "between": "Services"}
