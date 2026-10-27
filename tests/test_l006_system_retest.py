"""L-006 system RE-TEST (round 2, independent). No network, no real key.

Round 1 (tests/test_l006_system.py) found D1-D14; Opus fixed them (that file is
unchanged). This file (a) tries to break the fixes (D12 dedup, negation/hedge/
conditional guards, code skipping, BOM, duplicate-key loader, new forbid
recall patterns) and (b) pins what held, so a later change cannot regress it.

Tests marked ``xfail(strict=True)`` document DEFECTS found in round 2 (ids R1+);
they turn red (XPASS) when the defect is fixed, so the marker must then be
removed. Every defect test's docstring answers the three "how to read a red
test" questions: 1. which requirement, 2. where in the code, 3. how bad.

Oracle policy: precision over recall. A defect is only filed where the library
emits a claim whose meaning is opposite to, broader than, or unrelated to the
sentence (a false VIOLATED later), or where a real claim silently vanishes. A
missed rule is a recall gap and is not filed.
"""

# ruff: noqa: E501 - xfail reasons are single-line defect descriptions
from __future__ import annotations

import itertools
import json
import re
import time

import pytest

from driftwarden.claims import structure_decision
from driftwarden.claims.rules import match_sentence, sentence_spans
from driftwarden.discover.adr import scan_adrs
from driftwarden.llm import OfflineProvider, RetryPolicy

# --------------------------------------------------------------------------- helpers


def adr(decision: str, *, title: str = "1. Test", eol: str = "\n") -> str:
    text = f"# {title}\n\n## Status\n\nAccepted\n\n## Decision\n\n{decision}\n\n## Consequences\n\nNone.\n"
    return text.replace("\n", eol)


def fm(hint: str, decision: str = "Hello.") -> str:
    return f"---\n{hint}\n---\n" + adr(decision)


_N = itertools.count()


def run(make_repo, text: str, *, llm=None):
    repo = make_repo({"docs/adr/0001-x.md": text}, name=f"repo{next(_N)}")
    (d,) = scan_adrs(repo).decisions
    if llm is None:
        return d, structure_decision(d, repo, mode="offline")
    return d, structure_decision(d, repo, mode="llm", provider=scripted(llm))


def scripted(claims) -> OfflineProvider:
    return OfflineProvider(
        responder=lambda _req: json.dumps({"claims": claims}),
        retry=RetryPolicy(max_attempts=1, sleep=lambda _s: None),
    )


def lc(kind, subject, rule, quote, line):
    return {
        "kind": kind,
        "subject": subject,
        "rule": rule,
        "quote": quote,
        "line_start": line,
        "line_end": line,
    }


def kinds(sentence: str) -> list[str]:
    return [m.kind for m in match_sentence(sentence)]


def claims_of(sentence: str):
    return match_sentence(sentence)


def cites(cs, line: int) -> bool:
    """A claim (verified or reported as unverified) that cites ``line`` exists."""
    return any(
        c.source.line_start <= line <= c.source.line_end for c in [*cs.claims, *cs.unverified]
    )


# =========================================================================== 1. D12 dedup


def test_D12_rule_vs_rule_stays_strict_scope_action_subject(make_repo):
    _, cs = run(
        make_repo,
        adr(
            "Services must not use Redis in domain/.\n"
            "Services must not use Redis in reports/.\n"
            "Handlers must not use Redis in domain/.\n"
            "Services must not import Redis in domain/.\n"
        ),
    )
    assert len(cs.claims) == 4 and cs.notes == []


def test_D12_exact_restatement_by_llm_merges_and_is_reported(make_repo):
    text = adr("Services must not import `requests` or `urllib3`.")
    d, _ = run(make_repo, text)
    q = "Services must not import `requests` or `urllib3`."
    _, cs = run(
        make_repo,
        text,
        llm=[
            lc(
                "forbid",
                "svc",
                {"forbid": ["URLLIB3", "Requests"], "action": "import"},
                q,
                d.source.line_start,
            )
        ],
    )
    assert len(cs.claims) == 1 and cs.claims[0].origin == "rule"
    assert any("duplicate" in (g.subject or "") for g in cs.grounding)
    assert any("duplicate" in n for n in cs.notes)


def test_D12_llm_claim_with_conflicting_qualifier_is_kept_separate(make_repo):
    text = adr("Services must not use Redis in domain/.\nRedis is also banned in tests/.\n")
    d, _ = run(make_repo, text)
    rule = {"forbid": ["redis"], "scope": ["tests/"]}
    _, cs = run(
        make_repo,
        text,
        llm=[
            lc(
                "forbid",
                "codebase",
                rule,
                "Redis is also banned in tests/.",
                d.source.line_start + 1,
            )
        ],
    )
    assert [c.origin for c in cs.claims].count("llm") == 1


def test_D12_hint_distinct_category_and_distinct_free_text_are_kept(make_repo):
    _, cs = run(
        make_repo,
        fm(
            "driftwarden:\n  only:\n    datastore: [postgres]\n    queue: [postgres]\n  free: [alpha, beta]"
        ),
    )
    assert len(cs.claims) == 4


@pytest.mark.parametrize(
    "decision,quote,llm_rule,kind",
    [
        (
            "Services must not use Redis in domain/.\nRedis is banned everywhere in this codebase.\n",
            "Redis is banned everywhere in this codebase.",
            {"forbid": ["redis"]},
            "forbid",
        ),
        (
            "Services must not import Redis.\nRedis is forbidden everywhere.\n",
            "Redis is forbidden everywhere.",
            {"forbid": ["redis"]},
            "forbid",
        ),
        (
            "We will use Redis for caching.\nRedis is mandatory throughout.\n",
            "Redis is mandatory throughout.",
            {"require": ["redis"]},
            "require",
        ),
    ],
)
def test_R1_broader_llm_claim_is_not_swallowed_by_narrower_rule_claim(
    make_repo, decision, quote, llm_rule, kind
):
    """1. D12 contract: a distinct claim must never vanish by de-duplication. An LLM claim
    that states the key terms with NO scope/action/for ("banned everywhere") is a *broader*
    claim than the rule-library claim it is compared with ("... in domain/"); keeping only
    the narrower one silently weakens the ADR. 2. Code: claims/structure.py _duplicate():
    for non-rule/rule pairs it returns all(qo[k] == v for k, v in qn.items() if k in qo), so a
    qualifier present in ``old`` but absent in ``new`` is treated as a wildcard in the wrong
    direction (only new-narrower-than-old is a safe merge). 3. HIGH for the judge: the
    surviving claim cites only the first line; the broader requirement is lost with just a
    note count ('1 duplicate claim(s) merged')."""
    d, _ = run(make_repo, adr(decision))
    s = d.source.line_start
    _, cs = run(make_repo, adr(decision), llm=[lc(kind, "codebase", llm_rule, quote, s + 1)])
    assert cites(cs, s + 1), [(c.id, c.rule, c.source.line_start) for c in cs.claims]


def test_R1b_global_hint_not_swallowed_by_scoped_rule_claim(make_repo):
    """1. As R1, for the explicit machine-readable `driftwarden:` block (the author's
    stated rule). 2. Code: structure.py _duplicate() (hint is not 'rule', so the lenient
    branch applies). 3. HIGH: hint says forbid redis everywhere, ADR prose says only in
    domain/; the hint disappears and the weaker claim is checked."""
    _, cs = run(
        make_repo, fm("driftwarden:\n  forbid: [redis]", "Services must not use Redis in domain/.")
    )
    assert any(c.origin == "hint" for c in cs.claims), [(c.origin, c.rule) for c in cs.claims]


@pytest.mark.parametrize(
    "hint",
    [
        "driftwarden:\n  forbid:\n    payments: [redis]\n    reports: [redis]",
        "driftwarden:\n  boundary:\n    - {target: boto3, allowed_in: [adapters/], subject: aws}\n    - {target: boto3, allowed_in: [adapters/], subject: s3}",
    ],
)
def test_R2_hint_claims_with_different_subjects_are_both_kept(make_repo, hint):
    """1. The hint documents `forbid: {subject: [items]}` and boundary `subject`; two
    subjects are two claims. 2. Code: structure.py _duplicate(): subject is compared only
    for rule/rule pairs; hint/hint pairs fall into the lenient branch where subject is
    ignored. 3. HIGH: an author's explicit per-module declaration silently collapses to the
    first module; the second is never checked."""
    _, cs = run(make_repo, fm(hint))
    assert len(cs.claims) == 2, [(c.subject, c.rule) for c in cs.claims]


def test_R3_llm_claims_with_different_subjects_are_both_kept(make_repo):
    """1. SYSTEM_PROMPT: 'subject names what the claim is about, e.g. module:payments'; two
    modules are two claims. 2. Code: structure.py _duplicate() ignores subject for any pair
    that is not rule/rule. 3. MEDIUM-HIGH: the LLM path is the one that needs subject to
    carry scope, and exactly there it is discarded."""
    text = adr("Redis is off limits for payments.\nRedis is off limits for reports.\n")
    d, _ = run(make_repo, text)
    s = d.source.line_start
    _, cs = run(
        make_repo,
        text,
        llm=[
            lc(
                "forbid",
                "module:payments",
                {"forbid": ["redis"]},
                "Redis is off limits for payments.",
                s,
            ),
            lc(
                "forbid",
                "module:reports",
                {"forbid": ["redis"]},
                "Redis is off limits for reports.",
                s + 1,
            ),
        ],
    )
    assert len([c for c in cs.claims if c.origin == "llm"]) == 2


# =========================================================================== 2. guards that held


@pytest.mark.parametrize(
    "sentence",
    [
        "Services must not use X unless approved.",
        "Do not use Redis unless approved.",
        "Never use Redis unless approved.",
        "No service may use Redis unless approved.",
        "Services must not NOT use X.",
        "We will not not use Redis.",
        "Don't not use Redis.",
        "Not all services must use Redis.",
        "The team did not agree that services must use Redis.",
        "The team never agreed that services must use Redis.",
        "We do not believe services must use Redis.",
        "We do not use Redis yet.",
        "We do not use Redis (for now).",
        "We cannot use MongoDB for now.",
        "Redis is no longer the only datastore.",
        "Redis is not our only datastore.",
        "Redis will not be the only datastore.",
        "Redis is the only datastore for now.",
        "Redis is the only datastore, which is rejected.",
        "Redis is the only datastore that was not adopted.",
        "Redis is the only datastore if we choose option 2.",
        "Services must use Redis, which was rejected.",
        "Services must use Redis (rejected).",
        "It was claimed that services must use Redis.",
        "We will use Redis or Memcached.",
        "We will use either A or B.",
        "Services must use Python 3.11 or later.",
        "Kafka or RabbitMQ is the only broker.",
        "Chosen option: none.",
        "We will use Redis if possible.",
        "We will use Redis when needed.",
        "We will use Redis initially.",
        "We decided not to use Redis.",
        "We no longer use Redis.",
        "We are not going to use Redis.",
        "We will not be using Redis.",
        "We did not use Redis.",
        "Maybe we will use Redis.",
        "We might avoid MongoDB.",
        "Where possible, avoid MongoDB.",
        "Avoid MongoDB if possible.",
        "Avoid MongoDB for now.",
        "Should we avoid MongoDB?",
        "Rejected: we will not use MongoDB.",
        "Proposed: we will not use MongoDB.",
        "Option 1: we will not use MongoDB.",
        "We will not use MongoDB (rejected).",
    ],
)
def test_guards_that_held_yield_no_claim(sentence):
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    "sentence,kind,terms",
    [
        ("Services must use neither MongoDB nor Redis.", "forbid", ["MongoDB", "Redis"]),
        ("We will use neither MongoDB nor Redis.", "forbid", ["MongoDB", "Redis"]),
        ("We will not use MongoDB or Redis.", "forbid", ["MongoDB", "Redis"]),
        ("We will not use A, B or C.", "forbid", ["A", "B", "C"]),
        ("Avoid MongoDB and Redis.", "forbid", ["MongoDB", "Redis"]),
        ("We won’t use MongoDB.", "forbid", ["MongoDB"]),
        ("We don’t use MongoDB.", "forbid", ["MongoDB"]),
        ("We DO NOT use MongoDB.", "forbid", ["MongoDB"]),
        ("We cannot use MongoDB.", "forbid", ["MongoDB"]),
        ("We can not use MongoDB.", "forbid", ["MongoDB"]),
        ("We will avoid using MongoDB.", "forbid", ["MongoDB"]),
        ("We shall avoid MongoDB.", "forbid", ["MongoDB"]),
        ("We must avoid MongoDB.", "forbid", ["MongoDB"]),
        ("Avoid importing pandas in request handlers.", "forbid", ["pandas"]),
        ("We never use Redis.", "forbid", ["Redis"]),
        ("Never use Redis.", "forbid", ["Redis"]),
    ],
)
def test_new_forbid_recall_paraphrases_have_right_polarity_and_terms(sentence, kind, terms):
    (m,) = match_sentence(sentence)
    assert m.kind == kind and m.rule["forbid"] == terms


def test_negative_plus_positive_clauses_are_two_opposite_claims():
    ms = match_sentence("We will not use MongoDB, but we will use Redis.")
    assert [(m.kind, m.rule.get("forbid") or m.rule.get("require")) for m in ms] == [
        ("forbid", ["MongoDB"]),
        ("require", ["Redis"]),
    ]
    ms = match_sentence("We will use Memcached and will not use Redis.")
    assert sorted((m.kind, tuple(m.rule.get("forbid") or m.rule.get("require"))) for m in ms) == [
        ("forbid", ("Redis",)),
        ("require", ("Memcached",)),
    ]


def test_dont_use_x_use_y_does_not_forbid_the_alternative():
    ms = match_sentence("Don't use MongoDB, use PostgreSQL.")
    assert [(m.kind, m.rule.get("forbid") or m.rule.get("require")) for m in ms] == [
        ("forbid", ["MongoDB"]),
        ("require", ["PostgreSQL"]),
    ]


def test_opposite_kinds_fuzz_neither_nor_and_must_vs_must_not():
    """Cross product of subject x (modal | negated modal) x verb: a negated modal never
    yields require/only; a plain 'must/will use' never yields forbid. (The negated
    forms that DO leak are filed as R4; this table excludes them.)"""
    subj = ["Services", "We", "The team", "All services", "Handlers"]
    neg = [
        "must not",
        "should not",
        "will not",
        "won't",
        "do not",
        "cannot",
        "may not",
        "shall never",
        "must never",
    ]
    pos = ["must", "should", "shall", "will"]
    verbs = ["use", "adopt"]
    for s in subj:
        for v in verbs:
            for n in neg:
                for m in match_sentence(f"{s} {n} {v} Redis."):
                    assert m.kind == "forbid", (s, n, v, m)
            for p in pos:
                for m in match_sentence(f"{s} {p} {v} Redis."):
                    assert m.kind != "forbid", (s, p, v, m)


# =========================================================================== 3. block structure


def test_indented_code_skipped_list_continuation_and_tabs_kept(make_repo):
    code = "Intro.\n\n    Services must not import requests.\n"
    tab = "Intro.\n\n\tServices must not import requests.\n"
    _, cs = run(make_repo, adr(code))
    assert cs.claims == []
    _, cs = run(make_repo, adr(tab))
    assert cs.claims == []
    _, cs = run(
        make_repo, adr("- Services must use structlog\n    and must not import requests.\n")
    )
    assert {c.kind for c in cs.claims} == {"require", "forbid"}
    _, cs = run(make_repo, adr("Intro.\n\n    code line\n\nServices must not import requests.\n"))
    assert [c.kind for c in cs.claims] == ["forbid"]
    _, cs = run(
        make_repo,
        adr("~~~\nServices must not import requests.\n~~~\n\nPostgreSQL is the only datastore.\n"),
    )
    assert [c.kind for c in cs.claims] == ["only"]


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_bom_and_crlf_front_matter_hints_are_read(make_repo, eol):
    body = "---\ndriftwarden:\n  forbid: [requests]\n---\n" + adr("Hello.")
    text = "﻿" + body.replace("\n", eol)
    _, cs = run(make_repo, text)
    assert [c.origin for c in cs.claims] == ["hint"] and cs.unverified == []


def test_crlf_decision_equals_lf_claims_and_quotes_verify(make_repo):
    dec = "PostgreSQL is the only datastore.\nServices must not import `requests`."
    _, a = run(make_repo, adr(dec))
    _, b = run(make_repo, adr(dec, eol="\r\n"))
    assert [(c.kind, c.rule, c.source.line_start) for c in a.claims] == [
        (c.kind, c.rule, c.source.line_start) for c in b.claims
    ]
    assert b.unverified == []


@pytest.mark.parametrize(
    "block",
    [
        "```\n~~~\nServices must not import requests.\n```\n",
        "````\n```\nServices must not import requests.\n````\n",
        "```\nServices must not import requests.\n``` not a closer\nServices must not import flask.\n```\n",
    ],
)
def test_R13_code_fence_variants_are_not_prose(make_repo, block):
    """1. Fenced code is not prose (module docstring: 'Fenced and indented code blocks are
    not prose'); CommonMark: a fence closes only with the same character, at least as long,
    and no trailing text. 2. Code: claims/rules.py sentence_spans(): any line matching
    ^\\s*(```|~~~) toggles in_fence. 3. MEDIUM: an ADR that shows a Markdown example in a
    fence (common in 'how to write ADRs' text) produces claims from the example."""
    _, cs = run(make_repo, adr(block))
    assert cs.claims == [], [(c.kind, c.rule) for c in cs.claims]


# =========================================================================== 4. new false claims


@pytest.mark.parametrize(
    "sentence",
    [
        "Services don't have to use Redis.",
        "Services doesn't need to use Redis.",
        "Services won't have to use Redis.",
        "Don't have to use Redis.",
        "All services need not use Redis.",
        "All services do not have to use Redis.",
        "All services are not required to use Redis.",
        "All services aren't required to use Redis.",
        "All services are no longer required to use Redis.",
        "Every service no longer uses Redis.",
        "All services rarely use Redis.",
        "Each service hardly uses Redis.",
    ],
)
def test_R4_negation_inside_subject_capture_does_not_become_require(sentence):
    """1. D1/D2 contract: a negated sentence never yields a positive require/only claim.
    2. Code: claims/rules.py match_sentence() calls _negated(clean, span[0]) on the text
    *before* the match, but _subj() / require-all-use's {who} term can swallow the negator
    ("services don't", "services do not have to"), so it is inside the match and never
    inspected; _SUBJ_STOP lacks don't/doesn't/won't/need/no longer/hardly/rarely/seldom.
    3. HIGH: opposite meaning. 'Services don't have to use Redis' becomes 'every service
    must use Redis' -> a false VIOLATED on every service that does not."""
    assert [m for m in match_sentence(sentence) if m.kind in ("require", "only")] == [], [
        (m.kind, m.subject, m.rule) for m in match_sentence(sentence)
    ]


@pytest.mark.parametrize(
    "sentence,dropped",
    [
        ("Redis and Postgres are the only datastores.", "Redis"),
        ("Redis, Postgres are the only datastores.", "Redis"),
        ("Kafka and RabbitMQ are the only brokers.", "Kafka"),
        ("Kafka & RabbitMQ are the only brokers.", "Kafka"),
        ("Kafka, RabbitMQ and NATS are the only brokers.", "Kafka"),
        ("Both Kafka and RabbitMQ are our only brokers.", "Kafka"),
    ],
)
def test_R5_coordinated_subject_of_only_is_not_truncated_to_last_conjunct(sentence, dropped):
    """1. 'X and Y are the only <category>': either both are allowed or no claim; never
    'only Y'. 2. Code: rules.py only-category regex uses _subj('x'), whose first word cannot
    be 'and' (_SUBJ_STOP) so the match starts after the conjunction; _alternative() only
    checks or/nor/either/neither before the term, not 'and', ',' or '&'. 3. HIGH: the claim
    says Postgres is the only datastore; code using Redis is then flagged a violation of
    the ADR that explicitly allows it (opposite of the text)."""
    for m in match_sentence(sentence):
        if m.kind == "only":
            assert dropped in m.rule["only"], (sentence, m.rule)


@pytest.mark.parametrize(
    "sentence",
    [
        "We will not use MongoDB outside tests.",
        "We will not use MongoDB except in tests.",
        "We will not use MongoDB without approval.",
        "We will not use MongoDB for caching, but we will for search.",
        "We do not use Redis for sessions.",
        "Do not use Redis for the cart.",
        "Services must not use Redis except for sessions.",
        "Services must not import boto3 outside adapters/.",
        "Services must not import boto3 except in adapters/.",
        "Handlers must not call the database except via the repository.",
        "We will avoid MongoDB, except in tests.",
        "We will avoid MongoDB outside tests.",
        "We will avoid MongoDB until Q3.",
    ],
)
def test_R6_forbid_does_not_drop_exception_or_qualifier_clause(sentence):
    """1. Same principle as the 'unless/except' conditional guard (docstring: any
    'if/unless/whether' drops the sentence): a clause that narrows the ban must not be
    silently discarded. A correct output is no claim, a scoped forbid, or a boundary claim.
    2. Code: rules.py _LSTOP ends the term list at 'outside|except|without|for|when|...'
    and the pattern then matches successfully with the rest of the sentence ignored;
    _NOT_A_DECISION has if/unless/whether but not except/outside/without/for-purpose/until.
    3. MEDIUM-HIGH: 'We will not use MongoDB for caching, but we will for search' becomes
    forbid MongoDB everywhere (the sentence says the opposite for search): false VIOLATED."""
    bare = [
        m
        for m in match_sentence(sentence)
        if m.kind == "forbid" and set(m.rule) <= {"forbid", "action"}
    ]
    assert bare == [], [(m.rule) for m in bare]


@pytest.mark.parametrize(
    "sentence",
    [
        "We will not use Redis until Q3.",
        "We cannot use MongoDB until legal approves.",
        "We will not use Redis before the migration.",
        "We will not use Redis after the migration.",
        "We will not use Redis once the migration ends.",
        "We will not use Redis pending review.",
        "We will not use Redis during the pilot.",
        "We will not use Redis this quarter.",
        "We will use Redis until Q3.",
        "We will use Redis for six months.",
        "We will avoid MongoDB in the short term.",
    ],
)
def test_R7_time_limited_statements_yield_no_claim(sentence):
    """1. 'temporary' statements are already excluded for 'for now/temporarily/yet'; 'until
    X' is the same hedge. 2. Code: rules.py _NOT_A_DECISION lacks until/before/after/once/
    pending/during/this quarter. 3. MEDIUM: a time-boxed ban/choice is checked forever
    (false VIOLATED after the stated end date; junk terms like 'Redis before the migration')."""
    assert match_sentence(sentence) == [], [(m.kind, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence",
    [
        "Nobody says services must use Redis.",
        "Nobody thinks services must use Redis.",
        "Alice says services must use Redis.",
        "Some say that services must use Redis.",
        "Critics say services must use Redis.",
        "Alice suggests services must use Redis.",
        "The old ADR stated that services must use Redis.",
        "This supersedes ADR-0002, which said services must use Redis.",
        "The vendor says we will not use MongoDB.",
        "Some suggested we will avoid MongoDB.",
        "Bob proposed: do not use MongoDB.",
    ],
)
def test_R8_reported_speech_is_not_a_decision(sentence):
    """1. D5 contract: 'rejected / reported / hedged proposals are not claims'.
    2. Code: rules.py _NOT_A_DECISION reports only past-tense (argued|suggested|claimed|
    said|...) directly followed by 'that' or a quote; present tense (says, say, argue),
    'stated that', 'which said X' and 'proposed:' are not matched; also _NEGATOR lacks
    'nobody/no one'. 3. MEDIUM: 'Nobody says services must use Redis' becomes
    'require Redis' (opposite); quoted opinions of others become rules."""
    assert match_sentence(sentence) == [], [
        (m.kind, m.subject, m.rule) for m in match_sentence(sentence)
    ]


@pytest.mark.parametrize(
    "sentence",
    [
        "We will not use MongoDB (proposed).",
        "We will not use MongoDB (draft).",
        "We will not use MongoDB (TBD).",
        "We will not use MongoDB (to be confirmed).",
        "Proposal: we will not use MongoDB.",
        "Option A: we will not use MongoDB.",
        "Draft: we will not use MongoDB.",
        "TODO: we will not use MongoDB.",
        "TBD: we will not use MongoDB.",
    ],
)
def test_R9_draft_and_proposal_markers_yield_no_claim(sentence):
    """1. Same as D5 for hedged/rejected negatives: a sentence marked as a proposal/draft is
    not a decision. 2. Code: rules.py _NOT_A_DECISION label list has 'proposed:' and
    'option \\d+:' only. 3. MEDIUM-LOW: false forbid from alternatives lists written as
    'Option A: ...'."""
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "We generally don't use MongoDB.",
        "We typically do not use MongoDB.",
        "We currently do not use Redis.",
        "We presently do not use Redis.",
        "We will avoid MongoDB in general.",
    ],
)
def test_R10_hedged_or_descriptive_negatives_yield_no_claim(sentence):
    """1. 'We do not generally use X' (hedge after the negator) already yields nothing; the
    mirror order must too, and a description of the present ('currently do not use') is not
    a rule. 2. Code: rules.py _NOT_A_DECISION has no generally/usually/typically/normally/
    mostly/in general/currently/presently; _subj() even captures 'currently' as the claim
    subject. 3. MEDIUM: guidance with exceptions becomes an absolute ban; subject
    'currently'/'typically' is nonsense."""
    assert match_sentence(sentence) == [], [(m.subject, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence",
    [
        "Postgres is the only datastore that is not allowed.",
        "Postgres is the only datastore that must not be used.",
        "Postgres is the only datastore we ban.",
        "Postgres is the only datastore which is deprecated.",
        "Postgres is the only datastore we evaluated.",
        "Postgres is the only datastore we tried.",
        "Postgres is the only datastore in staging.",
        "Postgres is the only datastore for analytics.",
        "Postgres is the only datastore on mobile.",
        "Postgres is the only datastore, except for tests.",
        "Postgres is the only datastore should we choose option 2.",
        "Postgres is the only datastore in option 2.",
    ],
)
def test_R11_only_category_with_trailing_clause_is_not_a_global_only(sentence):
    """1. 'only' claims assert exclusivity within a category; a trailing clause that scopes,
    negates or reports the statement must not be dropped. Correct output: no claim, or a
    claim whose category/qualifier carries the clause. 2. Code: rules.py only-category
    regex ends the {cat} term at _STOP ('that|we|in|for|on|except|...') and ignores the
    rest of the sentence. 3. HIGH for the 'that is not allowed / we ban / deprecated' forms
    (the claim says the opposite: Postgres becomes the ONLY allowed store), MEDIUM for
    scope/report forms."""
    plain = [
        m
        for m in match_sentence(sentence)
        if m.kind == "only" and m.rule["category"].lower() == "datastore"
    ]
    assert plain == [], [(m.rule) for m in plain]


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Redis not Memcached.",
        "We will use Redis over Memcached.",
        "We will use Redis plus Memcached.",
        "We will use Redis / Memcached.",
        "Services must not use Redis and must use Memcached.",
        "Services must not use Redis but must use Memcached.",
        "We will not use Redis and we will use Memcached.",
        "Services must not call each other directly.",
        "We will use [Redis](https://redis.io) for caching.",
        "Avoid the temptation to use MongoDB.",
        "We will not use more than one datastore.",
    ],
)
def test_R12_claim_terms_are_clean_technology_names(sentence):
    """1. D6: 'alternatives and bounds are not flattened'; a claim term must name one
    thing. 2. Code: rules.py _single_term()/_NOT_ONE_TERM cover or/nor/either/rather than
    only; _LSTOP lets the forbid list run through ' and must use X' / ' but must ...'; clean_term()
    does not strip markdown links; 'each other' is taken as the object. 3. MEDIUM-LOW: a
    require of 'Redis not Memcached' can never be found in code (false VIOLATED); a forbid
    term 'must use Memcached' reads as banning Memcached (opposite)."""
    bad = re.compile(r"\b(?:not|over|plus|must|will|may|than|temptation)\b|[\[\]/]|^other$", re.I)
    for m in match_sentence(sentence):
        for key in ("forbid", "require", "only"):
            for t in m.rule.get(key, []):
                assert not bad.search(t), (sentence, m.kind, m.rule)


@pytest.mark.parametrize(
    "decision",
    [
        "We will use PostgreSQL.\n\n### Alternatives considered\n\n- We will use MongoDB.\n- Services must use Redis.\n",
        "We will use PostgreSQL.\n\n### Rejected\n\nServices must use Redis.\n",
        "We will use PostgreSQL.\n\n### Rejected options\n\n* Services must use Redis.\n",
    ],
)
def test_R14_rejected_alternatives_sections_are_not_claims(make_repo, decision):
    """1. D5: rejected proposals are not claims; ADRs list them under their own headings
    (the library handles 'Rejected: ...' only as a sentence prefix). 2. Code: rules.py
    sentence_spans() treats headings as block breaks only; _NOT_A_DECISION sees one
    sentence at a time, no section context. 3. MEDIUM-LOW: every rejected alternative
    becomes a require claim (false VIOLATED for the chosen design)."""
    _, cs = run(make_repo, adr(decision))
    assert [c.rule.get("require") for c in cs.claims] == [["PostgreSQL"]]


# =========================================================================== 5. performance


def _timed(fn, arg) -> float:
    t = time.perf_counter()
    fn(arg)
    return time.perf_counter() - t


@pytest.mark.parametrize(
    "build",
    [
        lambda n: "Services must not use " + "a, " * (n // 3) + "x.",
        lambda n: "Services must not use " + "a and " * (n // 6) + "x.",
        lambda n: "No " + "word " * (n // 5) + "may use x.",
        lambda n: "word " * (n // 5) + "must not use x",
        lambda n: "X is the only " + "w " * (n // 2),
        lambda n: "Services " + "only " * (n // 5) + "communicate via",
        lambda n: "Avoid " + "a, " * (n // 3),
        lambda n: "Avoid " + "a.b " * (n // 4),
        lambda n: "We will use " + "a.b" * (n // 3),
        lambda n: "We will use x " + "as the " * (n // 7),
        lambda n: ", " * (n // 2) + "We will use Redis",
        lambda n: "a " * (n // 2) + "must go through",
        lambda n: "All " + "w " * (n // 2) + "use x",
        lambda n: "Chosen option: " + "a" * n,
        lambda n: "Services must not use " + " " * n,
        lambda n: "We will use " + "(" * n,
        lambda n: "We will use " + '"' * n,
        lambda n: "`" * n,
        lambda n: "*a " * (n // 3) + "We will use X.",
        lambda n: "Aaa bbb. " * (n // 9),
        lambda n: "    a\n" * (n // 6),
        lambda n: "a\n" * (n // 2),
    ],
    ids=[f"shape{i}" for i in range(22)],
)
def test_regex_inputs_100kb_run_in_a_few_seconds(build):
    """Time-box: each 100 KB shape through sentence_spans + match_sentence per span."""
    text = build(100_000)
    t = time.perf_counter()
    spans = sentence_spans(text)
    for a, b in spans[:2000]:
        match_sentence(text[a:b])
    assert time.perf_counter() - t < 8.0


def test_R15_many_matches_in_one_sentence_scale_linearly():
    """1. Round-1 requirement 'very long single line is roughly linear' (and the 100 KB
    time-box). 2. Code: rules.py _negated() builds prefix=clean[:start] and runs
    _CLAUSE_START.match (greedy .*, re.S) over it for every candidate match, i.e. O(n) per
    match and O(n^2) for a sentence with O(n) matches ('We will use A, we will use B, ...').
    3. MEDIUM (regression vs the pre-fix library): one 100 KB paragraph without a full stop
    stalls the scan for about a minute."""
    s = "We will use A. " * 3000  # 45 KB, one 'sentence' for match_sentence
    assert _timed(match_sentence, s) < 2.0


def test_R16_abbreviation_dense_block_scales_linearly():
    """1. 100 KB time-box. 2. Code: rules.py sentence_spans(): for every abbreviation
    'continue' the start s does not advance, so the next iteration's
    re.search(r'([\\w.]+)[.!?]*$', text[s:m.start()+1]) re-scans an ever longer slice.
    3. LOW-MEDIUM (needs an adversarial or machine-generated ADR; not new in this round)."""
    assert _timed(sentence_spans, "e.g. " * 5000) < 2.0


def test_many_distinct_claims_stay_linear_enough(make_repo):
    """Observation (not filed): every claim is G1-verified through git, ~6-13 ms each; 800
    claims -> ~5 s. Guard against a further blow-up only."""
    dec = "\n".join(f"We will use T{i}." for i in range(300))
    t = time.perf_counter()
    _, cs = run(make_repo, adr(dec))
    assert len(cs.claims) == 300 and time.perf_counter() - t < 20


# =========================================================================== 6. hints & loader


def _hint_cs(make_repo, hint, decision="Hello."):
    return run(make_repo, fm(hint, decision))[1]


@pytest.mark.parametrize(
    "hint,needle",
    [
        ("driftwarden:\n  forbid: [a]\n  forbid: [b]", "duplicate key 'forbid'"),
        ("driftwarden:\n  forbid: [a]\ndriftwarden:\n  forbid: [b]", "duplicate key 'driftwarden'"),
        ("driftwarden:\n  forbid:\n    svc: [a]\n    svc: [b]", "duplicate key 'svc'"),
        ("driftwarden: {forbid: [a], forbid: [b]}", "duplicate key 'forbid'"),
    ],
)
def test_duplicate_yaml_key_is_reported_not_silent(make_repo, hint, needle):
    cs = _hint_cs(make_repo, hint)
    assert [c.rule for c in cs.claims] == [{"forbid": ["b"]}]
    assert any(needle in u.reason for u in cs.unverified), [u.reason for u in cs.unverified]


def test_duplicate_key_outside_the_hint_block_is_not_noise(make_repo):
    cs = _hint_cs(make_repo, "status: a\nstatus: b\ndriftwarden:\n  forbid: [x]")
    assert len(cs.claims) == 1 and cs.unverified == []


@pytest.mark.parametrize(
    "hint",
    [
        "driftwarden:\n  forbid: !!python/object/apply:os.system ['echo pwn']",
        "driftwarden:\n\tforbid: [a]",
        "1: a\n? [x]\n: b\ndriftwarden:\n  forbid: [a]",
        "driftwarden: [",
        "driftwarden:\n  forbid: " + "[" * 600 + "x" + "]" * 600,
        "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\ng: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\ndriftwarden:\n  forbid: *g",
    ],
)
def test_hostile_front_matter_never_raises_and_is_reported(make_repo, hint):
    t = time.perf_counter()
    cs = _hint_cs(make_repo, hint)
    assert time.perf_counter() - t < 5
    assert cs.unverified, "hostile hint must be reported, not silently ignored"


def test_anchors_and_merge_keys_work_and_explicit_key_overrides_merge(make_repo):
    cs = _hint_cs(make_repo, "base: &b [x, y]\ndriftwarden:\n  forbid: *b")
    assert cs.claims[0].rule == {"forbid": ["x", "y"]}
    cs = _hint_cs(make_repo, "base: &b {forbid: [x]}\ndriftwarden:\n  <<: *b\n  forbid: [z]")
    assert cs.claims[0].rule == {"forbid": ["z"]} and cs.unverified == []


def test_huge_front_matter_is_bounded(make_repo):
    t = time.perf_counter()
    cs = _hint_cs(make_repo, "driftwarden:\n  forbid: [a]\nfiller: " + "x" * 3_000_000)
    assert len(cs.claims) == 1 and time.perf_counter() - t < 10


def test_R18_case_variant_duplicate_hint_key_is_reported(make_repo):
    """1. D11: duplicate YAML keys must not be silently dropped; the loader matches the
    hint key case-insensitively (test_hint_key_case) so 'Driftwarden' IS a hint block.
    2. Code: rules.py extract_hint_claims(): hints = next(v for k, v in data.items() if
    str(k).lower() == HINT_KEY) takes the first and never looks at the rest; _HintLoader
    compares keys case-sensitively. 3. LOW: author's second block (forbid: [b]) is never
    checked and nothing says so."""
    cs = _hint_cs(make_repo, "driftwarden:\n  forbid: [a]\nDriftwarden:\n  forbid: [b]")
    assert cs.unverified or {tuple(c.rule["forbid"]) for c in cs.claims} == {("a",), ("b",)}


# =========================================================================== 7. LLM path residuals


def test_D14_bad_line_numbers_keep_valid_siblings_and_are_reported(make_repo):
    q = "PostgreSQL is the only datastore."
    d, _ = run(make_repo, adr(q))
    s = d.source.line_start
    good = lc("free", "ok", {"text": "t"}, q, s)
    for ls, le in [(0, 0), (-1, -1), (10**30, 10**30), (s + 3, s)]:
        bad = {**good, "subject": "bad", "line_start": ls, "line_end": le}
        _, cs = run(make_repo, adr(q), llm=[good, bad])
        assert [c.subject for c in cs.claims if c.origin == "llm"] == ["ok"], (ls, le)
        assert [u.origin for u in cs.unverified] == ["llm"] and cs.unverified[0].reason


@pytest.mark.parametrize(
    "patch",
    [
        {"subject": "x" * 300},
        {"subject": ""},
        {"quote": ""},
        {"kind": "weird"},
        {"rule": "notdict"},
        {"line_start": 9.5, "line_end": 9.5},
    ],
    ids=[
        "subject-300",
        "subject-empty",
        "quote-empty",
        "kind-unknown",
        "rule-string",
        "float-line",
    ],
)
def test_R17_one_bad_llm_item_does_not_discard_its_valid_siblings(make_repo, patch):
    """1. Acceptance criterion 'LLM-proposed claims whose quote/lines fail G1 are NOT dropped
    silently' and the D14 principle: one bad proposal is reported on its own, valid siblings
    survive. 2. Code: structure.py CLAIMS_SCHEMA (additionalProperties False, maxLength 200,
    minLength 1, enum kinds, integer lines) validated for the whole reply by
    provider.complete_json; one violation raises after the retries and
    propose_llm_claims() returns ([], [note]). 3. LOW-MEDIUM: a verbose model subject
    ('subject' > 200 chars) wipes the LLM contribution for the ADR; no per-claim 'Could not
    verify' row, only 'LLM structuring failed'."""
    q = "PostgreSQL is the only datastore."
    d, _ = run(make_repo, adr(q))
    s = d.source.line_start
    good = lc("free", "ok", {"text": "t"}, q, s)
    bad = {**good, "subject": "bad", **patch}
    _, cs = run(make_repo, adr(q), llm=[good, bad])
    assert [c.subject for c in cs.claims if c.origin == "llm"] == ["ok"]
