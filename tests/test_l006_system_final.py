"""L-006 FINAL confirmation (Sonnet, system tester) against 92b5048.

Covers the NEW risk of the central ``_covered()`` clause check (over-dropping), a
false-claim regression hunt (opposite / broadened claims), and perf time-boxes.

Tests marked ``xfail(strict=True)`` document DEFECTS found in this round (ids N1-N4);
they turn red (XPASS) when the defect is fixed, so the marker must then be removed.
Each defect docstring: 1. which requirement, 2. where in the code, 3. how bad.

Oracle policy (as in the earlier rounds): precision over recall. N1-N3 are precision
defects (a wrong or broadened claim). N4 is a recall regression (a real rule that the
previous library emitted is now dropped because of a harmless decoration): fail-closed
by design, so low severity, filed so the rate is tracked.
"""

# ruff: noqa: E501
from __future__ import annotations

import itertools
import time

import pytest

from driftwarden.claims import structure_decision
from driftwarden.claims.rules import match_sentence, sentence_spans
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.verify import verify_source_quote

_N = itertools.count()


def adr(decision: str) -> str:
    return f"# 1. Test\n\n## Status\n\nAccepted\n\n## Decision\n\n{decision}\n\n## Consequences\n\nNone.\n"


def offline(make_repo, text: str):
    repo = make_repo({"docs/adr/0001-x.md": text}, name=f"final{next(_N)}")
    (d,) = scan_adrs(repo).decisions
    return repo, structure_decision(d, repo, mode="offline")


def timed(fn, *a):
    t = time.perf_counter()
    fn(*a)
    return time.perf_counter() - t


# ------------------------------------------------------------------------- perf (held)


def test_perf_100kb_single_sentence_many_matches(perf_factor):
    s = "We will use A, we will use B, " * 3400  # ~100 KB, no full stop
    assert 90_000 < len(s) < 110_000
    assert timed(match_sentence, s) < 5.0 * perf_factor


def test_perf_100kb_single_sentence_dropped_qualifiers(perf_factor):
    s = "Services must not use Redis except for tests, " * 2200  # ~100 KB
    assert timed(match_sentence, s) < 5.0 * perf_factor


def test_perf_100kb_abbreviation_dense_block(perf_factor):
    s = "e.g. i.e. etc. " * 6700
    assert 90_000 < len(s) < 110_000
    assert timed(sentence_spans, s) < 5.0 * perf_factor
    assert (
        timed(lambda t: [match_sentence(t[a:b]) for a, b in sentence_spans(t)[:2000]], s)
        < 10.0 * perf_factor
    )


def test_perf_5000_claim_adr_end_to_end_and_all_g1_verified(make_repo, perf_factor):
    """Linear scaling (500 -> 5000 claims, same process) plus a ceiling calibrated on the
    measured per-claim G1 cost of this runner (`git show` subprocess), not a flat wall clock."""
    from conftest import time_5000_claim_adr

    def body(i):
        return f"Module m{i} must not import legacy{i}."

    t500, _, _, _ = time_5000_claim_adr(make_repo, body, adr, offline, 500)
    dt, per_call, repo, cs = time_5000_claim_adr(make_repo, body, adr, offline, 5000)
    print(f"\n500: {t500:.1f}s, 5000: {dt:.1f}s, G1 per claim {per_call * 1000:.1f} ms")
    assert len(cs.claims) == 5000 and cs.unverified == []
    assert dt / t500 < 20, (t500, dt)  # 10x input; quadratic would be ~100x
    assert dt < 5000 * per_call * 2.5 + 30 * perf_factor
    for c in cs.claims[:: 5000 // 100]:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"


# ------------------------------------------------------------------ held: justified drops

JUSTIFIED = [
    "Kafka is the only message broker except for tests.",
    "Only the gateway may call external services until Q3.",
    "Services must not import boto3 outside adapters/ except for tests.",
    "Do not use pickle for serialization except for tests.",
    "We will use JWT for session tokens in the payments module only.",
    "Only adapters/ may import boto3 when running in staging.",
    "We will use React for the frontend until Q3.",
    "Redis is the only cache for analytics workloads.",
]


@pytest.mark.parametrize("sentence", JUSTIFIED)
def test_meaning_changing_qualifier_never_yields_an_unqualified_claim(sentence):
    assert match_sentence(sentence) == []


# ---------------------------------------------------------------- N1 .. N4 (defects)


@pytest.mark.parametrize(
    "sentence",
    [
        "When running locally, services must not use Redis.",
        "When running locally, we will use Redis for caching.",
        "When running locally, Redis is the only cache.",
        "When deploying to production, services must not use Redis.",
    ],
)
def test_N1_leading_when_clause_is_a_condition(sentence):
    """1. R6/R7-style guard: a conditional / scoped decision is not a global rule
    (precision first). 'If ...,', 'Until ...,', 'Whenever possible,' etc. are all handled;
    'When <verb>-ing ...,' is the one leading condition that slips through. 2. rules.py
    _covered(): the leading fragment 'When running locally,' has no finite verb so it is
    treated as an orphan fragment, but the claim region is not dropped because the guard
    that should attach it is missing (the old library emitted the same claim). 3. MEDIUM:
    a local/stage-only rule becomes a repo-wide one, so a later G1/judge run can report a
    false VIOLATED. Seen in 124 of 100k generated sentences."""
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Every team can use Django.",
        "Every team is allowed to use Redis.",
        "Each service is free to use Redis.",
        "All services ought to use Redis.",
        "All services would like to use Redis.",
    ],
)
def test_N2_permission_is_not_an_obligation(sentence):
    """1. 'may/can/is allowed' grant a permission; an obligation claim (require) is the
    opposite of 'optional' and yields a false VIOLATED for every team that does not use X.
    ('All services may use Redis.' correctly yields nothing.) 2. the 'All/Every <noun> use
    X' require pattern lets the modal into the subject capture (subject is 'team can').
    3. MEDIUM: permission strengthened to obligation (85 of 100k generated sentences; the
    old library did it 203 times, so this is a pre-existing gap that _covered() does not
    catch because the modal is inside the captured subject)."""
    assert [m.kind for m in match_sentence(sentence) if m.kind in ("require", "only")] == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Do not use Redis, given our expertise.",
        "Handlers cannot import RabbitMQ, given our expertise.",
        "Do not use eval, as a rule.",
        "Do not use Redis, as per the security review.",
    ],
)
def test_N3_decoration_is_not_a_forbidden_term(sentence):
    """1. R12: claim terms are clean technology names. 2. forbid term-list splitter treats
    the comma-separated tail as a second term; _covered() sees the match span as covering
    the clause so nothing is dropped. 3. LOW-MEDIUM: a nonsense term in the claim (cannot
    be found in code, so it never fires, but it is shown to the user as a rule and it
    contradicts the fail-closed policy applied to the same decoration elsewhere). 6.5% of
    emitted claims in the 100k run (1,120); the old library: 1,919."""
    for m in match_sentence(sentence):
        assert all(len(t.split()) <= 1 for t in m.rule.get("forbid", [])), m.rule


OVERDROP = [
    # (sentence, what a reader would say it is)
    "Decision: We will use PostgreSQL as the primary datastore.",
    "In summary, we will use Kubernetes for orchestration.",
    "Given the above, we will use React for the frontend.",
    "As a result, we will adopt gRPC for internal service communication.",
    "After a long discussion, we will use Docker for packaging services.",
    "Note that we will use PostgreSQL as the primary datastore.",
    "The team agreed that we will use PostgreSQL as the primary datastore.",
    "We will use Redis for caching (see the security review).",
    "We will use PostgreSQL as the primary datastore (see ADR-0007).",
    "We will adopt gRPC for internal service communication, to reduce ops cost.",
    "We will not use Oracle to keep the architecture simple.",
    "Services should not use requests due to licensing concerns.",
    "We will use Kafka as the message broker, which keeps deployment simple.",
    "PostgreSQL is the only datastore for consistency.",
    "We use Alembic for database migrations, as per the security review.",
]


@pytest.mark.parametrize("sentence", OVERDROP)
def test_N4_harmless_decoration_does_not_drop_the_claim(sentence):
    """1. 'lower recall, very high precision': the Nygard 'Decision:' label, a discourse
    marker or a reason clause does not change what the rule says, and the previous
    library emitted these. 2. rules.py _covered(): any content word in a gap before/after
    a match (not a manner adverb) drops the whole region (fail closed), with no allow-list
    for discourse markers, reference parentheses or reason/purpose clauses ('because' and
    'since' survive in ~90% of cases, 'due to' / 'to ...' / 'which ...' / '(...)' do not).
    3. LOW-MEDIUM (recall only, never a wrong claim): measured on 3,000+ decorated
    sentences, 68% of the claims the old library emitted are now dropped; the plain
    sentence is unaffected."""
    assert match_sentence(sentence)


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Redis Streams instead of Kafka in the payments module only.",
        "We will use Redis Streams instead of Kafka in staging.",
        "We will use Redis Streams instead of Kafka for analytics workloads.",
        "We will use Redis Streams instead of Kafka when running in CI.",
        "We will use Redis Streams instead of Kafka in new services.",
    ],
)
def test_N5_instead_of_keeps_or_rejects_trailing_scope(sentence):
    """1. A scoped decision is not a global rule (precision first); the same sentence with
    'until Q3', 'except for tests' or 'unless approved' is correctly dropped. 2. rules.py:
    the 'X instead of Y' require pattern ends at Y, and the coverage check treats the
    trailing scope phrase as covered by the match (the pattern's Y capture swallows it).
    3. MEDIUM: scope-limited technology choice becomes a repo-wide require (false
    VIOLATED elsewhere). Old library: same output (pre-existing, found by the 150-sentence
    over-drop hunt as the only claim that survived a scope qualifier)."""
    assert match_sentence(sentence) == []
