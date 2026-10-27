"""L-024: offline rule-library hardening after L-006 (Sonnet's final run N1-N5).

The central table is a decorated-sentence matrix: every plain rule in ``BASES`` is
combined with every harmless decoration (``LEADING_OK`` / ``TRAILING_OK``: the claim
must survive unchanged) and with every scope qualifier (``LEADING_SCOPE`` /
``TRAILING_SCOPE``: the unqualified claim must NOT survive). Precision first: a scope
control that leaks is a failure; a harmless decoration that drops the claim is a recall
loss that is tracked by rate (``test_matrix_overdrop_rate``), with an exact-survival
list for the decorations named in the ticket.
"""

# ruff: noqa: E501
from __future__ import annotations

import pytest

from driftwarden.claims.rules import match_sentence

# (plain rule, imperative?) -- each yields at least one claim on its own
BASES: list[tuple[str, bool]] = [
    ("We will use PostgreSQL as the primary datastore.", False),
    ("We will use Kafka as the message broker.", False),
    ("We will adopt gRPC for internal service communication.", False),
    ("We use Alembic for database migrations.", False),
    ("Services must not use Redis.", False),
    ("Services should not import requests.", False),
    ("Do not use MongoDB.", True),
    ("We will not use Oracle.", False),
    ("PostgreSQL is the only datastore.", False),
    ("All services must use structlog for logging.", False),
    ("Services must not import boto3 outside adapters/.", False),
    ("Only adapters/ may import boto3.", False),
    ("All database access must go through the repository layer.", False),
    ("Services communicate only via Kafka.", False),
    ("Global mutable singletons are forbidden.", False),
    ("MongoDB must not be used.", False),
    ("No service may add another database.", False),
    ("Every service runs on Kubernetes.", False),
    ("We standardise on Terraform.", False),
    ("Never import pandas.", True),
]

# Harmless material (the claim must survive unchanged)
LEADING_OK = [
    "Decision: ",
    "Outcome: ",
    "Chosen option: ",
    "In summary, ",
    "Given the above, ",
    "As a result, ",
    "After a long discussion, ",
    "Note that ",
    "Importantly, ",
    "Per ADR-0003, ",
    "The team agreed that ",
    "We decided that ",
    "In conclusion, ",
    "Therefore, ",
    "Consequently, ",
    "For these reasons, ",
    "As discussed in ADR-0002, ",
    "Going forward, ",
    "It was agreed that ",
    "The architecture board decided that ",
]
TRAILING_OK = [
    " (see ADR-0007)",
    " (see the security review)",
    " (approved by the architecture board)",
    ", to reduce ops cost",
    " to keep the architecture simple",
    " in order to simplify operations",
    " due to licensing concerns",
    " based on the benchmark results",
    " for consistency",
    " for simplicity",
    " for security reasons",
    ", which keeps deployment simple",
    ", which gives us one toolchain",
    ", as discussed in ADR-0004",
    ", as per the security review",
    " across the organization",
    " as a team",
    ", given our expertise",
    " because it is simpler to operate",
    " in line with ADR-0005",
    " to avoid vendor lock-in",
    " (cf. ADR-0001)",
]
# Scope qualifiers and conditions (the unqualified claim must not survive)
LEADING_SCOPE = [
    "When running locally, ",
    "Whenever possible, ",
    "While migrating, ",
    "During the migration, ",
    "Once the migration is done, ",
    "After the migration, ",
    "Before launch, ",
    "In production, ",
    "For analytics, ",
    "Until Q3, ",
    "If possible, ",
    "In the payments module, ",
    "For new services, ",
    "Where latency matters, ",
    "Except for tests, ",
]
TRAILING_SCOPE = [
    " for analytics workloads",
    " in production",
    " only in the payments module",
    " except for tests",
    " until Q3",
    " when running locally",
    " if needed",
    " outside the core domain",
    " for audit logging",
    " for sessions",
    " in staging",
    " in new services",
    ", to store sessions",
    " to cache sessions",
    " for the payments team",
    " while we migrate",
    " (for analytics only)",
    " (except in tests)",
    " (see ADR-0007, production only)",
    ", due to licensing, except in tests",
    " instead of Memcached in staging",
    " rather than Memcached for analytics",
]

_PROPER_START = ("PostgreSQL", "MongoDB", "Global", "Kafka", "Redis")
_INTRODUCERS = ("that ", "Note that ")


def decorate(base: str, *, lead: str | None = None, trail: str | None = None) -> str | None:
    """``base`` with a leading and/or trailing decoration (None: ungrammatical combo)."""
    imperative = dict(BASES).get(base, False)
    s = base
    if trail:
        s = s[:-1] + trail + "."
    if lead:
        if lead.endswith(_INTRODUCERS) and imperative:
            return None  # "We decided that do not use X" is not English
        if lead.startswith("Chosen option") and not base.startswith("We "):
            return None  # "Chosen option: X" is the MADR pattern itself
        if lead.endswith(": ") or s.startswith(_PROPER_START):
            s = lead + s
        else:
            s = lead + s[0].lower() + s[1:]
    return s


def _sig(sentence: str) -> list[tuple]:
    """Claims of ``sentence``, case-folded (a leading decoration lower-cases the subject)."""
    return sorted(
        (m.kind, m.subject.lower(), repr(sorted(m.rule.items())).lower())
        for m in match_sentence(sentence)
    )


POSITIVE = [
    (b, d)
    for b, _ in BASES
    for d in [decorate(b, lead=x) for x in LEADING_OK] + [decorate(b, trail=x) for x in TRAILING_OK]
    if d
]
CONTROLS = [
    (b, d)
    for b, _ in BASES
    for d in [decorate(b, lead=x) for x in LEADING_SCOPE]
    + [decorate(b, trail=x) for x in TRAILING_SCOPE]
    if d
]


def test_matrix_is_large_and_every_base_is_a_rule():
    assert len(POSITIVE) >= 150 and len(CONTROLS) >= 150
    for b, _ in BASES:
        assert match_sentence(b), b


@pytest.mark.parametrize(("base", "sentence"), CONTROLS, ids=[d for _, d in CONTROLS])
def test_scope_qualifier_never_leaves_the_unqualified_claim(base, sentence):
    plain = _sig(base)
    leaked = [c for c in _sig(sentence) if c in plain]
    assert leaked == [], leaked


@pytest.mark.parametrize(("base", "sentence"), POSITIVE, ids=[d for _, d in POSITIVE])
def test_harmless_decoration_never_changes_or_adds_a_claim(base, sentence):
    """Survives unchanged or is dropped (fail closed); never a different claim."""
    got, plain = _sig(sentence), _sig(base)
    assert got in ([], plain), (got, plain)


def test_matrix_overdrop_rate():
    lost = [d for b, d in POSITIVE if _sig(d) != _sig(b)]
    rate = len(lost) / len(POSITIVE)
    print(f"\nover-drop on the decorated matrix: {len(lost)}/{len(POSITIVE)} = {rate:.1%}")
    assert rate < 0.15, lost


# The decorations named in the ticket must keep the claim on a plain base.
NAMED = [
    "Decision: We will use PostgreSQL as the primary datastore.",
    "Outcome: Services must not use Redis.",
    "Chosen option: We will use Kafka as the message broker.",
    "In summary, we will use Kafka as the message broker.",
    "Given the above, services must not use Redis.",
    "As a result, PostgreSQL is the only datastore.",
    "After a long discussion, we will not use Oracle.",
    "Note that services must not use Redis.",
    "Importantly, services must not import boto3 outside adapters/.",
    "Per ADR-0003, services must not use Redis.",
    "The team agreed that PostgreSQL is the only datastore.",
    "We decided that services must not use Redis.",
    "We will use Kafka as the message broker (see ADR-0007).",
    "Services must not use Redis (see the security review).",
    "Do not use MongoDB (approved by the architecture board).",
    "We will adopt gRPC for internal service communication, to reduce ops cost.",
    "Services must not use Redis in order to simplify operations.",
    "Services should not import requests due to licensing concerns.",
    "PostgreSQL is the only datastore, based on the benchmark results.",
    "PostgreSQL is the only datastore for consistency.",
    "We will use Kafka as the message broker for simplicity.",
    "We will use Kafka as the message broker, which keeps deployment simple.",
    "Services must not use Redis, as discussed in ADR-0004.",
    "We use Alembic for database migrations, as per the security review.",
    "All services must use structlog for logging across the organization.",
    "We will use Kafka as the message broker as a team.",
]


@pytest.mark.parametrize("sentence", NAMED)
def test_named_harmless_decorations_keep_the_claim(sentence):
    assert match_sentence(sentence), sentence


# ------------------------------------------------------------------ N1 .. N5, generalised


@pytest.mark.parametrize(
    "sentence",
    [
        "Whenever we deploy, services must not use Redis.",
        "While running locally, we will use SQLite.",
        "Services must not use Redis when running locally.",
        "Services must use structlog for logging while running in CI.",
        "We will use Redis, when deploying to production.",
        "Wherever possible, avoid MongoDB.",
        "As long as traffic is low, we will use SQLite.",
        "Where latency matters, we will use Redis.",
    ],
)
def test_N1_conditions_anywhere_yield_no_claim(sentence):
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Every team can use Django.",
        "All services may choose to use Redis.",
        "Each team is encouraged to use Terraform.",
        "All services could use Redis.",
        "Every service is welcome to use Redis.",
        "All teams might use Kafka.",
        "Every service is permitted to use Redis.",
        "All services would prefer to use Redis.",
    ],
)
def test_N2_permission_never_becomes_require_or_only(sentence):
    assert [m for m in match_sentence(sentence) if m.kind in ("require", "only")] == []


@pytest.mark.parametrize(
    ("sentence", "terms"),
    [
        ("Do not use Redis, given our expertise.", ["Redis"]),
        ("Do not use Redis, due to licensing.", ["Redis"]),
        ("Do not use Redis, based on the benchmark results.", ["Redis"]),
        ("Do not use Redis, as a rule.", ["Redis"]),
        ("Do not use Redis, Memcached, or Hazelcast.", ["Redis", "Memcached", "Hazelcast"]),
    ],
)
def test_N3_rationale_after_a_comma_is_not_a_term(sentence, terms):
    (m,) = match_sentence(sentence)
    assert m.rule["forbid"] == terms


@pytest.mark.parametrize(
    "sentence",
    [
        "Do not use Redis, given the load in production.",
        "Do not use Redis, given our expertise, except in tests.",
        "Do not use Redis, Memcached in staging.",
    ],
)
def test_N3_unrecognised_tail_fails_closed(sentence):
    for m in match_sentence(sentence):
        assert all(len(t.split()) == 1 for t in m.rule.get("forbid", [])), m.rule
        assert m.rule.get("forbid") != ["Redis"] or m.rule.get("scope"), m.rule


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Redis Streams rather than Kafka in staging.",
        "We will use PostgreSQL instead of MongoDB for analytics.",
        "PostgreSQL is the only datastore instead of MongoDB in the payments module.",
        "Services must not use Redis instead of Memcached in production.",
        "We will use Redis Streams in place of Kafka for new services.",
    ],
)
def test_N5_contrast_keeps_its_trailing_scope(sentence):
    plain = sentence.split(" instead of ")[0].split(" rather than ")[0].split(" in place of ")[0]
    leaked = [c for c in _sig(sentence) if c in _sig(plain + ".")]
    assert leaked == []


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Redis Streams instead of Kafka.",
        "We will use PostgreSQL rather than MongoDB or Cassandra.",
        "We will use PostgreSQL instead of running our own cluster, because it is simpler.",
    ],
)
def test_N5_plain_contrast_still_yields_the_claim(sentence):
    assert match_sentence(sentence)


# --------------------------------------------------------------- purpose vs scope 'to'


@pytest.mark.parametrize(
    "sentence",
    [
        "Services must not use Redis to store sessions.",
        "Do not use Kafka to send audit events.",
        "We will use Redis to cache sessions.",
        "Services must not use Redis to keep session state.",
        "Do not use pickle to serialise payloads.",
    ],
)
def test_operational_to_clause_is_a_scope_not_a_purpose(sentence):
    plain = sentence.split(" to ")[0] + "."
    leaked = [c for c in _sig(sentence) if c in _sig(plain)]
    assert leaked == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Services must not use Redis to reduce operational cost.",
        "Do not use pickle to reduce the attack surface.",
        "We will use Kafka to keep the architecture simple.",
        "We will use Kafka to ensure ordering guarantees.",
    ],
)
def test_purpose_to_clause_keeps_the_claim(sentence):
    assert match_sentence(sentence)


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Kafka for consistency.",
        "We will use Kafka as discussed in ADR-0004.",
        "We will use Kafka as a team.",
        "We standardise on structlog for consistency.",
    ],
)
def test_rationale_is_never_captured_as_a_category(sentence):
    (m,) = match_sentence(sentence)
    assert m.rule.get("for") in (None,) and m.rule.get("category") in (None, "technology"), m.rule


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Redis for caching (see ADR-0007 for analytics only).",
        "We will use Redis for caching (see the review, except in tests).",
        "We will use Redis for caching (approved by ops in staging).",
        "Rejected: we will use Redis for caching (see ADR-0007).",
        "Decision: Rejected: we will use MongoDB.",
        "Decision: Option A: we will use MongoDB.",
        "Note that maybe we will use Redis.",
        "Note: TODO: we will use Redis.",
        "Bob agreed that we will use Redis.",
        "The team hopes that we will use Redis.",
        "After the migration, we will use Redis.",
        "After a long discussion of the options except Redis, we will use Memcached.",
    ],
)
def test_decoration_whitelist_does_not_hide_guards_or_scopes(sentence):
    assert match_sentence(sentence) == [], [(m.kind, m.rule) for m in match_sentence(sentence)]


# ------------------------------------------- similar fail-open cases fixed generically


@pytest.mark.parametrize(
    ("sentence", "rule"),
    [
        # a rationale / universal phrase was swallowed into a term, a scope or a category
        ("Services must not use Redis as a team.", {"forbid": ["Redis"], "action": "use"}),
        (
            "Services must not use Redis in line with ADR-0005.",
            {"forbid": ["Redis"], "action": "use"},
        ),
        (
            "Services must not use Redis in order to simplify operations.",
            {"forbid": ["Redis"], "action": "use"},
        ),
        (
            "We standardise on Terraform across the organization.",
            {"only": ["Terraform"], "category": "technology"},
        ),
        (
            "No service may add another database as a team.",
            {"forbid": ["database"], "action": "add"},
        ),
        (
            "We will use PostgreSQL as the primary datastore across the organization.",
            {"require": ["PostgreSQL"], "for": "primary datastore"},
        ),
        ("Redis is banned across all code.", {"forbid": ["Redis"]}),
    ],
)
def test_rationale_and_universal_phrases_never_pollute_a_claim(sentence, rule):
    (m,) = match_sentence(sentence)
    assert m.rule == rule


def test_chosen_option_that_is_a_clause_is_not_a_term():
    assert match_sentence("Chosen option: Some services have to use Redis.") == []
    assert match_sentence("Chosen option: Most teams have to use Redis.") == []
    (m,) = match_sentence("Chosen option: structlog.")
    assert m.rule == {"require": ["structlog"]}


@pytest.mark.parametrize(
    "sentence", ["We will use a Kafka-like broker.", "We will use a lock-free queue."]
)
def test_permission_words_inside_a_term_are_not_a_permission(sentence):
    assert [m.kind for m in match_sentence(sentence)] == ["require"]


# ----------------------------------- L-024 round 2: rationale whitelist (Sonnet D1-D9)


@pytest.mark.parametrize(
    "sentence",
    [
        # an infinitive after a filler is a fragment, not a clause of its own
        "Services must not use Redis, as a rule to access the database.",
        "Services must use Redis, as a team to call the ledger.",
        "Services must not use Redis, for all services to run batch jobs.",
        # a reason clause never carries a place, scope, condition or time
        "We will use Kafka, because it is cheaper by default.",
        "We will use Kafka, because it is cheaper given a valid token.",
        "We will use Kafka since the licence is permissive with the legacy system.",
        "We will use Kafka since Q3.",
        # a reference is an ADR / RFC / review, not a scope
        "Services must not use Redis, per ADR-0007 as a last resort.",
        "We will use Kafka, in line with ADR-5 to send email.",
        # a relative clause outside the closed shapes fails closed
        "Do not use Redis, which leaks memory.",
        "We will use Kafka, which gives us replay.",
    ],
)
def test_round2_rationale_shapes_are_closed(sentence):
    assert match_sentence(sentence) == [], [(m.kind, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    ("sentence", "kinds"),
    [
        ("Services must use Kafka, while batch jobs must use RabbitMQ.", ["require", "require"]),
        ("While Redis is fast, services must not use Redis.", ["forbid"]),
        ("Services, as a rule, must not use Redis.", ["forbid"]),
        ("Status: Accepted. We will use Kafka.", ["require"]),
        ("Decision (2024-05-01): We will use Kafka.", ["require"]),
        ("Final decision: we will use Kafka.", ["require"]),
        ("We will use Kafka at all times.", ["require"]),
        ("We will use Kafka throughout the company, without exception.", ["require"]),
        ("We will use Kafka, for the long term.", ["require"]),
        ("We will use Kafka as described by Michael Nygard.", ["require"]),
    ],
)
def test_round2_harmless_forms_keep_the_claim(sentence, kinds):
    assert sorted(m.kind for m in match_sentence(sentence)) == kinds


@pytest.mark.parametrize(
    "sentence",
    ["While we are migrating, we will use Redis.", "Services must use Redis while we migrate."],
)
def test_round2_temporal_while_is_still_a_condition(sentence):
    assert match_sentence(sentence) == []


# ------------------------------------------------- Codex review of PR #18 (3x P2)

REF_PAREN_SCOPED = [
    "Services must use Redis (see ADR-7, scope: payments).",
    "Services must use Redis (see ADR-7 for payments).",
    "Services must not use Redis (see the payments team).",
    "We will use Kafka (cf. ADR-3, analytics workloads).",
    "We will use Kafka (approved by ops in staging).",
    "We will use Kafka (see ADR-7; EU region).",
    "We will use Kafka (per ADR-3, batch jobs).",
    "We will use Kafka (ref: ADR-3 sessions).",
    "We will use Kafka (see notes on the checkout flow).",
]


@pytest.mark.parametrize("sentence", REF_PAREN_SCOPED)
def test_codex1_only_recognised_reference_brackets_are_removed(sentence):
    assert match_sentence(sentence) == [], [(m.kind, m.rule) for m in match_sentence(sentence)]


@pytest.mark.parametrize(
    "sentence",
    [
        "We will use Kafka (see ADR-0007).",
        "We will use Kafka (ADR-0007).",
        "We will use Kafka (see also RFC-12).",
        "We will use Kafka (cf. ADR-0001, 2024-05-01).",
        "We will use Kafka (see the security review).",
        "We will use Kafka (approved by the architecture board).",
        "We will use Kafka (approved by Jane Doe).",
        "We will use Kafka (see PR #42).",
        "We will use Kafka (see ADR-7 for details).",
        "We will use Kafka (ref: ADR-3).",
        "We will use Kafka (#118).",
    ],
)
def test_codex1_reference_brackets_keep_the_claim(sentence):
    (m,) = match_sentence(sentence)
    assert m.rule == {"require": ["Kafka"]}


PRODUCT_NAMES = [
    "Google Cloud Run",
    "Cloud Run",
    "Microsoft Access",
    "Cloudflare Access",
    "Okta Access Gateway",
    "Octopus Deploy",
    "Deno Deploy",
    "Webpack Bundle Analyzer",
    "Import Maps",
    "Vendor Portal",
    "Azure Functions",
    "AWS Lambda",
    "Apache Spark",
    "Apache Flink",
    "Run:ai",
    "Add-on SDK",
    "Cloud Deploy",
    "Access Context Manager",
    "Install4j",
    "Prefer Header Proxy",
    "Used Book API",
]


@pytest.mark.parametrize("name", PRODUCT_NAMES)
def test_codex2_chosen_option_product_names_with_verb_like_words(name):
    (m,) = match_sentence(f"Chosen option: {name}.")
    assert m.kind == "require" and m.rule == {"require": [name]}


@pytest.mark.parametrize(
    "sentence",
    [
        "Chosen option: some services have to use Redis.",
        "Chosen option: services use Redis.",
        "Chosen option: use Redis.",
        "Chosen option: Redis is used.",
        "Chosen option: teams decided Redis.",
        "Chosen option: Redis only in staging.",
    ],
)
def test_codex2_chosen_option_clause_is_still_refused(sentence):
    assert match_sentence(sentence) == []


@pytest.mark.parametrize(
    ("sentence", "kinds"),
    [
        ("Never import pandas; we will use Kafka for consistency.", ["forbid", "require"]),
        ("Do not use MongoDB, and we will use Kafka for consistency.", ["forbid", "require"]),
        ("We will use Kafka for consistency; never import pandas.", ["forbid", "require"]),
        ("Do not use Redis for performance; we will use Kafka.", ["require"]),
        ("Do not use Redis for performance.", []),
    ],
)
def test_codex3_bare_for_purpose_only_suppresses_its_own_clause(sentence, kinds):
    assert sorted(m.kind for m in match_sentence(sentence)) == kinds
