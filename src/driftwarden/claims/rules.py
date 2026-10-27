"""Offline rule library: decision text -> typed, testable claims. No LLM, no network.

Two sources, both deterministic:

1. **Phrase patterns** (``RULES``). The decision text is split into sentences;
   each sentence is cleaned (Markdown emphasis and code backticks removed,
   whitespace collapsed, curly quotes straightened) and matched against typed
   patterns such as "X is the only datastore", "must not import Y",
   "no Y outside Z/", "all A must go through B", "we will use X",
   "services communicate only via Q". Patterns are tried in priority order
   (boundary, only, forbid, require); once part of a sentence is claimed by a
   pattern, overlapping matches from later patterns are ignored, so one phrase
   yields one claim. Questions (sentences ending in ``?``) never yield claims.

2. **Front-matter hints**: an ADR may state its rules in YAML front-matter::

       ---
       status: accepted
       driftwarden:
         forbid: [requests, urllib3]
         require: [httpx]
         only: {datastore: [postgresql]}
         boundary: [{target: boto3, allowed_in: [adapters/]}]
         free: "Every service exposes /healthz"
       ---

   ``forbid`` / ``require`` take a string, a list, or ``{subject: [items]}``;
   ``only`` takes ``{category: [items]}`` or a list; ``boundary`` takes one or a
   list of ``{target, allowed_in | via[, subject]}``; ``free`` a string or list.

Every claim carries G1 provenance (``Claim.source``): the ADR path, the 1-based
line range, the commit the ADR was read from, and a verbatim quote. For a
pattern claim the quote is the matched sentence as written in the decision
section (or, if the sentence cannot be quoted cleanly, its whole lines). For a
hint claim it is the hint's own front-matter lines: the team's machine-readable
statement of the decision. The dispatcher (``claims.structure``) re-checks every
quote with ``verify_source_quote()``.

Claim ids produced here are provisional (``<ADR>.c<n>``); the dispatcher
renumbers after merging and de-duplicating.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import yaml

from driftwarden.grounding.verify import normalise
from driftwarden.models import Claim, ClaimKind, Decision, Provenance, rule_errors
from driftwarden.text import split_lines

# --------------------------------------------------------------------------- regex parts

# One term: any run of characters except clause punctuation. A dot is allowed only
# inside a token ("Node.js", "v1.2"), never as a sentence end.
_C = r"(?:[^,;:!?()—–\".]|\.(?=\S))"
# A list of terms ("a, b or c"): commas allowed.
_LC = r"(?:[^;:!?()—–\".]|\.(?=\S))"
# A subject in front of a verb: 1-6 word tokens, none of them a verb, modal or
# conjunction (so "X is the only datastore and services must not use Y" gives the
# subject "services", not "is the only datastore and services").
_SUBJ_STOP = (
    r"and|or|but|nor|is|are|was|were|be|been|being|must|may|shall|should|can|could|will|"
    r"would|not|never|do|does|did|that|which|because|so|then|if|when|while|use|uses"
)
_W = rf"(?!(?:{_SUBJ_STOP})\b)[\w.+#/@'-]+"


def _term(name: str) -> str:
    return rf"(?P<{name}>{_C}{{1,120}}?)"


def _list(name: str) -> str:
    return rf"(?P<{name}>{_LC}{{1,240}}?)"


def _subj(name: str) -> str:
    return rf"(?<![\w.+#/@'-])(?P<{name}>{_W}(?:\s+{_W}){{0,5}}?)"


_STOP_WORDS = (
    "and|or|but|because|so|when|unless|except|without|instead|for|as|in|from|within|"
    "inside|outside|via|through|to|which|that|if|is|are|was|were|will|would|must|may|"
    "should|shall|can|by|on|at|with|using|since|until|where|while|we|directly|only"
)
# End of a single term: a clause word, clause punctuation, a sentence end or the end.
_STOP = rf"(?=\s+(?:{_STOP_WORDS})\b|\s*(?:[,;:!?()—–\"]|\.(?:\s|$))|\s*$)"
# End of a term list: commas and and/or are part of the list.
_LSTOP = (
    r"(?=\s+(?:without|unless|except|outside|because|in|from|within|inside|for|to|"
    r"directly|when|if|so|since|until|unless)\b|\s*(?:[;:!?()—–\"]|\.(?:\s|$))|\s*$)"
)

_VERBS = (
    r"us(?:e|es|ing)|import(?:s|ing)?|depend(?:s|ing)? on|call(?:s|ing)?|access(?:es|ing)?|"
    r"referenc(?:e|es|ing)|includ(?:e|es|ing)|add(?:s|ing)?|introduc(?:e|es|ing)|"
    r"bundl(?:e|es|ing)|install(?:s|ing)?|vendor(?:s|ing)?|adopt(?:s|ing)?|"
    r"run(?:s|ning)?|deploy(?:s|ing)?|instantiat(?:e|es|ing)"
)
_PASSIVE = (
    r"used|imported|added|introduced|called|accessed|deployed|installed|referenced|instantiated"
)
_NEG_MODAL = (
    r"must not|mustn't|shall not|shan't|should not|shouldn't|may not|cannot|can not|can't|"
    r"must never|shall never|should never|may never|will not|won't|will never|do not|don't|"
    r"does not|doesn't|are not to|is not to|are not allowed to|is not allowed to|"
    r"are not permitted to|is not permitted to|are forbidden to|is forbidden to|"
    r"are prohibited from|is prohibited from|are never to|is never to"
)

_I = re.IGNORECASE

# --------------------------------------------------------------------------- term clean-up

_DET = re.compile(
    r"^(?:the|a|an|another|any|our|other|all|some|each|every|this|these|those|its|their|"
    r"new|additional|extra)\s+",
    _I,
)
_TRAIL = re.compile(r"\s+(?:directly|anymore|any more|at all|again|either|too|also)$", _I)
_PRONOUNS = {
    "it", "this", "that", "these", "those", "they", "them", "we", "you", "which", "there",
    "he", "she", "one", "i", "us", "what", "who", "nothing", "anything", "everything",
    "something", "here", "everyone", "anyone", "nobody",
}  # fmt: skip
_LEAD = {
    "we", "have", "has", "had", "decided", "decide", "agreed", "agree", "that", "so", "then",
    "now", "therefore", "thus", "hence", "going", "forward", "from", "today", "on", "in",
    "at", "and", "but", "also", "the", "a", "an", "our", "currently", "henceforth",
    "consequently", "accordingly", "finally", "instead", "all", "every", "each", "any",
}  # fmt: skip


def clean_term(raw: str | None) -> str | None:
    """Trim a captured term: quotes, determiners, trailing adverbs. None if empty or a
    bare pronoun ("this is not allowed" names nothing testable)."""
    if raw is None:
        return None
    t = " ".join(raw.split()).strip(" '\"`.")
    prev = None
    while prev != t:
        prev = t
        t = _DET.sub("", t)
        t = _TRAIL.sub("", t).strip(" '\"`.")
    if not t or t.lower() in _PRONOUNS or not re.search(r"\w", t):
        return None
    return t


def _strip_lead(raw: str | None) -> str | None:
    """Drop filler words in front of a subject ("We decided that PostgreSQL" -> "PostgreSQL")."""
    if raw is None:
        return None
    words = raw.split()
    while len(words) > 1 and words[0].lower() in _LEAD:
        words.pop(0)
    return clean_term(" ".join(words))


def split_list(raw: str | None) -> list[str]:
    """``"another database, cache-as-database or document store"`` -> three terms."""
    if raw is None:
        return []
    parts = re.split(r"\s*,\s*(?:(?:and|or|nor)\s+)?|\s+(?:and|or|nor|and/or)\s+", raw)
    out: list[str] = []
    for p in parts:
        t = clean_term(p)
        if t and t not in out:
            out.append(t)
    return out


def _paths(raw: str | None) -> list[str]:
    """Location terms; a token with a ``/`` is taken as the path ("the adapters/ package")."""
    out: list[str] = []
    for t in split_list(raw):
        slashed = [w for w in t.split() if "/" in w]
        for v in slashed or [t]:
            if v not in out:
                out.append(v)
    return out


_VERB_BASE = (
    ("depend", "depend on"),
    ("import", "import"),
    ("us", "use"),
    ("call", "call"),
    ("access", "access"),
    ("referenc", "reference"),
    ("includ", "include"),
    ("add", "add"),
    ("introduc", "introduce"),
    ("bundl", "bundle"),
    ("install", "install"),
    ("vendor", "vendor"),
    ("adopt", "adopt"),
    ("run", "run"),
    ("deploy", "deploy"),
    ("instantiat", "instantiate"),
)


def _base_verb(v: str) -> str:
    low = v.lower()
    for prefix, base in _VERB_BASE:
        if low.startswith(prefix):
            return base
    return low


# --------------------------------------------------------------------------- patterns

Built = tuple[str, dict[str, Any]] | None  # (subject, rule) or None to reject the match


@dataclass(frozen=True)
class RulePattern:
    """One typed phrase pattern of the rule library.

    ``examples`` must each yield a claim from this pattern; ``non_examples`` are
    near misses that must yield none from it. Both are exercised by the tests.
    """

    id: str
    kind: ClaimKind
    description: str
    regexes: tuple[re.Pattern[str], ...]
    build: Callable[[dict[str, str | None]], Built]
    examples: tuple[str, ...] = ()
    non_examples: tuple[str, ...] = ()


def _rx(*sources: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(s, _I) for s in sources)


def _only(x: str | None, cat: str | None, *, default_cat: str | None = None) -> Built:
    x, cat = clean_term(x), clean_term(cat) or default_cat
    if not x or not cat:
        return None
    return cat.lower(), {"only": [x], "category": cat}


def _b_only_category(g: dict) -> Built:
    return _only(_strip_lead(g["x"]), g["cat"])


def _b_only_use_for(g: dict) -> Built:
    return _only(g["x"], g["cat"])


def _b_only_via(g: dict) -> Built:
    if not (g.get("o1") or g.get("o2")):
        return None
    who, q = _strip_lead(g["who"]), clean_term(g["q"])
    if not who or not q:
        return None
    return "communication", {"only": [q], "between": who}


def _b_standardise(g: dict) -> Built:
    return _only(g["x"], g.get("cat"), default_cat="technology")


def _b_no_outside(g: dict) -> Built:
    y, z = clean_term(g["y"]), _paths(g["z"])
    if not y or not z:
        return None
    return y.lower(), {"target": [y], "allowed_in": z}


_b_not_outside = _b_no_outside


def _b_only_from(g: dict) -> Built:
    y, z = _strip_lead(g["y"]), _paths(g["z"])
    if not y or not z:
        return None
    return y.lower(), {"target": [y], "allowed_in": z}


def _b_only_actor(g: dict) -> Built:
    y, z = clean_term(g["y"]), _paths(g["z"])
    if not y or not z:
        return None
    return y.lower(), {"target": [y], "allowed_in": z, "action": _base_verb(g["v"])}


def _b_through(g: dict) -> Built:
    a, b = _strip_lead(g["a"]), clean_term(g["b"])
    if not a or not b:
        return None
    return a.lower(), {"target": [a], "via": [b]}


def _forbid(who: str | None, items: list[str], **extra: Any) -> Built:
    if not items:
        return None
    rule: dict[str, Any] = {"forbid": items}
    rule.update({k: v for k, v in extra.items() if v})
    return (who.lower() if who else "codebase"), rule


def _b_no_actor_may(g: dict) -> Built:
    who = clean_term(g["who"])
    if not who:
        return None
    return _forbid(who, split_list(g["y"]), action=_base_verb(g["v"]))


def _b_must_not(g: dict) -> Built:
    who = _strip_lead(g.get("who"))
    if g.get("who") and who is None:
        return None  # "It must not use ..." names no subject we can test
    scope = _paths(g.get("scope"))
    return _forbid(who, split_list(g["y"]), action=_base_verb(g["v"]), scope=scope)


def _b_not_allowed(g: dict) -> Built:
    y = _strip_lead(g["y"])
    if not y:
        return None
    return _forbid(None, [y], scope=_paths(g.get("scope")))


def _b_not_be_used(g: dict) -> Built:
    y = _strip_lead(g["y"])
    if not y:
        return None
    return _forbid(None, [y], action=_base_verb(g["v"]), scope=_paths(g.get("scope")))


def _b_never(g: dict) -> Built:
    return _forbid(None, split_list(g["y"]), action=_base_verb(g["v"]))


def _require(subject: str | None, x: str | None, cat: str | None) -> Built:
    x = clean_term(x)
    if not x or x.lower().startswith(("only ", "not ")):
        return None
    cat = clean_term(cat)
    rule: dict[str, Any] = {"require": [x]}
    if cat:
        rule["for"] = cat
    return (subject or (cat.lower() if cat else "technology")), rule


def _b_chosen(g: dict) -> Built:
    return _require("chosen option", g["x"], None)


def _b_must_use(g: dict) -> Built:
    who = _strip_lead(g["who"])
    if not who:
        return None
    return _require(who.lower(), g["x"], g.get("cat"))


def _b_all_use(g: dict) -> Built:
    who = clean_term(g["who"])
    if not who:
        return None
    return _require(who.lower(), g["x"], None)


def _b_we_use(g: dict) -> Built:
    return _require(None, g["x"], g.get("cat"))


RULES: tuple[RulePattern, ...] = (
    # ---- boundary -------------------------------------------------------------
    RulePattern(
        "boundary-no-outside",
        "boundary",
        '"No Y outside Z/": Y is allowed only inside Z.',
        _rx(
            rf"\bno\s+{_term('y')}\s+(?:(?:is|are)\s+(?:allowed|permitted|used)\s+|"
            rf"may\s+be\s+used\s+|(?:imports?|usages?|uses|calls?|access)\s+)?"
            rf"outside\s+(?:of\s+)?{_term('z')}{_STOP}"
        ),
        _b_no_outside,
        examples=(
            "No cloud SDK outside adapters/.",
            "No SQL is allowed outside the repository layer.",
            "No boto3 imports outside of `infra/aws/`.",
        ),
        non_examples=("No cloud SDK is used today.", "There is no outside contractor."),
    ),
    RulePattern(
        "boundary-not-outside",
        "boundary",
        '"Y must not be used/imported outside Z".',
        _rx(
            rf"{_subj('y')}\s+(?:must|shall|may|should|can)\s*(?:not|never|n't)\s+be\s+"
            rf"(?:{_PASSIVE})\s+outside\s+(?:of\s+)?{_term('z')}{_STOP}"
        ),
        _b_not_outside,
        examples=(
            "Cloud SDKs must not be used outside adapters/.",
            "The ORM may not be imported outside of the persistence package.",
        ),
        non_examples=("Cloud SDKs must not be used.", "Cloud SDKs must be used outside tests."),
    ),
    RulePattern(
        "boundary-only-from",
        "boundary",
        '"Y may be imported only from Z" / "Y may only be used in Z".',
        _rx(
            rf"{_subj('y')}\s+(?:may|can|must|shall|should|will|are to|is to)\s+"
            rf"(?:only\s+be\s+(?:{_PASSIVE})|be\s+(?:{_PASSIVE})\s+(?:only|exclusively|solely))"
            rf"\s+(?:from|in|within|inside|by|through)\s+{_term('z')}{_STOP}"
        ),
        _b_only_from,
        examples=(
            "Cloud provider SDKs may be imported only from the `adapters/` package.",
            "Database drivers may only be imported from the persistence layer.",
            "The payments API must be called only by the billing service.",
        ),
        non_examples=(
            "Cloud provider SDKs may be imported from anywhere.",
            "Cloud SDKs may only be discussed in meetings.",
        ),
    ),
    RulePattern(
        "boundary-only-actor-may",
        "boundary",
        '"Only Z may access/import Y".',
        _rx(
            rf"(?<!not\s)\bonly\s+{_term('z')}\s+(?:may|can|is allowed to|are allowed to|"
            rf"shall|should|must)\s+(?P<v>import|use|access|call|talk to|write to|read from|"
            rf"depend on|reference|query)\s+{_term('y')}{_STOP}"
        ),
        _b_only_actor,
        examples=(
            "Only the billing service may access the payments database.",
            "Only adapters/ may import boto3.",
        ),
        non_examples=(
            "Only the billing service was migrated.",
            "The billing service may access the payments database.",
        ),
    ),
    RulePattern(
        "boundary-go-through",
        "boundary",
        '"All A must go through B": A is allowed only via B.',
        _rx(
            rf"{_subj('a')}\s+(?:must|shall|should|will|has to|have to|is to|are to)\s+"
            rf"(?:always\s+)?(?:go|pass|be routed|be sent|flow|be made|be proxied)\s+"
            rf"(?:through|via)\s+{_term('b')}{_STOP}"
        ),
        _b_through,
        examples=(
            "All database access must go through the repository layer.",
            "External HTTP calls must be routed through the API gateway.",
        ),
        non_examples=("All tests must pass.", "All requests go through review."),
    ),
    # ---- only -----------------------------------------------------------------
    RulePattern(
        "only-communicate-via",
        "only",
        '"Services communicate only via Q".',
        _rx(
            rf"{_subj('who')}\s+(?:must\s+|shall\s+|should\s+|will\s+|may\s+|can\s+)?"
            rf"(?P<o1>only\s+|exclusively\s+|solely\s+)?"
            rf"(?:communicate|talk|interact|integrate|exchange (?:data|messages))"
            rf"(?:\s+(?:with|to)\s+(?:each other|one another))?\s+"
            rf"(?P<o2>only\s+|exclusively\s+|solely\s+)?"
            rf"(?:via|through|over|using|by way of)\s+{_term('q')}{_STOP}"
        ),
        _b_only_via,
        examples=(
            "Services talk to each other only through the event bus.",
            "Microservices must communicate exclusively via Kafka topics.",
            "Services only communicate over gRPC.",
        ),
        non_examples=(
            "Services communicate via the event bus.",
            "Teams talk to each other only on Slack.",
        ),
    ),
    RulePattern(
        "only-use-for",
        "only",
        '"Use only X for Y" / "Only X may be used for Y".',
        _rx(
            rf"(?<!not\s)\b(?:use|uses|using)\s+only\s+{_term('x')}\s+(?:for|as)\s+"
            rf"{_term('cat')}{_STOP}",
            rf"(?<!not\s)\bonly\s+{_term('x')}\s+(?:may|can|shall|must|should|will)\s+be\s+"
            rf"used\s+(?:for|as)\s+{_term('cat')}{_STOP}",
        ),
        _b_only_use_for,
        examples=("We use only Redis for caching.", "Only structlog may be used for logging."),
        non_examples=(
            "We use Redis for caching.",
            "Not only Redis but also Memcached are used for caching.",
        ),
    ),
    RulePattern(
        "only-category",
        "only",
        '"X is the only <category>".',
        _rx(
            rf"{_subj('x')}\s+(?:is|are|will be|shall be|remains|remain|stays|becomes)\s+"
            rf"(?:the|our)\s+(?:only|sole|single|one and only|exclusive)\s+"
            rf"{_term('cat')}{_STOP}"
        ),
        _b_only_category,
        examples=(
            "PostgreSQL is the only datastore.",
            "Kafka will be the sole message broker for all services.",
            "React is our only frontend framework.",
        ),
        non_examples=(
            "PostgreSQL is not the only datastore we evaluated.",
            "Is PostgreSQL the only datastore?",
            "PostgreSQL is the primary datastore.",
        ),
    ),
    RulePattern(
        "only-standardise-on",
        "only",
        '"We standardise on X (for Y)".',
        _rx(
            rf"\bstandardi[sz](?:e|es|ed)\s+on\s+{_term('x')}"
            rf"(?:\s+(?:for|as)\s+{_term('cat')})?{_STOP}"
        ),
        _b_standardise,
        examples=(
            "We standardise on structlog for logging.",
            "The team standardized on Terraform.",
        ),
        non_examples=("We did not standardise anything.", "Standards on logging are TBD."),
    ),
    # ---- forbid ---------------------------------------------------------------
    RulePattern(
        "forbid-no-actor-may",
        "forbid",
        '"No <actor> may add/use Y".',
        _rx(
            rf"\bno\s+{_term('who')}\s+(?:may|shall|can|must|should|will|is allowed to|"
            rf"are allowed to|is permitted to)\s+(?P<v>{_VERBS})\s+{_list('y')}{_LSTOP}"
        ),
        _b_no_actor_may,
        examples=(
            "No service may add another database, cache-as-database or document store "
            "without a new ADR that supersedes this one.",
            "No module may import boto3 directly.",
        ),
        non_examples=("No decision was made on caching.", "No service has been migrated yet."),
    ),
    RulePattern(
        "forbid-must-not",
        "forbid",
        '"(A) must not use/import Y", "Do not use Y".',
        _rx(
            rf"(?:{_subj('who')}\s+)?(?:{_NEG_MODAL})\s+(?:directly\s+|ever\s+)?"
            rf"(?P<v>{_VERBS})\s+{_list('y')}"
            rf"(?:\s+(?:in|from|within|inside)\s+{_term('scope')})?{_LSTOP}"
        ),
        _b_must_not,
        examples=(
            "Services must not import the requests library.",
            "Do not use MongoDB.",
            "The domain layer must never depend on Django or Flask.",
            "Handlers are not allowed to call the database directly.",
        ),
        non_examples=(
            "Services must use the event bus.",
            "We must not forget the migration plan.",
            "We will not delay the release.",
        ),
    ),
    RulePattern(
        "forbid-must-not-be-used",
        "forbid",
        '"Y must not be used/imported".',
        _rx(
            rf"{_subj('y')}\s+(?:must|shall|may|should|can|will)\s*(?:not|never|n't)\s+be\s+"
            rf"(?P<v>{_PASSIVE})(?:\s+(?:in|within|inside|by|from)\s+{_term('scope')})?{_STOP}"
        ),
        _b_not_be_used,
        examples=(
            "MongoDB must not be used.",
            "The legacy client should never be imported by new services.",
        ),
        non_examples=("MongoDB must be used.", "MongoDB must not be forgotten."),
    ),
    RulePattern(
        "forbid-not-allowed",
        "forbid",
        '"Y is not allowed / forbidden / prohibited".',
        _rx(
            rf"{_subj('y')}\s+(?:is|are|will be|shall be|remain|remains)\s+"
            rf"(?:not\s+(?:allowed|permitted)|forbidden|prohibited|banned|disallowed)"
            rf"(?:\s+(?:in|within|inside|from)\s+{_term('scope')})?{_STOP}"
        ),
        _b_not_allowed,
        examples=(
            "Synchronous service-to-service HTTP calls are not allowed.",
            "Global mutable singletons are forbidden.",
            "Raw SQL is prohibited in controllers.",
        ),
        non_examples=(
            "Exceptions are allowed with approval.",
            "This is not allowed.",
            "It is forbidden.",
        ),
    ),
    RulePattern(
        "forbid-never",
        "forbid",
        '"Never import Y" / "We never use Y".',
        _rx(rf"\b(?:we\s+|they\s+)?never\s+(?P<v>{_VERBS})\s+{_list('y')}{_LSTOP}"),
        _b_never,
        examples=("Never import pandas in request handlers.", "We never use ORMs."),
        non_examples=("We never expected this growth.", "It never rains."),
    ),
    # ---- require --------------------------------------------------------------
    RulePattern(
        "require-chosen-option",
        "require",
        'MADR "Chosen option: X".',
        _rx(r"^chosen\s+option\s*:\s*\"?(?P<x>[^\",]+?)\"?(?=\s*,|\s+because\b|\.?\s*$)"),
        _b_chosen,
        examples=(
            'Chosen option: "FastAPI", because it gives typed request models.',
            "Chosen option: structlog.",
            'Chosen option: "in-process LRU cache", because it needs no new datastore.',
        ),
        non_examples=("We have not chosen an option yet.", "Considered option: Flask."),
    ),
    RulePattern(
        "require-must-use",
        "require",
        '"A must use X (for Y)".',
        _rx(
            rf"{_subj('who')}\s+(?:must|shall|should|are required to|is required to|"
            rf"have to|has to|need to|needs to)\s+(?:always\s+)?(?:use|be built (?:with|on)|"
            rf"be written in|run on)\s+{_term('x')}(?:\s+for\s+{_term('cat')})?{_STOP}"
        ),
        _b_must_use,
        examples=(
            "All services must use structlog for logging.",
            "Every service must be written in Go.",
            "Frontends shall be built with React.",
        ),
        non_examples=("Services must not use structlog.", "You must use your judgement."),
    ),
    RulePattern(
        "require-all-use",
        "require",
        '"All A use X".',
        _rx(
            rf"\b(?:all|every|each)\s+{_term('who')}\s+(?:use|uses|run on|runs on|"
            rf"is built with|are built with|is written in|are written in)\s+{_term('x')}{_STOP}"
        ),
        _b_all_use,
        examples=(
            "All text columns use UTF-8 and names are stored exactly as entered.",
            "Every service runs on Kubernetes.",
        ),
        non_examples=("All services were reviewed.", "Some services use Redis."),
    ),
    RulePattern(
        "require-we-will-use",
        "require",
        '"We will use X (as/for Y)".',
        _rx(
            rf"\bwe\s+(?:will\s+|shall\s+|have decided to\s+|decided to\s+|are going to\s+|"
            rf"agreed to\s+|have agreed to\s+|choose to\s+|chose to\s+)?"
            rf"(?:use|adopt|go with|build on|rely on)\s+{_term('x')}"
            rf"(?:\s+(?:as|for)\s+(?:our\s+|the\s+|a\s+|an\s+)?{_term('cat')})?{_STOP}"
        ),
        _b_we_use,
        examples=(
            "We will use RabbitMQ as the message broker.",
            "We will use Architecture Decision Records, as described by Michael Nygard.",
            "We have decided to adopt Terraform for infrastructure.",
        ),
        non_examples=(
            "We will not use MongoDB.",
            "We will revisit this decision in a year.",
            "Should we use MongoDB?",
        ),
    ),
)

PATTERNS: dict[str, RulePattern] = {p.id: p for p in RULES}

# --------------------------------------------------------------------------- sentences

_BULLET = re.compile(r"^\s*(?:[*+-]|\d+[.)])\s+")
_FENCE_LINE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^\s*#{1,6}(\s|$)")
_SENT_END = re.compile(r"[.!?]+[\"')\]]*(?=\s|$)")
_ABBREV = {"e.g", "i.e", "etc", "vs", "cf", "approx", "incl", "esp", "resp", "fig", "no"}


def sentence_spans(text: str) -> list[tuple[int, int]]:
    """Character spans ``[start, end)`` of the prose sentences of ``text``.

    Blank lines, headings, table rows and list items start a new block; fenced
    code is skipped; a list marker is not part of the sentence.
    """
    blocks: list[tuple[int, int]] = []
    cur: list[int] | None = None
    in_fence = False
    offset = 0
    for line in text.split("\n"):
        start, end = offset, offset + len(line)
        offset = end + 1
        if _FENCE_LINE.match(line):
            in_fence = not in_fence
            cur = _flush(blocks, cur)
            continue
        stripped = line.strip()
        if in_fence or not stripped or _HEADING.match(line) or stripped.startswith("|"):
            cur = _flush(blocks, cur)
            continue
        m = _BULLET.match(line)
        if m:
            cur = _flush(blocks, cur)
            s = start + m.end()
        else:
            s = start + (len(line) - len(line.lstrip()))
        if cur is None:
            cur = [s, end]
        else:
            cur[1] = end
    _flush(blocks, cur)

    spans: list[tuple[int, int]] = []
    for bs, be in blocks:
        s = bs
        for m in _SENT_END.finditer(text, bs, be):
            word = re.search(r"([\w.]+)[.!?]*$", text[s : m.start() + 1])
            tail = word.group(1).rstrip(".").lower() if word else ""
            if m.group(0).startswith(".") and (tail in _ABBREV or len(tail) == 1):
                continue
            spans.append((s, m.end()))
            s = m.end()
            while s < be and text[s].isspace():
                s += 1
        if s < be and text[s:be].strip():
            spans.append((s, be))
    return [(a, b) for a, b in spans if text[a:b].strip()]


def _flush(blocks: list[tuple[int, int]], cur: list[int] | None) -> None:
    if cur is not None and cur[1] > cur[0]:
        blocks.append((cur[0], cur[1]))
    return None


def clean_sentence(raw: str) -> str:
    """The text the patterns see: G1-normalised (paired emphasis removed, curly quotes
    straightened, whitespace collapsed) with code backticks dropped."""
    return normalise(raw).replace("`", "").strip()


# --------------------------------------------------------------------------- matching


@dataclass(frozen=True)
class Match:
    pattern: str
    kind: ClaimKind
    subject: str
    rule: dict[str, Any]
    span: tuple[int, int]  # in the cleaned sentence


def match_sentence(sentence: str, patterns: Iterable[RulePattern] = RULES) -> list[Match]:
    """Typed matches for one sentence, in priority order, without overlaps."""
    clean = clean_sentence(sentence)
    if not clean or clean.endswith("?"):
        return []
    taken: list[tuple[int, int]] = []
    out: list[Match] = []
    for pat in patterns:
        for rx in pat.regexes:
            for m in rx.finditer(clean):
                span = m.span()
                if span[0] == span[1] or any(span[0] < b and a < span[1] for a, b in taken):
                    continue
                built = pat.build(m.groupdict())
                if built is None:
                    continue
                subject, rule = built
                if rule_errors(pat.kind, rule):
                    continue
                taken.append(span)
                out.append(Match(pat.id, pat.kind, subject, rule, span))
    return out


# --------------------------------------------------------------------------- claims


@dataclass
class RejectedHint:
    """A front-matter hint that could not be turned into a claim (reported, not dropped)."""

    kind: str
    subject: str
    rule: Any
    source: Provenance | None
    reason: str


@dataclass
class RuleResult:
    claims: list[Claim] = field(default_factory=list)
    rejected: list[RejectedHint] = field(default_factory=list)


def _quote_for(lines: list[str], first: int, last: int, raw: str) -> str:
    """``raw`` when it normalises into lines ``first..last`` (0-based), else the lines."""
    block = "\n".join(lines[first : last + 1])
    needle = normalise(raw)
    if needle and needle in normalise(block):
        return raw
    return block


def extract_rule_claims(decision: Decision, text: str | None = None) -> RuleResult:
    """Offline claims for ``decision``: phrase patterns over its decision text, plus
    front-matter hints when the ADR's full ``text`` (at ``decision.source.commit``) is
    given. Never raises on odd content."""
    result = RuleResult()
    src = decision.source
    body = decision.decision_text
    body_lines = body.split("\n")
    n = 0
    for s, e in sentence_spans(body):
        raw = body[s:e]
        matches = match_sentence(raw)
        if not matches:
            continue
        first = body.count("\n", 0, s)
        last = body.count("\n", 0, e)
        prov = Provenance(
            path=src.path,
            line_start=src.line_start + first,
            line_end=src.line_start + last,
            commit=src.commit,
            quote=_quote_for(body_lines, first, last, raw),
        )
        for m in matches:
            n += 1
            result.claims.append(
                Claim(
                    id=f"{decision.id}.c{n}",
                    kind=m.kind,
                    subject=m.subject,
                    rule=m.rule,
                    source=prov,
                    decision_id=decision.id,
                    origin="rule",
                    pattern=m.pattern,
                )
            )
    if text is not None:
        hints = extract_hint_claims(decision, text, start=n)
        result.claims.extend(hints.claims)
        result.rejected.extend(hints.rejected)
    return result


# --------------------------------------------------------------------------- hints

HINT_KEY = "driftwarden"
_HINT_KINDS = ("forbid", "require", "only", "boundary", "free")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _hint_ranges(
    lines: list[str], fm_end: int
) -> tuple[tuple[int, int], dict[str, tuple[int, int]]]:
    """0-based inclusive line ranges: the whole ``driftwarden:`` block, and per sub-key."""
    key_idx = next(
        (i for i in range(1, fm_end) if re.match(rf"^{HINT_KEY}\s*:", lines[i].lstrip("﻿"), _I)),
        None,
    )
    if key_idx is None:
        return (0, 0), {}
    end = fm_end
    for j in range(key_idx + 1, fm_end):
        if lines[j].strip() and not lines[j][0].isspace() and not lines[j].lstrip().startswith("#"):
            end = j
            break

    def trim(a: int, b: int) -> tuple[int, int]:  # [a, b) -> inclusive, no trailing blanks
        while b - 1 > a and (not lines[b - 1].strip() or lines[b - 1].lstrip().startswith("#")):
            b -= 1
        return a, b - 1

    whole = trim(key_idx, end)
    children = [j for j in range(key_idx + 1, end) if lines[j].strip()]
    subs: dict[str, tuple[int, int]] = {}
    if children:
        child_indent = min(_indent(lines[j]) for j in children)
        keys = [
            (j, m.group(1).lower())
            for j in children
            if _indent(lines[j]) == child_indent
            and (m := re.match(r"^\s*([A-Za-z_-]+)\s*:", lines[j]))
        ]
        for k, (j, name) in enumerate(keys):
            nxt = keys[k + 1][0] if k + 1 < len(keys) else end
            subs[name] = trim(j, nxt)
    return whole, subs


def _as_list(value: Any) -> list[str] | None:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        items = [str(value)]
    elif isinstance(value, list) and all(
        isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in value
    ):
        items = [str(v) for v in value]
    else:
        return None
    items = [i.strip() for i in items if i.strip()]
    return items or None


def _hint_specs(kind: str, value: Any) -> list[tuple[str, Any, str | None]]:
    """(subject, rule, error) triples for one hint key."""
    if kind in ("forbid", "require"):
        if isinstance(value, dict):
            out = []
            for subj, items in value.items():
                lst = _as_list(items)
                out.append((str(subj), {kind: lst or items}, None if lst else "expected a list"))
            return out or [("codebase", value, "empty mapping")]
        lst = _as_list(value)
        return [("codebase", {kind: lst or value}, None if lst else "expected a list of names")]
    if kind == "only":
        if isinstance(value, dict):
            out = []
            for cat, items in value.items():
                lst = _as_list(items)
                rule = {"only": lst or items, "category": str(cat)}
                out.append((str(cat), rule, None if lst else "expected a list"))
            return out or [("technology", value, "empty mapping")]
        lst = _as_list(value)
        return [("technology", {"only": lst or value}, None if lst else "expected a list")]
    if kind == "boundary":
        entries = value if isinstance(value, list) else [value]
        out = []
        for entry in entries:
            if not isinstance(entry, dict):
                out.append(("boundary", entry, "expected {target, allowed_in | via}"))
                continue
            rule: dict[str, Any] = {}
            for key in ("target", "allowed_in", "via"):
                if key in entry:
                    rule[key] = _as_list(entry[key]) or entry[key]
            target = rule.get("target")
            subj = str(entry.get("subject") or (target[0] if isinstance(target, list) else ""))
            out.append((subj.lower() or "boundary", rule, None))
        return out
    # free
    lst = _as_list(value)
    if lst is None:
        return [("free", value, "expected a string or a list of strings")]
    return [("free", {"text": t}, None) for t in lst]


def extract_hint_claims(decision: Decision, text: str, *, start: int = 0) -> RuleResult:
    """Claims from a ``driftwarden:`` block in the ADR's YAML front-matter."""
    result = RuleResult()
    lines = split_lines(text)
    if not lines or lines[0].strip() != "---":
        return result
    fm_end = next((i for i in range(1, len(lines)) if lines[i].strip() in ("---", "...")), None)
    if fm_end is None:
        return result
    src = decision.source
    whole, subs = _hint_ranges(lines, fm_end)

    def prov(rng: tuple[int, int]) -> Provenance:
        a, b = rng
        return Provenance(
            path=src.path,
            line_start=a + 1,
            line_end=b + 1,
            commit=src.commit,
            quote="\n".join(lines[a : b + 1]),
        )

    try:
        data = yaml.safe_load("\n".join(lines[1:fm_end]))
    except yaml.YAMLError as exc:
        if subs or whole != (0, 0):
            reason = f"front-matter is not valid YAML: {str(exc).splitlines()[0]}"
            result.rejected.append(RejectedHint("hint", "front-matter", None, prov(whole), reason))
        return result
    if not isinstance(data, dict):
        return result
    hints = next((v for k, v in data.items() if str(k).lower() == HINT_KEY), None)
    if hints is None:
        return result
    if not isinstance(hints, dict):
        result.rejected.append(
            RejectedHint(
                "hint", HINT_KEY, hints, prov(whole), f"'{HINT_KEY}' must be a mapping of kinds"
            )
        )
        return result

    n = start
    for raw_kind, value in hints.items():
        kind = str(raw_kind).lower()
        p = prov(subs.get(kind, whole))
        if kind not in _HINT_KINDS:
            reason = f"unknown hint kind {raw_kind!r} (expected one of {', '.join(_HINT_KINDS)})"
            result.rejected.append(RejectedHint(kind, kind, value, p, reason))
            continue
        for subject, rule, error in _hint_specs(kind, value):
            errors = [error] if error else rule_errors(kind, rule)
            if errors:
                reason = "invalid front-matter hint: " + "; ".join(errors)
                result.rejected.append(RejectedHint(kind, subject, rule, p, reason))
                continue
            n += 1
            result.claims.append(
                Claim(
                    id=f"{decision.id}.c{n}",
                    kind=kind,  # type: ignore[arg-type]
                    subject=subject,
                    rule=rule,
                    source=p,
                    decision_id=decision.id,
                    origin="hint",
                    pattern=f"hint:{kind}",
                )
            )
    return result
