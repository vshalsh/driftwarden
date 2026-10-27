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

Precision guards (a missed rule costs recall; an invented or inverted one is a false
VIOLATED, so the library errs towards no claim):

* **Clause coverage** (``_covered``, the one place where matches become claims): a
  match must account for its whole clause. Text it did not capture -- a leading actor
  or location ("In adapters/, ..."), a list member ("PostgreSQL and | Redis are the
  only ..."), a trailing purpose / location / time ("... for analytics", "... in
  production", "(for analytics)"), a relative clause ("... that is not allowed") --
  drops the clause's claims. Only a short whitelist may be left over: articles,
  linking words ("therefore", "from today"), universal phrases ("for all services",
  "in the codebase", "anywhere"), rationale ("because ...", "rather than X",
  "instead of X", "as described by ...") and ADR boilerplate ("without a new ADR").
  A trailing manner adverb ("directly", "synchronously") is captured as ``manner``.
* A sentence that reports, hedges, conditions or time-limits a statement yields no
  claim: rejected/dropped proposals and draft labels ("Rejected:", "Proposal:",
  "Option A:", "TODO:", "(draft)", "(TBD)"), reported speech in any tense ("says",
  "said that", "stated that", "suggested", "Nobody thinks ..."), hedges and frequency
  adverbs ("maybe", "generally", "typically", "currently"), conditions and exceptions
  ("if", "unless", "except", "other than") and time limits ("until", "before",
  "after", "once", "during", "pending", "this quarter", "for six months", "for now").
* A negator before a match in its clause, or inside a require/only match ("Services
  don't have to use X", "need not", "rarely"), drops it.
* A require/only/boundary term that is one of several alternatives or a bound ("Redis
  or Memcached", "Python 3.11 or later"), no choice ("Chosen option: none"), a
  negative noun phrase ("no external database") or a fragment ("Redis not Memcached",
  "more than one", "[Redis]", "Redis / Memcached") yields no claim. Conjunctive
  members are kept whole ("Only Redis and Memcached may be used" -> both; "outside
  repo/ and db/" -> both allowed).
* Fenced code (CommonMark fence rules), indented code (also inside list items) and
  sections headed "Alternatives considered" / "Rejected" / "Options" are not prose.

Known limits (recall gaps, documented rather than guessed at):

* Clause coverage is lexical and fail-closed: any uncaptured content word drops the
  claim, so legitimate decorations outside the whitelist ("We will use Kafka, which
  gives us replay") cost the claim. Conjunctive subjects ("PostgreSQL and Redis are
  the only datastores", "Services and handlers must not use X") yield no claim.
* The guards are lexical: "before", "after", "once", "during", "says", "claims",
  "states", "proposed", "currently", "generally", ... anywhere in a sentence drop it,
  including real rules that merely mention them; exceptions ("except in tests") are
  not modelled.
* Curly-/guillemet-quoted terms ("We will use “Postgres”", "«Zürich-DB»") end the
  term at the quote mark and usually yield no claim.
* Inverted phrasings: "The only datastore is PostgreSQL", "Nothing outside adapters/
  may import boto3", "boto3 imports are restricted to adapters/", "No service uses
  MongoDB" (present tense), "Services do not communicate via REST".
* Passive / descriptive forms: "Every service is deployed on Kubernetes", "All HTTP
  traffic goes through the gateway" (no modal).
* "We decided not to use X", "We are not going to use X" and "We no longer use X"
  yield no claim.
* A second verbal clause without its own subject ("Services must not use Redis and
  must use PostgreSQL") ends the first claim but yields no claim of its own.
* An allowed channel or route given as alternatives ("only via Kafka or RabbitMQ",
  "through X or Y"), and an "any of" choice ("We will use Redis or Memcached"), yield
  no claim rather than a stricter one.
* Hint keys that differ only in case inside one block (``forbid`` / ``Forbid``) are
  reported as unverified; root ``driftwarden:`` blocks are each cited from their own
  lines (an exact duplicate is reported and the kept one cited).
* An actor of an active-voice boundary ("Services must not import boto3 outside
  adapters/") is kept as ``actor``; the judge decides how to scope it.
"""

from __future__ import annotations

import bisect
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
    r"would|not|never|do|does|did|that|which|because|so|then|if|when|while|use|uses|"
    # negators and hedges never belong to a subject ("Services don't have to use X")
    r"don't|doesn't|won't|isn't|aren't|can't|cannot|need|needs|no|hardly|rarely|seldom|"
    r"scarcely|generally|usually|typically|normally|currently|presently"
)
_W = rf"(?!(?:{_SUBJ_STOP})\b)[\w.+#/@'-]+"


def _term(name: str) -> str:
    return rf"(?P<{name}>{_C}{{1,120}}?)"


def _list(name: str) -> str:
    return rf"(?P<{name}>{_LC}{{1,240}}?)"


def _subj(name: str) -> str:
    return rf"(?<![\w.+#/@'-])(?P<{name}>{_W}(?:\s+{_W}){{0,5}}?)"


# Manner adverbs that qualify a ban/requirement ("must not call X directly"): they end
# a term and are kept on the claim as ``manner``.
_MANNER_WORDS = (
    "directly|indirectly|synchronously|asynchronously|transitively|explicitly|implicitly|"
    "manually|automatically|locally|remotely|globally|dynamically|statically"
)
_STOP_WORDS = (
    "and|or|nor|but|because|so|when|unless|except|without|instead|rather|for|as|in|from|within|"
    "inside|outside|via|through|to|which|that|if|is|are|was|were|will|would|must|may|"
    "should|shall|can|by|on|at|with|using|since|until|where|while|we|only|" + _MANNER_WORDS
)
# End of a single term: a clause word, clause punctuation, a sentence end or the end.
_STOP = rf"(?=\s+(?:{_STOP_WORDS})\b|\s*(?:[,;:!?()—–\"]|\.(?:\s|$))|\s*$)"
# End of a term list: commas and and/or are part of the list.
_LSTOP = (
    r"(?=\s+(?:without|unless|except|outside|because|in|from|within|inside|for|to|"
    r"when|if|so|since|until|unless|instead|rather|on|at|under|across|throughout|via|"
    r"through|over|during|" + _MANNER_WORDS + r")\b|\s*(?:[;:!?()—–\"]|\.(?:\s|$))|"
    r"\s*$|"
    # a new clause after a comma ("Don't use MongoDB, use PostgreSQL"): not a list item
    r"\s*,\s*(?:but|instead|rather|use|prefer|we|they|which|so|and\s+(?:use|prefer))\b|"
    # "(,) and PostgreSQL is the only datastore", "and must use X", "but never Y":
    # a new clause with its own verb, with or without a comma (a plain "X and Y" stays a list)
    r"\s*,?\s+(?:and|but|then)\s+(?:(?:must|shall|should|may|can|cannot|will|won't|do|does|"
    r"don't|never|always|is|are)\b|"
    r"(?:[\w.+#/@'-]+\s+){1,4}?(?:is|are|must|shall|should|will|may|can|cannot)\b))"
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
    r"additional|extra)\s+",  # not "new": "new services" is narrower than "services"
    _I,
)
_TRAIL = re.compile(r"\s+(?:directly|anymore|any more|at all|again|either|too|also)$", _I)
_PRONOUNS = {
    "it", "this", "that", "these", "those", "they", "them", "we", "you", "which", "there",
    "he", "she", "one", "i", "us", "what", "who", "nothing", "anything", "everything",
    "something", "here", "everyone", "anyone", "nobody", "other", "others", "each other",
    "one another",
}  # fmt: skip
# Not a technology name: a contrast, comparison, coordination or markup fragment
# ("Redis not Memcached", "more than one datastore", "Redis / Memcached", "[Redis]").
_JUNK_TERM = re.compile(
    r"\b(?:not|over|plus|than|versus|vs|must|will|may|shall|should)\b|[\[\]{}<>|\\]|\s/\s|^/$",
    re.IGNORECASE,
)
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
    if not t or t.lower() in _PRONOUNS or not re.search(r"\w", t) or _JUNK_TERM.search(t):
        return None
    return t


_OF_HEAD = re.compile(
    r"^(?:(?:use|usage|uses|import|imports|importing|adoption|introduction|addition|"
    r"inclusion)\s+)?of\s+",
    _I,
)


def _strip_lead(raw: str | None) -> str | None:
    """Drop filler words in front of a subject ("We decided that PostgreSQL" -> "PostgreSQL",
    "Use of MongoDB" -> "MongoDB")."""
    if raw is None:
        return None
    words = raw.split()
    while len(words) > 1 and words[0].lower() in _LEAD:
        words.pop(0)
    return clean_term(_OF_HEAD.sub("", " ".join(words)))


# A positive term that is really an alternative, a bound or the absence of a choice:
# "Redis or Memcached", "Python 3.11 or later", "neither X nor Y", "none". Turning it
# into require/only [X] would be stricter than (or the opposite of) the text.
_NOT_ONE_TERM = re.compile(
    r"\b(?:or|nor|and/or|either|neither|rather than|versus|vs|at least|at most)\b|\+$", _I
)
_NEGATIVE_NP = re.compile(r"(?:no|none|neither|nothing|never|nobody|not)\b", _I)
_NO_CHOICE = {
    "none", "nothing", "n/a", "na", "tbd", "tba", "undecided", "no option", "nothing yet",
    "not decided", "not yet decided", "to be decided", "pending", "unknown", "-",
}  # fmt: skip


def _single_term(x: str | None) -> str | None:
    """``x`` when it names one technology; None for alternatives, bounds and 'none'."""
    x = clean_term(x)
    if not x or _NOT_ONE_TERM.search(x) or x.lower().strip(" .!") in _NO_CHOICE:
        return None
    if _NEGATIVE_NP.match(x):
        return None  # "We use no external database": a prohibition, not a require
    return x


def split_list(raw: str | None) -> list[str]:
    """``"another database, cache-as-database or document store"`` -> three terms."""
    if raw is None:
        return []
    parts = re.split(r"\s*,\s*(?:(?:and|or|nor)\s+)?|\s+(?:and|or|nor|and/or)\s+", raw)
    out: list[str] = []
    for p in parts:
        t = clean_term(p)
        if t is None and _JUNK_TERM.search(p):
            return []  # one junk member: the list is not a list of names (fail closed)
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
    raw, cat = clean_term(x), clean_term(cat) or default_cat
    if not raw or not cat:
        return None
    if re.search(r",|&|\band\b", raw, _I):  # "Redis and Memcached": every member
        items = [_single_term(t) for t in split_list(raw)] if not _NOT_ONE_TERM.search(raw) else []
        if not items or not all(items):
            return None
    else:
        one = _single_term(raw)
        items = [one] if one else []
    if not items:
        return None
    return cat.lower(), {"only": items, "category": cat}


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


_WHOLE_CODEBASE = frozenset(
    {"we", "the team", "our team", "everything", "everyone", "all teams", "engineering",
     "the company", "the organisation", "the organization", "all code"}
)  # fmt: skip


def _b_standardise(g: dict) -> Built:
    who = " ".join((g.get("who") or "we").split()).lower()
    if who not in _WHOLE_CODEBASE:
        return None  # "Services standardise on X": an actor the only-claim cannot carry
    return _only(g["x"], g.get("cat"), default_cat="technology")


_MODAL_IN_TERM = re.compile(r"\b(?:may|must|shall|can|cannot|should|will|is|are)\b", _I)


def _b_no_outside(g: dict) -> Built:
    y, z = clean_term(g["y"]), _paths(g["z"])
    if not y or not z or _MODAL_IN_TERM.search(y):
        return None  # "No module may import boto3 outside ...": a clause, not a term
    return y.lower(), {"target": [y], "allowed_in": z}


def _b_not_outside(g: dict) -> Built:
    """ "(A) must not import Y outside Z": Y allowed only in Z; a named actor A is kept
    as ``actor`` (the restriction is on A's code)."""
    built = _b_no_outside(g)
    raw_who = g.get("who")
    if built is None or not raw_who or raw_who.strip().lower() in ("we", "they"):
        return built
    who = _strip_lead(raw_who)
    if who is None:
        return None
    subject, rule = built
    return subject, {**rule, "actor": [who]}


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
    raw_who = g.get("who")
    if raw_who and raw_who.strip().lower() == "we":
        raw_who = None  # "We will not use X": the team speaking for the whole codebase
    who = _strip_lead(raw_who)
    if raw_who and who is None:
        return None  # "It must not use ..." names no subject we can test
    scope = _paths(g.get("scope"))
    v = g.get("v")
    return _forbid(who, split_list(g["y"]), action=_base_verb(v) if v else None, scope=scope)


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
    raw_who = g.get("who")
    if raw_who and raw_who.strip().lower() in ("we", "they"):
        raw_who = None  # the team speaking for the whole codebase
    who = _strip_lead(raw_who)
    if raw_who and who is None:
        return None  # "It never ..." names no subject we can test
    scope = _paths(g.get("scope"))
    return _forbid(who, split_list(g["y"]), action=_base_verb(g["v"]), scope=scope)


def _require(subject: str | None, x: str | None, cat: str | None) -> Built:
    x = _single_term(x)
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
            rf"outside\s+(?:of\s+)?{_list('z')}{_LSTOP}"
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
            rf"(?:{_PASSIVE})\s+outside\s+(?:of\s+)?{_list('z')}{_LSTOP}",
            # active voice: "(A) must not import Y outside Z", "Never use Y outside Z"
            rf"(?:{_subj('who')}\s+)?"
            rf"(?:(?:{_NEG_MODAL})|\bnever|\bno\s+{_term('anyone')}\s+(?:may|shall|can|must|"
            rf"should|is allowed to|are allowed to))\s+(?:directly\s+)?(?:{_VERBS})\s+"
            rf"{_term('y')}\s+outside\s+(?:of\s+)?{_list('z')}{_LSTOP}",
        ),
        _b_not_outside,
        examples=(
            "Cloud SDKs must not be used outside adapters/.",
            "The ORM may not be imported outside of the persistence package.",
            "Services must not import boto3 outside adapters/.",
            "Never import boto3 outside of `adapters/`.",
            "No module may use the ORM outside the persistence package.",
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
            rf"\s+(?:from|in|within|inside|by|through)\s+{_list('z')}{_LSTOP}"
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
            rf"(?:{_subj('who')}\s+)?(?:(?:have|has)\s+)?standardi[sz](?:e|es|ed)\s+on\s+"
            rf"{_term('x')}"
            rf"(?:\s+(?:for|as)\s+{_term('cat')})?{_STOP}"
        ),
        _b_standardise,
        examples=(
            "We standardise on structlog for logging.",
            "The team standardized on Terraform.",
        ),
        non_examples=(
            "We did not standardise anything.",
            "Standards on logging are TBD.",
            "We do not standardise on PostgreSQL.",
            "We won't standardise on PostgreSQL.",
        ),
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
        '"(A) must not use/import Y", "Do not use Y", "We will not use Y", "A must use '
        'neither X nor Y", "(We will) avoid Y".',
        _rx(
            rf"(?:{_subj('who')}\s+)?(?:{_NEG_MODAL})\s+(?:directly\s+|ever\s+)?"
            rf"(?P<v>{_VERBS})\s+{_list('y')}"
            rf"(?:\s+(?:in|from|within|inside)\s+{_term('scope')})?{_LSTOP}",
            rf"{_subj('who')}\s+(?:must|shall|should|may|can|will|are to|is to)\s+"
            rf"(?P<v>{_VERBS})\s+neither\s+{_list('y')}"
            rf"(?:\s+(?:in|from|within|inside)\s+{_term('scope')})?{_LSTOP}",
            rf"(?:^|\bwe\s+(?:will|shall|must|should)\s+)avoid\s+"
            rf"(?:(?P<v>using|importing|depending on|calling|adding|introducing)\s+)?"
            rf"{_list('y')}(?:\s+(?:in|from|within|inside)\s+{_term('scope')})?{_LSTOP}",
        ),
        _b_must_not,
        examples=(
            "Services must not import the requests library.",
            "Do not use MongoDB.",
            "The domain layer must never depend on Django or Flask.",
            "Handlers are not allowed to call the database directly.",
            "We will not use MongoDB.",
            "We do not use Redis.",
            "Services must use neither MongoDB nor Redis.",
            "We will avoid MongoDB.",
            "Avoid importing pandas in request handlers.",
        ),
        non_examples=(
            "Services must use the event bus.",
            "We must not forget the migration plan.",
            "We will not delay the release.",
            "We do not use Redis yet.",
            "Where possible, avoid MongoDB.",
            "We should try to avoid MongoDB.",
            "If we can, we will avoid Redis.",
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
            rf"(?:\b(?:the\s+)?(?:use|usage|imports?|adoption|introduction)\s+of\s+)?"
            rf"{_subj('y')}\s+(?:is|are|will be|shall be|remain|remains)\s+"
            rf"(?:not\s+(?:allowed|permitted)|forbidden|prohibited|banned|disallowed)"
            rf"(?:\s+(?:in|within|inside|from)\s+{_term('scope')})?{_STOP}"
        ),
        _b_not_allowed,
        examples=(
            "Synchronous service-to-service HTTP calls are not allowed.",
            "Global mutable singletons are forbidden.",
            "Raw SQL is prohibited in controllers.",
            "Use of MongoDB is prohibited.",
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
        _rx(
            rf"(?:{_subj('who')}\s+)?never\s+(?P<v>{_VERBS})\s+{_list('y')}"
            rf"(?:\s+(?:in|from|within|inside)\s+{_term('scope')})?{_LSTOP}"
        ),
        _b_never,
        examples=(
            "Never import pandas in request handlers.",
            "We never use ORMs.",
            "Request handlers never import pandas.",
        ),
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
        non_examples=(
            "We have not chosen an option yet.",
            "Considered option: Flask.",
            "Chosen option: none.",
            "Chosen option: Redis or Memcached.",
        ),
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
        non_examples=(
            "Services must not use structlog.",
            "You must use your judgement.",
            "Services must use neither MongoDB nor Redis.",
            "Services must use Python 3.11 or later.",
        ),
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
        '"We will use X (as/for Y)"; "Don\'t use Y, use X".',
        _rx(
            rf"\bwe\s+(?:will\s+|shall\s+|have decided to\s+|decided to\s+|are going to\s+|"
            rf"agreed to\s+|have agreed to\s+|choose to\s+|chose to\s+)?"
            rf"(?:use|adopt|go with|build on|rely on)\s+{_term('x')}"
            rf"(?:\s+(?:as|for)\s+(?:our\s+|the\s+|a\s+|an\s+)?{_term('cat')})?{_STOP}",
            # the alternative named after a ban; only the "use X" clause is claimed
            rf"^(?:do not|don't|never)\s+use\s+[^,;]{{1,120}}?[,;]\s+"
            rf"(?P<claim>(?:but\s+|instead\s+)?use\s+{_term('x')}(?:\s+instead)?){_STOP}",
        ),
        _b_we_use,
        examples=(
            "We will use RabbitMQ as the message broker.",
            "We will use Architecture Decision Records, as described by Michael Nygard.",
            "We have decided to adopt Terraform for infrastructure.",
            "Don't use MongoDB, use PostgreSQL.",
        ),
        non_examples=(
            "We will not use MongoDB.",
            "We will revisit this decision in a year.",
            "Should we use MongoDB?",
            "We will use Redis or Memcached.",
            "Maybe we will use Redis.",
            "If we need a cache, we will use Redis.",
            "Rejected: we will use MongoDB.",
        ),
    ),
)

PATTERNS: dict[str, RulePattern] = {p.id: p for p in RULES}

# --------------------------------------------------------------------------- sentences

_BULLET = re.compile(r"^\s*(?:[*+-]|\d+[.)])\s+")
# Any indentation (fences nested in list items); skipping too much only costs recall.
_FENCE_LINE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
_HEADING = re.compile(r"^\s*#{1,6}(\s|$)")
_SENT_END = re.compile(r"[.!?]+[\"')\]]*(?=\s|$)")
# Sub-headings inside a decision section whose content was NOT decided.
_NOT_CHOSEN_HEADING = re.compile(
    r"(?:(?:other|considered|rejected|discarded|alternative)\s+)?"
    r"(?:alternatives?|options?)(?:\s+(?:considered|rejected|not\s+chosen))?\s*$"
    r"|(?:rejected|discarded|not\s+chosen|pros\s+and\s+cons|pros|cons|"
    r"rejected\s+(?:options?|alternatives?|proposals?))\s*$",
    re.IGNORECASE,
)
_ABBREV = {"e.g", "i.e", "etc", "vs", "cf", "approx", "incl", "esp", "resp", "fig", "no"}


def sentence_spans(text: str) -> list[tuple[int, int]]:
    """Character spans ``[start, end)`` of the prose sentences of ``text``.

    Blank lines, headings, table rows and list items start a new block; fenced
    code and indented code (4+ columns beyond the enclosing indentation after a blank
    line: column 4 outside a list, the list item's content column + 4 inside one) are
    skipped; a list marker is not part of the sentence.
    """
    blocks: list[tuple[int, int]] = []
    cur: list[int] | None = None
    fence: str | None = None  # the opening fence run ("```", "~~~~") while inside one
    code_col: int | None = None  # inside an indented code block starting at this column
    in_list = False  # inside a list item (indented lines are its continuation)
    list_col = 0  # content column of the current list item
    skip_level: int | None = None  # inside a rejected/alternatives section of this level
    offset = 0
    for line in text.split("\n"):
        start, end = offset, offset + len(line)
        offset = end + 1
        fm = _FENCE_LINE.match(line.rstrip("\r"))
        if fence is not None:
            # CommonMark: closed only by the same character, at least as long, no info
            if fm and fm.group(1)[0] == fence[0] and len(fm.group(1)) >= len(fence):
                if not fm.group(2).strip():
                    fence = None
            continue
        if fm and not (fm.group(1)[0] == "`" and "`" in fm.group(2)):
            fence = fm.group(1)
            cur = _flush(blocks, cur)
            continue
        stripped = line.strip()
        if not stripped:
            cur = _flush(blocks, cur)
            continue
        col = _columns(line)
        if code_col is not None and col >= code_col:
            continue
        code_col = None
        m = _BULLET.match(line)
        if in_list and cur is None and not m and col < list_col:
            in_list = False  # a new paragraph outside the item
        base = list_col if in_list else 0
        if cur is None and col >= base + 4:
            code_col = base + 4
            continue
        h = _HEADING.match(line)
        if h:
            level = len(stripped) - len(stripped.lstrip("#"))
            if skip_level is not None and level <= skip_level:
                skip_level = None  # the rejected/alternatives section has ended
            if _NOT_CHOSEN_HEADING.match(stripped.lstrip("#").strip()):
                skip_level = level
        if skip_level is not None:
            cur = _flush(blocks, cur)
            continue  # under "### Alternatives considered", "## Rejected", ...
        if h or stripped.startswith("|"):
            cur = _flush(blocks, cur)
            in_list = False
            continue
        if m:
            in_list = True
            list_col = len(line[: m.end()].expandtabs(4))
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
            # bounded look-back: an abbreviation-dense block stays linear
            word = re.search(r"([\w.]+)[.!?]*$", text[max(s, m.start() - 64) : m.start() + 1])
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


def _columns(line: str) -> int:
    """Leading indentation in columns (a tab counts as 4)."""
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        elif ch == "\t":
            n += 4 - n % 4
        else:
            break
    return n


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


# Sentences that report, hedge, condition or time-box a statement instead of deciding
# it. They yield no claim at all (precision first: a missed rule costs recall, an
# invented or inverted one costs a false VIOLATED).
_NOT_A_DECISION = re.compile(
    # labels of drafts, proposals and alternatives
    r"^(?:rejected|dropped|discarded|abandoned|withdrawn|superseded|deprecated|"
    r"proposed|proposal|considered|alternatives?(?:\s+[a-z0-9])?|option\s+[a-z0-9]+|pros?|cons?|"
    r"draft|todo|to\s*do|tbd|tba|wip|idea|question|open\s+question)\s*:"
    r"|\((?:proposed|proposal|draft|tbd|tba|wip|tentative|pending|under\s+discussion|"
    r"to\s+be\s+(?:confirmed|decided|discussed|agreed))\)"
    r"|\b(?:rejected|dropped|discarded|abandoned|withdrawn|overruled|vetoed|"
    r"(?:was|were) not (?:adopted|accepted|chosen|pursued))\b"
    # reported speech, in any tense, with or without "that"
    r"|\b(?:says?|said|states|stated|suggests?|suggested|argues?|argued|claims|claimed|"
    r"thinks?|thought|believes?|believed|feels?|felt|proposes?|proposed|wrote|writes|"
    r"insists?|insisted|contends?|contended|speculated?|wondered|asked|nobody|no one)\b"
    # hedges and frequency / degree / descriptive-present adverbs
    r"|\b(?:maybe|perhaps|possibly|probably|potentially|hopefully|ideally|tentatively|"
    r"likely|might|generally|usually|typically|normally|mostly|largely|mainly|often|"
    r"sometimes|occasionally|frequently|rarely|seldom|hardly|scarcely|currently|presently|"
    r"in general|in most cases|for the most part)\b"
    # conditions and exceptions
    r"|\b(?:if|unless|in case|provided that|assuming|whether|should we)\b"
    r"|\b(?:except|excepting|excluding|other than|apart from|aside from|save for|"
    r"with the exception of|barring)\b"
    r"|\b(?:where|when|if|as) (?:possible|feasible|practical|appropriate|needed|necessary)\b"
    # time limits: a temporary statement is not a standing rule
    r"|\b(?:yet|for now|for the time being|at the moment|at present|temporarily|initially|"
    r"until|till|before|after|once|pending|during|meanwhile|in the (?:short|interim|meantime)|"
    r"short[- ]term)\b"
    r"|\b(?:this|next|the coming) (?:week|sprint|month|quarter|year|release)\b"
    r"|\bfor (?:\w+ )?(?:days?|weeks?|sprints?|months?|quarters?|years?)\b",
    _I,
)
# A negator in front of a match, in the same clause: "We do not standardise on X".
_NEGATOR = re.compile(
    r"\b(?:not|never|no longer|neither|nor|without|nobody|no one|none|rarely|hardly|"
    r"seldom|scarcely)\b|n't\b|\bneed not\b",
    _I,
)
_NEG_BOUNDARY = re.compile(r"[,;:()—–.!?]|\b(?:and|but|while|whereas|so|then)\b", _I)
_NEG_WINDOW = 300  # a negator further back than this in one clause is not looked for
# A term that is one of several alternatives: "Redis or Memcached", "3.11 or later".
_ALT_AFTER = re.compile(r"\s*(?:\bor\b|\bnor\b|\band/or\b|\+)", _I)
_ALT_BEFORE = re.compile(r"\b(?:or|nor|either|neither)\s*$", _I)


class _Clauses:
    """Clause starts of one sentence, computed once (keeps match_sentence linear)."""

    def __init__(self, clean: str) -> None:
        self.clean = clean
        self.starts = [0] + [m.end() for m in _NEG_BOUNDARY.finditer(clean)]

    def negated(self, start: int) -> bool:
        k = bisect.bisect_right(self.starts, start) - 1
        a = max(self.starts[k], start - _NEG_WINDOW)
        return bool(_NEGATOR.search(self.clean, a, start))


def _negated(clean: str, start: int) -> bool:
    return _Clauses(clean).negated(start)


# Capture groups that name what is allowed / required / the way through: a list cut
# short at "or" ("only via Kafka or RabbitMQ", "only in adapters/ or infra/") is
# stricter than the text. (Targets and forbid lists are split on "or" instead.)
_POSITIVE_GROUPS = ("x", "q", "z", "b")


def _alternative(clean: str, m: re.Match[str]) -> bool:
    """A positive term of ``m`` is one alternative or a bound, not a single choice."""
    for g in _POSITIVE_GROUPS:
        if g not in m.re.groupindex or m.group(g) is None:
            continue
        a, b = m.span(g)
        if _ALT_AFTER.match(clean, b) or _ALT_BEFORE.search(clean[max(0, a - 20) : a]):
            return True
    return False


# --------------------------------------------------------------------------- clause coverage
#
# The one place where a match becomes a claim checks that the match accounts for its
# whole clause. Text in the clause that no match captured (a leading actor, a trailing
# "for analytics" / "in production", a list member "PostgreSQL and | Redis are ...")
# would make the claim broader or narrower than the sentence, so the clause's matches
# are dropped (fail closed). Only fillers on a short whitelist may be left over.

_CLAUSE_VERB = re.compile(
    rf"\b(?:is|are|was|were|be|been|am|must|shall|should|may|can|cannot|will|would|could|"
    rf"do|does|did|has|have|had|need|needs|decided|agreed|chose|choose|prefer|"
    rf"{_VERBS}|{_PASSIVE})\b|n't\b",
    _I,
)
# Hard clause boundaries, and soft ones: a comma or conjunction that starts a new verbal
# clause ("..., use PostgreSQL", "... and services must not ...", "PostgreSQL and | Redis
# are ..."). A plain list ("X, Y and Z") is not split.
_HARD_BOUNDARY = re.compile(r"[;:!?()\[\]{}—–]|\s-\s")
_SOFT_BOUNDARY = re.compile(
    r"(?:,|\s(?=(?:and|but|then|while|whereas|so|or|nor)\s))\s*"
    rf"(?=(?:and\s+|but\s+|then\s+|while\s+|whereas\s+|so\s+|or\s+|nor\s+)?"
    rf"(?:[\w.+#/@'-]+\s+){{0,4}}?(?:{_CLAUSE_VERB.pattern}))",
    _I,
)
# Leftover text that never changes what a claim means.
_FILLER_WORDS = frozenset(
    """a an the this that these those we our us it its they their there here
    and but then so while whereas also too now thus hence therefore however moreover
    furthermore additionally consequently accordingly finally henceforth hereby overall
    will shall should have has had decided agreed really strictly absolutely explicitly
    always ever""".split()
)
_FILLER_PHRASES = re.compile(
    r"\b(?:(?:in|across|throughout)\s+(?:the|this|our)\s+(?:whole\s+|entire\s+)?"
    r"(?:codebase|code\s+base|repository|repo|project|system)"
    r"|(?:for|in|across|by|to|throughout)\s+(?:all|every|each|any)(?:\s+of\s+(?:the|our))?"
    r"\s+[\w-]+"  # one noun: "for all services" (not "for all new services")
    r"|anywhere|everywhere|at\s+all|going\s+forward|from\s+(?:now\s+on|today)"
    r"|as\s+of\s+today|with\s+immediate\s+effect|effective\s+immediately|in\s+this\s+adr)\b",
    _I,
)
# From here to the end of the gap is rationale or ADR boilerplate, not a qualifier.
_RATIONALE = re.compile(
    # a contrast names what was NOT chosen; it does not qualify the chosen term
    r"\b(?:rather\s+than|instead\s+of|"
    r"because|since|given\s+that|so\s+that|as\s+(?:described|defined|documented|"
    r"proposed|recommended|outlined|explained)|without\s+(?:a|an)\s+(?:new\s+|separate\s+|"
    r"superseding\s+)?ADR)\b",
    _I,
)
_TOKEN = re.compile(r"[\w'/.+#@-]+")
_MANNER = re.compile(rf"^\s*(?:{_MANNER_WORDS})\s*[.!]?\s*$", _I)


def _clauses(clean: str) -> list[tuple[int, int]]:
    """A partition of ``clean`` into clause segments (see the section comment)."""
    cuts = {0, len(clean)}
    for m in _HARD_BOUNDARY.finditer(clean):
        cuts.update((m.start(), m.end()))
    for m in _SOFT_BOUNDARY.finditer(clean):
        cuts.add(m.start())
    pts = sorted(cuts)
    return [(a, b) for a, b in zip(pts, pts[1:], strict=False) if b > a]


def _content(gap: str) -> list[str]:
    """Words of ``gap`` that are not fillers (empty: nothing was left uncaptured)."""
    r = _RATIONALE.search(gap)
    if r:
        gap = gap[: r.start()]
    gap = _FILLER_PHRASES.sub(" ", gap)
    words = (t.strip(".'-").lower() for t in _TOKEN.findall(gap))
    return [w for w in words if w and w not in _FILLER_WORDS]


def _covered(clean: str, matches: list[Match]) -> list[Match]:
    """``matches`` that fully account for their clauses (see the section comment)."""
    if not matches:
        return []
    clauses = _clauses(clean)
    starts = [a for a, _ in clauses]
    label = list(range(len(clauses)))
    order = sorted(range(len(matches)), key=lambda i: matches[i].span)
    first: dict[int, int] = {}  # match index -> its first clause
    for i in order:
        s, e = matches[i].span
        k0 = bisect.bisect_right(starts, s) - 1
        k1 = bisect.bisect_right(starts, max(s, e - 1)) - 1
        first[i] = k0
        for k in range(k0 + 1, k1 + 1):  # a match spanning clauses joins them
            label[k] = label[k0]
    # contiguous runs of one label are the regions
    regions: list[tuple[int, int, int]] = []  # (label, first clause, last clause)
    for k, lab in enumerate(label):
        if regions and regions[-1][0] == lab:
            regions[-1] = (lab, regions[-1][1], k)
        else:
            regions.append((lab, k, k))
    region_of = {}
    for r, (_, k0, k1) in enumerate(regions):
        for k in range(k0, k1 + 1):
            region_of[k] = r
    mine: dict[int, list[int]] = {}
    for i in order:
        mine.setdefault(region_of[first[i]], []).append(i)

    drop: set[int] = set()  # regions whose matches are dropped
    manner: dict[int, str] = {}
    for r, (_, k0, k1) in enumerate(regions):
        a, b = clauses[k0][0], clauses[k1][1]
        ms = mine.get(r)
        if not ms:
            # an orphan fragment with no verb qualifies a neighbouring clause
            # ("In adapters/, ...", "PostgreSQL and | Redis are ...", "... (for analytics)")
            text = clean[a:b]
            if _content(text) and not _CLAUSE_VERB.search(text):
                # fail closed: the nearest claim-bearing region on each side
                before = [q for q in range(r - 1, -1, -1) if mine.get(q)][:1]
                after = [q for q in range(r + 1, len(regions)) if mine.get(q)][:1]
                drop.update(before + after)
            continue
        gaps, at = [], a
        for i in ms:
            gaps.append(clean[at : matches[i].span[0]])
            at = max(at, matches[i].span[1])
        gaps.append(clean[at:b])
        for g, gap in enumerate(gaps):
            if not _content(gap):
                continue
            if g == len(gaps) - 1 and _MANNER.match(gap):  # "... directly", "synchronously"
                manner[ms[-1]] = " ".join(gap.split()).strip(" .!").lower()
                continue
            drop.add(r)
            break
    out = []
    for i, m in enumerate(matches):
        if region_of[first[i]] in drop:
            continue
        if i in manner:
            m = Match(m.pattern, m.kind, m.subject, {**m.rule, "manner": manner[i]}, m.span)
        out.append(m)
    return out


def match_sentence(sentence: str, patterns: Iterable[RulePattern] = RULES) -> list[Match]:
    """Typed matches for one sentence, in priority order, without overlaps, each
    accounting for its whole clause (``_covered``)."""
    clean = clean_sentence(sentence)
    if not clean or clean.endswith("?") or _NOT_A_DECISION.search(clean):
        return []
    neg = _Clauses(clean)
    taken: list[tuple[int, int]] = []  # sorted, non-overlapping
    out: list[Match] = []
    for pat in patterns:
        for rx in pat.regexes:
            for m in rx.finditer(clean):
                span = m.span("claim") if "claim" in rx.groupindex else m.span()
                if span[0] == span[1]:
                    continue
                k = bisect.bisect_left(taken, span)
                if (k > 0 and taken[k - 1][1] > span[0]) or (
                    k < len(taken) and taken[k][0] < span[1]
                ):
                    continue  # overlaps a higher-priority match
                if neg.negated(span[0]):
                    continue  # "We do not standardise on X", "must not NOT use X"
                if pat.kind in ("require", "only") and _NEGATOR.search(clean, *span):
                    continue  # "Services don't have to use X", "need not use X"
                if pat.kind in ("require", "only", "boundary") and _alternative(clean, m):
                    continue
                built = pat.build(m.groupdict())
                if built is None:
                    continue
                subject, rule = built
                if rule_errors(pat.kind, rule):
                    continue
                taken.insert(k, span)
                out.append(Match(pat.id, pat.kind, subject, rule, span))
    return _covered(clean, out)


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
        try:
            hints = extract_hint_claims(decision, text, start=n)
        except Exception as exc:  # last line of defence: one odd ADR never aborts a scan
            reason = f"front-matter hints could not be read ({type(exc).__name__}: {exc})"
            hints = RuleResult(rejected=[RejectedHint("hint", HINT_KEY, None, None, reason)])
        result.claims.extend(hints.claims)
        result.rejected.extend(hints.rejected)
    return result


# --------------------------------------------------------------------------- hints

HINT_KEY = "driftwarden"
_HINT_KINDS = ("forbid", "require", "only", "boundary", "free")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _hint_key_lines(lines: list[str], fm_end: int) -> list[tuple[int, str]]:
    """(0-based index, key text) of root-level ``driftwarden:`` keys, quoted or not, any
    case, in file order."""
    rx = re.compile(rf"^([\"']?)({HINT_KEY})\1\s*:", _I)
    out = []
    for i in range(1, fm_end):
        m = rx.match(lines[i].lstrip("﻿"))
        if m:
            out.append((i, m.group(2)))
    return out


def _hint_ranges(
    lines: list[str], fm_end: int, key_idx: int
) -> tuple[tuple[int, int], dict[str, list[tuple[str, tuple[int, int]]]]]:
    """0-based inclusive line ranges of the block whose root key is on ``key_idx``: the
    whole block, and per sub-key (lower-cased name -> [(key as written, range)])."""
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
    subs: dict[str, list[tuple[str, tuple[int, int]]]] = {}
    if children:
        child_indent = min(_indent(lines[j]) for j in children)
        keys = [
            (j, m.group(2))
            for j in children
            if _indent(lines[j]) == child_indent
            and (m := re.match(r"^\s*([\"']?)([A-Za-z_-]+)\1\s*:", lines[j]))
        ]
        for k, (j, name) in enumerate(keys):
            nxt = keys[k + 1][0] if k + 1 < len(keys) else end
            subs.setdefault(name.lower(), []).append((name, trim(j, nxt)))
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
                name = str(subj).strip() or "codebase"
                out.append((name, {kind: lst or items}, None if lst else "expected a list"))
            return out or [("codebase", value, "empty mapping")]
        lst = _as_list(value)
        return [("codebase", {kind: lst or value}, None if lst else "expected a list of names")]
    if kind == "only":
        if isinstance(value, dict):
            out = []
            for cat, items in value.items():
                lst = _as_list(items)
                name = str(cat).strip()
                rule = {"only": lst or items, "category": name}
                error = None if lst else "expected a list"
                if not name:
                    error = "empty category name"
                out.append((name or "technology", rule, error))
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
            first = target[0] if isinstance(target, list) and target else ""
            subj = str(entry.get("subject") or first).strip()
            out.append((subj.lower() or "boundary", rule, None))
        return out
    # free
    lst = _as_list(value)
    if lst is None:
        return [("free", value, "expected a string or a list of strings")]
    return [("free", {"text": t}, None) for t in lst]


class _HintLoader(yaml.SafeLoader):
    """SafeLoader that records duplicate mapping keys (PyYAML silently keeps the last)."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        # (key, first key line, duplicate key line, first value, first value end line)
        self.duplicates: list[tuple[Any, int, int, Any, int]] = []

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
            first: dict[Any, tuple[Any, Any]] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=True)
                try:
                    hash(key)
                except TypeError:
                    continue  # the base constructor reports unhashable keys
                if key in first:
                    k0, v0 = first[key]
                    end = v0.end_mark.line - (1 if v0.end_mark.column == 0 else 0)
                    value = self.construct_object(v0, deep=True)
                    self.duplicates.append(
                        (key, k0.start_mark.line, key_node.start_mark.line, value, end)
                    )
                else:
                    first[key] = (key_node, value_node)
        return super().construct_mapping(node, deep=deep)


def _load_front_matter(source: str) -> tuple[Any, list[tuple[Any, int, int, Any, int]]]:
    loader = _HintLoader(source)
    try:
        return loader.get_single_data(), loader.duplicates
    finally:
        loader.dispose()


def extract_hint_claims(decision: Decision, text: str, *, start: int = 0) -> RuleResult:
    """Claims from ``driftwarden:`` blocks in the ADR's YAML front-matter. Every claim
    cites the lines of the block YAML actually kept. Never raises: a block that cannot be
    read or located is returned in ``rejected`` with the reason."""
    result = RuleResult()
    lines = split_lines(text)
    if lines:
        lines[0] = lines[0].removeprefix("﻿")  # BOM (Windows editors)
    if not lines or lines[0].strip() != "---":
        return result
    fm_end = next((i for i in range(1, len(lines)) if lines[i].strip() in ("---", "...")), None)
    if fm_end is None:
        return result
    src = decision.source
    roots = _hint_key_lines(lines, fm_end)
    ranges = {i: _hint_ranges(lines, fm_end, i) for i, _ in roots}

    def prov(rng: tuple[int, int]) -> Provenance:
        a, b = rng
        return Provenance(
            path=src.path,
            line_start=a + 1,
            line_end=b + 1,
            commit=src.commit,
            quote="\n".join(lines[a : b + 1]),
        )

    where = prov(ranges[roots[0][0]][0] if len(roots) == 1 else (0, fm_end))
    try:
        data, duplicates = _load_front_matter("\n".join(lines[1:fm_end]))
    except yaml.YAMLError as exc:
        if roots:
            msg = (str(exc).splitlines() or [type(exc).__name__])[0]
            reason = f"front-matter is not valid YAML: {msg}"
            result.rejected.append(RejectedHint("hint", "front-matter", None, where, reason))
        return result
    except Exception as exc:  # RecursionError on deep nesting etc.: report, never raise
        if roots:
            reason = f"front-matter could not be read ({type(exc).__name__}): too deeply nested?"
            result.rejected.append(RejectedHint("hint", "front-matter", None, where, reason))
        return result
    if not isinstance(data, dict):
        return result
    blocks = [rng for rng, _ in ranges.values()]
    for key, first, dup, value, end in duplicates:
        # yaml lines are 0-based from the line after the opening '---'
        a, b, e = first + 1, dup + 1, max(first, end) + 1
        if not any(w[0] <= a <= w[1] for w in blocks) and str(key).lower() != HINT_KEY:
            continue  # a duplicate elsewhere in the front-matter is not a hint
        reason = (
            f"duplicate key {key!r} in front-matter (lines {a + 1} and {b + 1}): YAML keeps "
            "only the last one, so this earlier value is not used; merge the two entries"
        )
        result.rejected.append(RejectedHint("hint", str(key), value, prov((a, e)), reason))

    n = start
    for root_key, hints in data.items():
        if str(root_key).lower() != HINT_KEY:
            continue
        # YAML keeps the LAST of exact duplicates: cite that block's own lines
        idx = [i for i, written in roots if written == str(root_key)]
        if not idx:
            reason = f"cannot locate the '{root_key}:' block lines in the front-matter"
            result.rejected.append(RejectedHint("hint", HINT_KEY, hints, prov((0, fm_end)), reason))
            continue
        whole, subs = ranges[idx[-1]]
        if not isinstance(hints, dict):
            reason = f"'{HINT_KEY}' must be a mapping of kinds"
            result.rejected.append(RejectedHint("hint", HINT_KEY, hints, prov(whole), reason))
            continue
        n = _block_claims(decision, hints, whole, subs, prov, result, n)
    return result


def _block_claims(decision, hints, whole, subs, prov, result: RuleResult, n: int) -> int:
    folded: dict[str, list[str]] = {}
    for raw_kind in hints:
        folded.setdefault(str(raw_kind).lower(), []).append(str(raw_kind))
    for raw_kind, value in hints.items():
        kind = str(raw_kind).lower()
        written = [rng for name, rng in subs.get(kind, []) if name == str(raw_kind)]
        p = prov(written[-1] if written else whole)
        if len(folded[kind]) > 1:
            reason = (
                f"hint keys differing only in case ({', '.join(map(repr, folded[kind]))}): "
                "merge them into one key"
            )
            result.rejected.append(RejectedHint(kind, kind, value, p, reason))
            continue
        if kind not in _HINT_KINDS:
            reason = f"unknown hint kind {raw_kind!r} (expected one of {', '.join(_HINT_KINDS)})"
            result.rejected.append(RejectedHint(kind, kind, value, p, reason))
            continue
        try:
            specs = _hint_specs(kind, value)
        except Exception as exc:  # odd shapes: report, never raise
            reason = f"invalid front-matter hint: cannot read ({type(exc).__name__}: {exc})"
            result.rejected.append(RejectedHint(kind, kind, value, p, reason))
            continue
        for subject, rule, error in specs:
            errors = [error] if error else rule_errors(kind, rule)
            if errors:
                reason = "invalid front-matter hint: " + "; ".join(errors)
                result.rejected.append(RejectedHint(kind, subject, rule, p, reason))
                continue
            try:
                claim = Claim(
                    id=f"{decision.id}.c{n + 1}",
                    kind=kind,  # type: ignore[arg-type]
                    subject=subject,
                    rule=rule,
                    source=p,
                    decision_id=decision.id,
                    origin="hint",
                    pattern=f"hint:{kind}",
                )
            except ValueError as exc:  # pydantic ValidationError is a ValueError
                msg = (str(exc).splitlines() or [""])[-1].strip()
                reason = f"invalid front-matter hint: {msg or type(exc).__name__}"
                result.rejected.append(RejectedHint(kind, subject, rule, p, reason))
                continue
            n += 1
            result.claims.append(claim)
    return n
