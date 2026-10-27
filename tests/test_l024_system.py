"""L-024 system test (Sonnet, system tester) against origin/L-024-rules-hardening @ 302e192.

Scope: OVER-ACCEPTANCE of the new "harmless decoration" whitelist (``_PURPOSE``,
``_LEAD_DECOR``, ``_REF_PAREN``, ``_PURPOSE_FOR``, ``_CONTRAST``), the ticket's N1-N5
fixes, zero opposite-meaning claims, fixture recall, G1 and performance.

Method. ``MATRIX`` = subjects x modals x terms x qualifiers x decorations: every plain rule
(17 templates x 10 terms x 5 subjects) is combined with leading labels / discourse markers,
trailing rationale, reference brackets and scope qualifiers, singly, mid-sentence and in
random two-decoration combinations, plus permission/aspiration sentences. Ground truth
comes from the construction (each decoration is classified H = harmless, S = scope,
C = condition / hedge / rejection, P = permission, A = ambiguous and not judged):

* H: the claim must survive with the SAME kind and terms (dropped = over-drop; changed =
  altered; other kind = opposite meaning).
* S / C: no claim, or a claim whose rule carries the qualifier in an extra key (``scope``,
  ``for``, ``actor``, ...). A bare claim = LEAK (silently broadened).
* P: no require / only claim (strengthened permission).

Everything was also run against origin/main (8cd0dee); "NEW" = the leak is not also
produced by main. Full run (DW_L024_FULL=1): 231,205 unique matrix sentences + 26,784
purpose x scope pairs (every harmless trailing rationale x every scope trailer x 4 rules).
Results, branch vs main:

* over-drop of harmless decorations: 13.1 % single (5,000 / 38,250), 20.2 % in two-way
  combinations (605 / 2,999), 13.6 % overall (5,605 / 41,249); main 69.0 % / 91.4 % / 70.7 %.
  The decorations named in the ticket drop 0 % (``test_named_decorations_overdrop_rate``).
  Still dropped 100 %: mid-sentence markers (", as a rule,"), "Status: Accepted.",
  "Decision (date):", "Final decision:", "at all times", "without exception",
  "throughout the company", "for the long term" (documented fail-closed; recall only).
* opposite-meaning claims: 0. Permission strengthened to obligation: 0 of 50,020 (main
  3,330). Altered terms on harmless decorations: 454 (all "X everywhere", the same junk term
  main emits), main 3,078.
* scope leaks (bare claim although a scope / condition is stated): 8,697 of 135,846 S / C
  sentences on the branch (main 12,616), 5,092 of them NEW. Pairs matrix: 12,435 of 26,784
  leak (main 2,778), 9,988 NEW. 0 leaks lie outside the families of the defects below
  (``test_matrix_no_leak_outside_the_documented_defect_families``).
* fixtures: claims identical to main (12 on 'basic', all VERIFIED), G1 tamper 1200 / 1200.
* perf: 100 KB single sentences 0.1-3 s (main: same), linear; 5000 decorated claims 45 s.

Defects (all strict xfail; the xfail turns red = XPASS when fixed, then drop the marker):
D1 purpose/rationale swallows a trailing scope (NEW, HIGH), D9 a clause-verb homograph
('vendor lock-in', 'call volume') hides even an explicit 'in staging' (NEW for forbid, HIGH), D2 'in order to <operation>' /
'to <goal verb> <domain object>' is a scope (NEW, MEDIUM), D3 'given' as a condition
(NEW, MEDIUM), D4 relative clause with an explicit scope word (pre-existing, MEDIUM),
D5 forbid + 'for <abstract noun>' becomes a blanket ban (NEW, LOW, arguable),
D6 scope text inside a term (pre-existing + 1 NEW form, MEDIUM for require/only),
D7 N5 residual: 'instead of Y <scope>' still keeps some scopes (pre-existing, MEDIUM),
D8 leading/contrastive 'while' now drops real rules (recall regression, LOW).

Every defect docstring answers the three "read a red test" questions: 1. which requirement
fails, 2. where in the code, 3. how bad.
"""

# ruff: noqa: E501
from __future__ import annotations

import itertools
import os
import random
import re
import time
from collections import Counter

import pytest

from driftwarden.claims import structure_decision
from driftwarden.claims.rules import match_sentence, sentence_spans
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.verify import verify_source_quote

_N = itertools.count()


def claims(s: str):
    return [(m.kind, m.rule) for m in match_sentence(s)]


def kinds(s: str):
    return [k for k, _ in claims(s)]


def terms_of(rule: dict) -> list[str]:
    out: list[str] = []
    for key in ("forbid", "require", "only", "target", "via"):
        v = rule.get(key)
        if v:
            out += v if isinstance(v, list) else [v]
    return out


_JUNK_TERM = re.compile(
    r"\b(?:only|everywhere|by default|between|with the|for|in staging|across|per)\b", re.I
)


def adr(decision: str) -> str:
    return f"# 1. Test\n\n## Status\n\nAccepted\n\n## Decision\n\n{decision}\n\n## Consequences\n\nNone.\n"


def offline(make_repo, text: str):
    repo = make_repo({"docs/adr/0001-x.md": text}, name=f"l024sys{next(_N)}")
    (d,) = scan_adrs(repo).decisions
    return repo, structure_decision(d, repo, mode="offline")


# ============================================================================ the matrix

TERMS = [
    "Redis",
    "Kafka",
    "PostgreSQL",
    "MongoDB",
    "RabbitMQ",
    "gRPC",
    "Django",
    "boto3",
    "requests",
    "Kubernetes",
]
SUBJ = ["Services", "Handlers", "Modules", "Teams", "Workers"]

BASES = [
    ("forbid", "{S} must not use {T}"),
    ("forbid", "{S} should not use {T}"),
    ("forbid", "{S} cannot import {T}"),
    ("forbid", "Do not use {T}"),
    ("forbid", "We will not use {T}"),
    ("forbid", "Never use {T}"),
    ("require", "We will use {T}"),
    ("require", "{S} must use {T}"),
    ("require", "{S} should use {T}"),
    ("require", "We will adopt {T}"),
    ("require", "All {S} must use {T}"),
    ("require", "We will use {T} instead of {U}"),
    ("only", "{T} is the only datastore"),
    ("only", "{S} communicate only via {T}"),
    ("boundary", "Only adapters/ may import {T}"),
    ("boundary", "No {T} imports outside adapters/"),
    ("boundary", "All traffic must go through {T}"),
]
PERMS = [
    "Every team can use {T}",
    "Every team is allowed to use {T}",
    "Each service is free to use {T}",
    "All {S} ought to use {T}",
    "All {S} would like to use {T}",
    "{S} may use {T}",
    "{S} could use {T}",
    "{S} might use {T}",
    "{S} are encouraged to use {T}",
    "{S} are welcome to use {T}",
    "{S} are permitted to use {T}",
    "Every team may choose to use {T}",
    "{S} are not required to use {T}",
    "{S} need not use {T}",
    "{S} don't have to use {T}",
    "Any team may use {T}",
    "Each team is encouraged to adopt {T}",
]

# decorations: (id, lead, trail, mid_after_subject, cls)  cls: H harmless, S scope/qualifier, C condition/hedge/reject
LEADS = [
    ("Decision: ", "H"),
    ("Outcome: ", "H"),
    ("Chosen option: ", "H"),
    ("In summary, ", "H"),
    ("Given the above, ", "H"),
    ("As a result, ", "H"),
    ("After a long discussion, ", "H"),
    ("Note that ", "H"),
    ("Importantly, ", "H"),
    ("Per ADR-0003, ", "H"),
    ("The team agreed that ", "H"),
    ("We decided that ", "H"),
    ("Therefore, ", "H"),
    ("Overall, ", "H"),
    ("Going forward, ", "H"),
    ("Update: ", "H"),
    ("Status: Accepted. ", "H"),
    ("Decision (2024-05-01): ", "H"),
    ("We agreed that ", "H"),
    ("It was decided that ", "H"),
    ("In conclusion, ", "H"),
    ("Hence, ", "H"),
    ("Thus, ", "H"),
    ("Consequently, ", "H"),
    ("Accordingly, ", "H"),
    ("Following the review, ", "H"),
    ("Final decision: ", "H"),
    # scopes / conditions / rejections
    ("Rejected: ", "C"),
    ("Proposal: ", "C"),
    ("Decision: Rejected: ", "C"),
    ("Decision: maybe ", "C"),
    ("Decision: TODO: ", "C"),
    ("Note that maybe ", "C"),
    ("We decided that maybe ", "C"),
    ("We decided that generally ", "C"),
    ("The team agreed that ideally ", "C"),
    ("Decision: Option A: ", "C"),
    ("Chosen option: none, but ", "C"),
    ("When running locally, ", "C"),
    ("While migrating, ", "C"),
    ("Whenever possible, ", "C"),
    ("If approved, ", "C"),
    ("Given a valid token, ", "C"),
    ("Given that the flag is on, ", "C"),
    ("Given the staging environment, ", "C"),
    ("As of Q3, ", "C"),
    ("In staging, ", "S"),
    ("For analytics, ", "S"),
    ("For the payments domain, ", "S"),
    ("In production, ", "S"),
    ("In the payments service, ", "S"),
    ("Per environment, ", "S"),
    ("Per service, ", "S"),
    ("Per ADR-0003, in staging, ", "S"),
    ("In line with ADR-5, in staging, ", "S"),
    ("Decision: Alternatively, ", "C"),
    ("Decision (proposed): ", "C"),
    ("Decision (draft): ", "C"),
    ("Option B (rejected): ", "C"),
    ("Some argue that ", "C"),
    ("We considered whether ", "C"),
    ("It is unclear whether ", "C"),
    ("Where applicable, ", "C"),
    ("When deploying to production, ", "C"),
    ("While in beta, ", "C"),
    ("Decision: Rejected - ", "C"),
    ("Note that in staging, ", "S"),
    ("We decided that in staging, ", "S"),
    ("Given our expertise, in staging, ", "S"),
    ("Importantly, for analytics, ", "S"),
    ("Decision: for new services, ", "S"),
    ("On mobile, ", "S"),
    ("For batch jobs, ", "S"),
    ("As a cache, ", "S"),
    ("Where possible, ", "C"),
    ("Decision: not yet accepted: ", "C"),
    ("Decision: Superseded: ", "C"),
    ("Decision: Deprecated: ", "C"),
]
TRAILS = [
    # harmless
    (", to reduce ops cost", "H"),
    (", in order to reduce ops cost", "H"),
    (", in order to keep things simple", "H"),
    (", due to licensing concerns", "H"),
    (", based on the benchmark results", "H"),
    (", given our expertise", "H"),
    (", for consistency", "H"),
    (" for consistency", "H"),
    (", for security reasons", "H"),
    (", which keeps deployment simple", "H"),
    (", as discussed in ADR-0003", "H"),
    (" (see ADR-0007)", "H"),
    (" (see the security review)", "H"),
    (" (approved by the architecture board)", "H"),
    (" across the organization", "H"),
    (" across the organisation", "H"),
    (" in the codebase", "H"),
    (" everywhere", "H"),
    (", as a team", "H"),
    (", as a rule", "H"),
    (", as per the security review", "H"),
    (", in line with ADR-5", "H"),
    (", because it is cheaper", "H"),
    (" since the licence is permissive", "H"),
    (", to avoid vendor lock-in", "H"),
    (", to simplify operations", "H"),
    (" to ensure consistency", "H"),
    (", to keep it simple", "H"),
    (" for simplicity", "H"),
    (" for maintainability", "H"),
    (" for cost reasons", "H"),
    (", per the security review", "H"),
    (", per ADR-0007", "H"),
    (", which reduces risk", "H"),
    (", as described in the RFC", "H"),
    (", for security", "H"),
    (", to reduce complexity", "H"),
    (", to improve reliability", "H"),
    (", which simplifies operations", "H"),
    (", to minimise cost", "H"),
    (", to lower costs", "H"),
    (", to reduce risk", "H"),
    (", based on our experience", "H"),
    (", due to cost", "H"),
    (", for compliance reasons", "H"),
    (" for security", "H"),
    (", as agreed in ADR-0003", "H"),
    (", as documented in the wiki", "H"),
    (", for all services", "H"),
    (" at all times", "H"),
    (", without exception", "H"),
    (" throughout the company", "H"),
    (" in all services", "H"),
    (", for the long term", "H"),
    # scope-like
    (" to store sessions", "S"),
    (" to serve analytics", "S"),
    (" to handle payments", "S"),
    (" to cache sessions", "S"),
    (" to queue jobs", "S"),
    (" to process orders", "S"),
    (" to route traffic to the gateway", "S"),
    (" to the gateway", "S"),
    (" to production", "S"),
    (" to staging", "S"),
    (" for audit events", "S"),
    (" for analytics", "S"),
    (" for sessions", "S"),
    (" for payments", "S"),
    (" for the billing domain", "S"),
    (" for batch workloads", "S"),
    (" for audit logging", "S"),
    (" as a cache", "S"),
    (" as a queue", "S"),
    (" as a message broker", "S"),
    (" as a session store", "S"),
    (" as primary", "S"),
    (" as the only cache", "S"),
    (" across services", "S"),
    (" across the payments domain", "S"),
    (" across the payments services", "S"),
    (" across regions", "S"),
    (" across the data pipelines", "S"),
    (" in staging", "S"),
    (" (in staging)", "S"),
    (" (except tests)", "S"),
    (" (see ADR-7) only in staging", "S"),
    (" (see ADR-7, production only)", "S"),
    (" (for analytics)", "S"),
    (" (not in tests)", "S"),
    (" (in the payments service)", "S"),
    (", which stores PII", "S"),
    (", which is used by billing", "S"),
    (", which only runs in production", "S"),
    (" per environment", "S"),
    (" per service", "S"),
    (" per tenant", "S"),
    (" per region", "S"),
    (" in line with ADR-5 in staging", "S"),
    (" given a valid token", "S"),
    (" while migrating", "S"),
    (" while in beta", "S"),
    (" when running locally", "S"),
    (" when possible", "S"),
    (" where possible", "S"),
    (" outside tests", "S"),
    (" except tests", "S"),
    (" until Q3", "S"),
    (" in the payments module only", "S"),
    (" for now", "S"),
    (" for six months", "S"),
    (" on mobile", "S"),
    (" on Kubernetes", "S"),
    (" on AWS", "S"),
    (" in tests", "S"),
    (" for new services", "S"),
    (" for greenfield projects", "S"),
    (" for internal tools", "S"),
    (" for production traffic", "S"),
    (" for the web tier", "S"),
    (" on the backend", "S"),
    (" by default", "S"),
    (" as a fallback", "S"),
    (" as a last resort", "S"),
    (", but only in staging", "S"),
    (", but not in production", "S"),
    (" for user data", "S"),
    (" for event streaming", "S"),
    (" for caching", "S"),
    (" for messaging", "S"),
    (" to store user data", "S"),
    (" to publish events", "S"),
    (" to persist orders", "S"),
    (" to access the database", "S"),
    (" to reach the database", "S"),
    (" to communicate with billing", "S"),
    (" to talk to the payments API", "S"),
    (" to share state", "S"),
    (" to send email", "S"),
    (" to call the ledger", "S"),
    (" to run batch jobs", "S"),
    (" to support the mobile app", "S"),
    (" to power search", "S"),
    (" in service code", "S"),
    (" in the data layer", "S"),
    (" within the billing team", "S"),
    (" at the edge", "S"),
    (" in CI", "S"),
    (" in the frontend", "S"),
    (" between services", "S"),
    (" with the legacy system", "S"),
    (" for reporting", "S"),
    (" for the checkout flow", "S"),
    (" for read replicas", "S"),
    (" for new code", "S"),
    (" in new projects", "S"),
    (" from now on in staging", "S"),
    (", unless approved", "S"),
    (", if possible", "S"),
    (", except for tests", "S"),
    (", at least for now", "S"),
    (", which is only for staging", "S"),
    (", which holds customer data", "S"),
    (", which serves the checkout flow", "S"),
    (", which the payments team owns", "S"),
    (", which runs the ledger", "S"),
    (", which stores sessions", "S"),
    (", for audit events", "S"),
    (", for analytics", "S"),
    (", to store sessions", "S"),
    (", to serve analytics", "S"),
    (", as a cache", "S"),
    (", as a queue", "S"),
    (", as primary", "S"),
    (", per service", "S"),
    (", per environment", "S"),
    (", across services", "S"),
    (", across the payments domain", "S"),
    (", in staging", "S"),
    # ambiguous (recorded, not judged)
    (" in this repository", "A"),
    (" for the team", "A"),
    (", as agreed with the platform team", "A"),
    (" across all environments", "A"),
    (" in all environments", "A"),
    (" for compliance", "A"),
]
MIDS = [
    (", as a rule,", "H"),
    (", for consistency,", "H"),
    (", in summary,", "H"),
    (", therefore,", "H"),
    (", in practice,", "A"),
    (", in staging,", "S"),
    (", for analytics,", "S"),
    (", in production,", "S"),
    (", per service,", "S"),
    (", as a cache,", "S"),
    (", for sessions,", "S"),
    (", in the payments service,", "S"),
    (", when possible,", "S"),
    (", unless approved,", "S"),
]


def _attach(body: str, lead: str, trail: str, mid: str | None) -> str:
    if mid:
        parts = body.split(" ")
        idx = (
            2
            if parts[0] == "We"
            or (len(parts) > 2 and parts[1] in ("must", "should", "cannot", "communicate", "will"))
            else 1
        )
        if parts[0] == "All":
            idx = 3
        body = (" ".join(parts[:idx]) + mid + " " + " ".join(parts[idx:])).replace(",, ", ", ")
    s = body + trail
    if lead:
        if lead.endswith((", ", "that ", "whether ")) and body[:3] != "Eve":
            s = s[0].lower() + s[1:]
        s = lead + s
    return s + "."


def matrix_cases() -> list[dict]:
    """Every plain rule x every decoration (singly), plus mid-sentence markers."""
    plains = []
    for (kind, tpl), T, S in itertools.product(BASES, TERMS, SUBJ):
        U = "Kafka" if T != "Kafka" else "RabbitMQ"
        if "{S}" not in tpl and S != SUBJ[0]:
            continue
        body = tpl.format(T=T, S=S, U=U)
        plains.append(dict(kind=kind, tpl=tpl, T=T, body=body, base=body + "."))
    out = []
    for c in plains:
        out.append(dict(c, sentence=c["base"], cls="plain", dec=""))
        for lead, lc in LEADS:
            out.append(
                dict(c, sentence=_attach(c["body"], lead, "", None), cls=lc, dec="L:" + lead)
            )
        for trail, tc in TRAILS:
            out.append(
                dict(c, sentence=_attach(c["body"], "", trail, None), cls=tc, dec="T:" + trail)
            )
        for mid, mc in MIDS:
            out.append(dict(c, sentence=_attach(c["body"], "", "", mid), cls=mc, dec="M:" + mid))
    return out


def combo_cases(n: int = 60000, seed: int = 7) -> list[dict]:
    """Random lead + trail + trail combinations (the worst class is the label)."""
    rnd = random.Random(seed)
    plains = [c for c in matrix_cases() if c["cls"] == "plain"]
    rank = {"H": 0, "A": 1, "S": 2, "C": 2}
    res = []
    for _ in range(n):
        c = rnd.choice(plains)
        lead, lc = rnd.choice(LEADS + [("", "H")] * 10)
        t1, c1 = rnd.choice(TRAILS + [("", "H")] * 20)
        t2, c2 = rnd.choice(TRAILS + [("", "H")] * 60)
        cls = max((lc, c1, c2), key=lambda x: rank[x])
        res.append(
            dict(
                c,
                sentence=_attach(c["body"], lead, t1 + t2, None),
                cls=cls,
                dec=f"L:{lead}|T:{t1}|T:{t2}",
            )
        )
    return res


def perm_cases() -> list[dict]:
    out = []
    for tpl, T, S in itertools.product(PERMS, TERMS, SUBJ):
        body = tpl.format(T=T, S=S)
        mk = dict(kind="perm", T=T, tpl=tpl, body=body, base=body + ".", cls="P")
        out.append(dict(mk, sentence=body + ".", dec=""))
        for lead, _ in LEADS[:29]:
            if _ == "H":
                out.append(dict(mk, sentence=_attach(body, lead, "", None), dec="L:" + lead))
        for trail, tc in TRAILS[:60]:
            if tc == "H":
                out.append(dict(mk, sentence=_attach(body, "", trail, None), dec="T:" + trail))
    return out


def all_matrix() -> dict[str, dict]:
    seen: dict[str, dict] = {}
    for c in matrix_cases() + combo_cases() + perm_cases():
        seen.setdefault(c["sentence"], c)
    return seen


def _sig(res) -> tuple:
    out = []
    for kind, r in res:
        vals = []
        for k in ("forbid", "require", "only", "target", "allowed_in", "via"):
            v = r.get(k)
            if v is None:
                continue
            v = v if isinstance(v, list) else [v]
            vals.append((k, tuple(sorted(str(x).lower() for x in v))))
        out.append((kind, tuple(vals)))
    return tuple(sorted(out))


def _keys(res) -> set[str]:
    return {k for _, r in res for k in r}


def judge(case: dict, res, plain) -> str | None:
    """Category of a defect, or None when the claim set is acceptable."""
    cls = case["cls"]
    if cls == "P":
        return "STRENGTHENED" if any(k in ("require", "only") for k, _ in res) else None
    if cls == "plain" or cls == "A" or not plain:
        return None
    if cls == "H":
        if not res:
            return "OVERDROP"
        if _sig(res) == _sig(plain):
            return None
        return "OPPOSITE" if {k for k, _ in res} != {k for k, _ in plain} else "ALTERED"
    # S / C: nothing, or a claim that carries the qualifier in an extra key
    if not res or (_keys(res) - _keys(plain)):
        return None
    return "LEAK"


# Families of leak that the defects below describe. A leak OUTSIDE these is a NEW defect.
KNOWN_LEAK = re.compile(
    r"(, which|[Gg]iven (?:the staging|that the flag|a valid|our)|given a valid|everywhere|by default|"
    r"with the legacy|between services|to reduce|to lower|to minimi|to simplif|to improve|to ensure|"
    r"to keep|to avoid|in order to|due to|based on|as per|per the|per ADR|as discussed|as agreed|"
    r"as described|as documented|in line with|for consistency|for security|for simplicity|"
    r"for maintain|for cost|for compliance|because|since the licence|without exception to|to call the|to access the|to run batch)"
)

_PLAIN_CACHE: dict[str, list] = {}


def _plain(case: dict):
    b = case["base"]
    if b not in _PLAIN_CACHE:
        _PLAIN_CACHE[b] = claims(b)
    return _PLAIN_CACHE[b]


def evaluate(sentences: list[dict]):
    tally: Counter[str] = Counter()
    bad: dict[str, list[tuple[str, str]]] = {}
    for c in sentences:
        res = claims(c["sentence"])
        cat = judge(c, res, _plain(c))
        if c["cls"] == "H" and _plain(c):
            tally["H_total"] += 1
        tally[cat or "ok"] += 1
        if cat:
            bad.setdefault(cat, []).append((c["sentence"], repr(res)))
    return tally, bad


def sample(n: int, seed: int = 24) -> list[dict]:
    allc = list(all_matrix().values())
    if os.environ.get("DW_L024_FULL"):
        return allc
    random.Random(seed).shuffle(allc)
    return allc[:n]


# ============================================================ held: matrix-level checks


@pytest.fixture(scope="module")
def matrix():
    cases = sample(24_000)
    tally, bad = evaluate(cases)
    print(
        f"\nL-024 matrix: {len(cases)} sentences "
        f"(DW_L024_FULL=1 runs all {len(all_matrix())}); tally={dict(tally)}"
    )
    return tally, bad


def test_matrix_is_large_enough():
    assert len(all_matrix()) >= 200_000


def test_matrix_zero_opposite_meaning_claims(matrix):
    """No decoration flips forbid/require/only/boundary (held)."""
    _, bad = matrix
    assert bad.get("OPPOSITE", []) == []


def test_matrix_zero_permission_strengthened_to_obligation(matrix):
    """N2 across decorations: permission / aspiration never becomes require/only (held)."""
    tally, bad = matrix
    assert tally["STRENGTHENED"] == 0, bad.get("STRENGTHENED", [])[:5]


def test_matrix_harmless_decoration_never_changes_the_terms_except_everywhere(matrix):
    """A kept claim carries exactly the plain terms; the only exception is the pre-existing
    'X everywhere' junk term (D6, same output on main)."""
    _, bad = matrix
    altered = [x for x in bad.get("ALTERED", []) if "everywhere" not in x[0]]
    assert altered == [], altered[:5]


def test_matrix_no_leak_outside_the_documented_defect_families(matrix):
    """Guard for NEW leak families: every bare claim on a scope / condition sentence must
    belong to D1-D4 / D6 / D9 (``KNOWN_LEAK``). An unknown family fails this test."""
    _, bad = matrix
    unknown = [x for x in bad.get("LEAK", []) if not KNOWN_LEAK.search(x[0])]
    assert unknown == [], unknown[:10]


NAMED = [  # the decorations named in the ticket (N4)
    ("L:", "Decision: "),
    ("T:", " (see ADR-0007)"),
    ("T:", ", to reduce ops cost"),
    ("T:", ", in order to reduce ops cost"),
    ("T:", ", due to licensing concerns"),
    ("T:", ", based on the benchmark results"),
    ("T:", " for consistency"),
    ("T:", ", for consistency"),
    ("T:", ", which keeps deployment simple"),
    ("T:", ", as discussed in ADR-0003"),
    ("T:", " across the organization"),
]


def test_named_decorations_overdrop_rate():
    """N4: the ticket's decorations (target < 15 %) over every plain rule x term x subject.
    Measured 0 % on this branch (main: ~70 %)."""
    want = {a + b for a, b in NAMED}
    tot = dropped = 0
    for c in matrix_cases():
        if c["dec"] in want and _plain(c):
            tot += 1
            dropped += not claims(c["sentence"])
    rate = dropped / tot
    print(f"\nnamed N4 decorations: {dropped}/{tot} dropped = {rate:.1%}")
    assert tot > 3000 and rate < 0.15


def test_matrix_overdrop_rate_under_15_percent(matrix):
    """All harmless decorations in the matrix (incl. the ones the library documents as
    fail-closed: mid-sentence markers, 'Status: Accepted.', 'without exception', ...).
    Measured 13.0 % single / 20 % two-way combinations (main 69.8 % / 91.8 %)."""
    tally, _ = matrix
    rate = tally["OVERDROP"] / tally["H_total"]
    print(f"\nmatrix over-drop {tally['OVERDROP']}/{tally['H_total']} = {rate:.1%}")
    assert rate < 0.15


# ------------------------------------------------------------- N1 .. N5 (ticket) held

N1 = [
    "When running locally, services must not use Redis.",
    "When running locally, we will use Redis for caching.",
    "When running locally, Redis is the only cache.",
    "When deploying to production, services must not use Redis.",
    "Whenever we deploy, we will use Redis.",
    "While migrating, we will use Redis.",
    "While deploying to production, we will use Redis.",
    "when running locally, we will use Redis.",
    "When using Python, we will use Django.",
    "When deploying, only adapters/ may import boto3.",
]
N2 = [
    "Every team can use Django.",
    "Every team is allowed to use Redis.",
    "Each service is free to use Redis.",
    "All services ought to use Redis.",
    "All services would like to use Redis.",
    "Decision: every team can use Django.",
    "Every team can use Django, to reduce ops cost.",
    "We decided that every team may choose to use Django.",
]
N3 = [
    "Do not use Redis, given our expertise.",
    "Handlers cannot import RabbitMQ, given our expertise.",
    "Do not use eval, as a rule.",
    "Do not use Redis, as per the security review.",
    "Do not use Redis, due to licensing concerns.",
    "Do not use Redis, based on the benchmark results.",
]
N5 = [
    "We will use Redis Streams instead of Kafka in the payments module only.",
    "We will use Redis Streams instead of Kafka in staging.",
    "We will use Redis Streams instead of Kafka for analytics workloads.",
    "We will use Redis Streams instead of Kafka when running in CI.",
    "We will use Redis Streams instead of Kafka in new services.",
    "We will use Redis Streams instead of Kafka per service.",
    "We will use Redis Streams instead of Kafka across the payments domain.",
    "We will use Redis Streams instead of Kafka as a queue.",
    "We will use Redis Streams rather than Kafka in staging.",
    "Instead of Kafka in staging, we will use Redis Streams.",
    "Services must use Redis Streams instead of Kafka on mobile.",
    "Services must use Redis Streams instead of Kafka to talk to billing.",
]


@pytest.mark.parametrize("s", N1)
def test_N1_leading_condition_is_no_claim(s):
    assert claims(s) == []


@pytest.mark.parametrize("s", N2)
def test_N2_permission_is_no_obligation(s):
    assert [k for k in kinds(s) if k in ("require", "only")] == []


@pytest.mark.parametrize("s", N3)
def test_N3_rationale_is_not_a_forbidden_term(s):
    ((k, rule),) = claims(s)
    assert k == "forbid" and len(rule["forbid"]) == 1 and " " not in rule["forbid"][0]


@pytest.mark.parametrize("s", N5)
def test_N5_instead_of_scope_is_kept_or_dropped(s):
    for _k, rule in claims(s):
        assert rule.get("scope") or rule.get("for"), (s, rule)


# --------------------------------------------------- held: curated keep / drop controls

KEEP = [  # (sentence, kind, first term)
    ("Decision: We will use PostgreSQL as the primary datastore.", "require", "PostgreSQL"),
    ("Outcome: services must not use Redis.", "forbid", "Redis"),
    ("In summary, we will use Kubernetes for orchestration.", "require", "Kubernetes"),
    ("Given the above, we will use React for the frontend.", "require", "React"),
    ("As a result, we will adopt gRPC for internal service communication.", "require", "gRPC"),
    ("After a long discussion, we will use Docker for packaging services.", "require", "Docker"),
    ("Note that we will use PostgreSQL as the primary datastore.", "require", "PostgreSQL"),
    (
        "The team agreed that we will use PostgreSQL as the primary datastore.",
        "require",
        "PostgreSQL",
    ),
    ("We decided that services must not use Redis.", "forbid", "Redis"),
    ("We will use Redis for caching (see the security review).", "require", "Redis"),
    ("We will use PostgreSQL as the primary datastore (see ADR-0007).", "require", "PostgreSQL"),
    (
        "We will adopt gRPC for internal service communication, to reduce ops cost.",
        "require",
        "gRPC",
    ),
    ("We will not use Oracle to keep the architecture simple.", "forbid", "Oracle"),
    ("Services should not use requests due to licensing concerns.", "forbid", "requests"),
    ("We will use Kafka as the message broker, which keeps deployment simple.", "require", "Kafka"),
    ("PostgreSQL is the only datastore for consistency.", "only", "PostgreSQL"),
    ("We use Alembic for database migrations, as per the security review.", "require", "Alembic"),
    ("Chosen option: Redis.", "require", "Redis"),
    ('Chosen option: "Redis", because it is cheaper.', "require", "Redis"),
    ("To reduce cost, we will use Redis.", "require", "Redis"),
    ("In order to reduce cost, we will use Redis.", "require", "Redis"),
    ("Because it is cheaper, we will use Redis.", "require", "Redis"),
    ("Since the licence is permissive, we will use Redis.", "require", "Redis"),
    ("For consistency, we will use Redis.", "require", "Redis"),
    ("For security reasons, services must not use Redis.", "forbid", "Redis"),
    ("As discussed in ADR-0003, we will use Redis.", "require", "Redis"),
    ("As per ADR-0003, we will use Redis.", "require", "Redis"),
    ("As a rule, services must not use Redis.", "forbid", "Redis"),
    ("As a team, we will use Redis.", "require", "Redis"),
    ("In line with ADR-5, we will use Redis.", "require", "Redis"),
    ("Per ADR-0003, we will use Redis.", "require", "Redis"),
    ("Per ADR-0003, services must not use Redis.", "forbid", "Redis"),
    ("In all services, we will use Redis.", "require", "Redis"),
    ("For all services, we will use Redis.", "require", "Redis"),
    ("We will use Kafka across the organization.", "require", "Kafka"),
    ("Services communicate only via Kafka across the organization.", "only", "Kafka"),
    ("Only adapters/ may import boto3 as a rule.", "boundary", "boto3"),
    ("Only adapters/ may import boto3 (see ADR-7).", "boundary", "boto3"),
    ("No boto3 imports outside adapters/ for consistency.", "boundary", "boto3"),
    ("All traffic must go through the gateway, which keeps auth central.", "boundary", "traffic"),
    ("Services must not use Redis, to avoid vendor lock-in.", "forbid", "Redis"),
    ("Services must not use Redis (approved by the architecture board).", "forbid", "Redis"),
    ("Do not use Redis, given our expertise.", "forbid", "Redis"),
    ("Although Redis is fast, services must not use Redis.", "forbid", "Redis"),
]


@pytest.mark.parametrize(("s", "kind", "term"), KEEP)
def test_harmless_decoration_keeps_the_exact_claim(s, kind, term):
    ((k, rule),) = claims(s)
    assert k == kind and terms_of(rule)[0] == term, (s, rule)
    assert not _JUNK_TERM.search(terms_of(rule)[0])


DROP_CONTROLS = [
    "We will use the cache which stores sessions.",
    "We will use Kafka which serves analytics.",
    "Services must not use Redis, which stores sessions in staging.",
    "Given a valid token, services must use Redis.",
    "Services must use Redis given a valid token.",
    "Given staging, services must use Redis.",
    "Services must not use Redis given staging.",
    "Services must not use Redis, given a valid token.",
    "Given a valid token, we will use Kafka.",
    "Given production traffic, we will use Kafka.",
    "Redis is the only datastore in staging.",
    "We will use Redis in staging.",
    "Services must not use Redis per service.",
    "Services must not use Redis across services.",
    "Services must not use Redis across the payments domain.",
    "We will use Redis across services.",
    "We will use Redis across the payments domain.",
    "We will use Kafka across the organization's payments services.",
    "We will use Kafka across the platform.",
    "We will use Kafka across teams.",
    "We will use Kafka per environment.",
    "We will use Kafka per service.",
    "Each service must have its own database per environment.",
    "Services must use Kafka as a queue.",
    "Do not use Redis as a queue.",
    "Do not use Redis as a primary datastore.",
    "Do not use Redis, as a queue.",
    "Do not use Redis as a cache, as a rule.",
    "We will use Redis, as a cache.",
    "We will use Redis to store sessions.",
    "We will use Redis to serve analytics.",
    "We will use Redis to handle payments.",
    "We will use Redis to avoid vendor lock-in in staging.",
    "We will use Redis for consistency in staging.",
    "We will use Redis for consistency on payments.",
    "We will use Redis for security reasons in production.",
    "Do not use Redis for latency.",
    "Do not use Redis for audit.",
    "Do not use Redis for the cost.",
    "Do not use Redis for performance-critical paths.",
    "Do not use Redis for security-sensitive data.",
    "Do not use Redis for compliance data.",
    "Do not use Redis for cost-sensitive workloads.",
    "Do not use Redis for resilience-critical systems.",
    "Do not use Redis for consistency-critical data.",
    "Do not use Redis for consistency-sensitive workloads.",
    "Decision: Rejected: we will use Redis.",
    "Decision: Rejected. We will use Redis.",
    "Decision: maybe we will use Redis.",
    "Decision: Maybe use Redis.",
    "Decision: We might use Redis.",
    "Decision: Proposed: we will use Redis.",
    "Decision: Option A: we will use Redis.",
    "Decision: Option A - we will use Redis.",
    "Decision: Not accepted: we will use Redis.",
    "Decision: Superseded by ADR-9: we will use Redis.",
    "Decision: Deprecated - we will use Redis.",
    "Decision: Reverted: we will use Redis.",
    "Decision: Withdrawn: we will use Redis.",
    "Decision: Open question: we will use Redis.",
    "Decision: Under review: we will use Redis.",
    "Decision: Pending approval: we will use Redis.",
    "Decision: In progress: we will use Redis.",
    "Decision: Draft: we will use Redis.",
    "Decision: Not yet: we will use Redis.",
    "Decision: No. We will use Redis.",
    "Decision: Declined: services must not use Redis.",
    "Decision: Postponed: we will use Redis.",
    "Decision: Deferred: we will use Redis.",
    "Decision: Obsolete: we will use Redis.",
    "Decision: Abandoned: we will use Redis.",
    "Decision: Unresolved: we will use Redis.",
    "Decision: Contested: we will use Redis.",
    "Decision: Disputed: we will use Redis.",
    "Decision: Optional: we will use Redis.",
    "Decision: Experimental: we will use Redis.",
    "Decision: Pilot: we will use Redis.",
    "Decision: Temporary: we will use Redis.",
    "Decision: Interim: we will use Redis.",
    "Decision: Staging only: we will use Redis.",
    "Decision: Production only: we will use Redis.",
    "Decision: For analytics: we will use Redis.",
    "Decision: Payments: we will use Redis.",
    "Decision: Backend: we will use Redis.",
    "Decision: Mobile: we will use Redis.",
    "Decision: Frontend: services must not use Redis.",
    "Decision: Payments service: we will use Redis.",
    "Decision: Scope: payments. We will use Redis.",
    "Outcome: Rejected: we will use Redis.",
    "Outcome: we will use Redis in staging.",
    "Chosen option: Redis, in staging.",
    "Chosen option: we will use Redis, but only for analytics.",
    "Note that we will use Redis in staging.",
    "Note that services should perhaps use Redis.",
    "Note that services probably must not use Redis.",
    "Note that we will use Redis, if possible.",
    "Note that, in staging, we will use Redis.",
    "Note that services must use Redis where possible.",
    "We decided that we will use Redis in staging.",
    "We decided that we will probably use Redis.",
    "We decided that we will possibly use Redis.",
    "We decided that we might use Redis.",
    "We decided that we will use Redis, hopefully.",
    "We decided that we will ideally use Redis.",
    "We decided that we will tentatively use Redis.",
    "We decided that we will provisionally use Redis.",
    "We decided that we will initially use Redis.",
    "We decided that we will experimentally use Redis.",
    "We decided that we will sometimes use Redis.",
    "We decided that we will often use Redis.",
    "We decided that we will mostly use Redis.",
    "We decided that we will mainly use Redis.",
    "We decided that we will primarily use Redis.",
    "We decided that we will preferably use Redis.",
    "We decided that we will optionally use Redis.",
    "We decided that teams are free to use Redis.",
    "We decided that teams may use Redis.",
    "We decided that services should preferably use Redis.",
    "We decided that services should ideally not use Redis.",
    "The team agreed that services may use Redis.",
    "The team agreed that services should consider Redis.",
    "The team agreed that we will evaluate Redis.",
    "The team agreed that we will trial Redis.",
    "The team agreed that we will pilot Redis.",
    "The team agreed that we will prototype with Redis.",
    "The team agreed that we will experiment with Redis.",
    "The team agreed that we will use Redis temporarily.",
    "The team agreed that we will use Redis for a while.",
    "The team agreed that we will use Redis for the time being.",
    "The team agreed that we will use Redis during the migration.",
    "The team agreed that we will use Redis in the interim.",
    "The team agreed that we will use Redis in the meantime.",
    "The team agreed that we will use Redis in the prototype.",
    "The team agreed that we will use Redis on this project.",
    "The team agreed that we will use Redis in this service.",
    "The team agreed that we will use Redis in this module.",
    "In summary, we will use Redis in the pilot.",
    "In summary, we will, in the pilot, use Redis.",
    "In order to reduce cost, we will use Redis in staging.",
    "To store sessions, we will use Redis.",
    "To serve analytics, services must use Redis.",
    "To handle payments, services must use Redis.",
    "To reduce cost in staging, we will use Redis.",
    "Because it is cheaper, we will use Redis in staging.",
    "Based on the benchmark results in staging, we will use Redis.",
    "For consistency in staging, we will use Redis.",
    "For analytics, we will use Redis.",
    "For payments, services must not use Redis.",
    "For audit events, we will use Kafka.",
    "For simplicity in staging, we will use Redis.",
    "As discussed in ADR-0003, we will use Redis in staging.",
    "As per ADR-0003, in staging we will use Redis.",
    "As a cache, we will use Redis.",
    "As a queue, we will use Redis.",
    "As primary, we will use Redis.",
    "As the primary datastore, we will use PostgreSQL.",
    "As the only datastore, we will use PostgreSQL.",
    "As of Q3, we will use Redis.",
    "As of version 2, we will use Redis.",
    "In line with ADR-5, we will use Redis in staging.",
    "Per environment we will use Redis.",
    "Per service we will use Redis.",
    "Per region, we will use Redis.",
    "Per tenant, we will use Redis.",
    "Per ADR-0003 (staging), we will use Redis.",
    "Per ADR-0003 (staging only), we will use Redis.",
    "Per ADR-0003 only in staging, we will use Redis.",
    "Services must not use Redis (in staging).",
    "Services must not use Redis (except tests).",
    "Services must not use Redis (ADR-7, payments).",
    "Services must not use Redis (ADR-7: payments domain).",
    "Services must not use Redis (payments).",
    "Services must not use Redis (staging).",
    "Services must not use Redis (tests excluded).",
    "Services must not use Redis (not in tests).",
    "Services must not use Redis (excluding tests).",
    "Services must not use Redis (apart from tests).",
    "Services must not use Redis (besides tests).",
    "Services must not use Redis (tests aside).",
    "Services must not use Redis (new services).",
    "Services must not use Redis (new services only).",
    "Services must not use Redis (for new services).",
    "Services must not use Redis (approved by payments for staging).",
    "Services must not use Redis (approved in staging).",
    "We will use Redis for consistency (in staging).",
    "We will use Redis for consistency (staging only).",
    "We will use Redis, for consistency, in staging.",
    "We will use Redis, which keeps deployment simple, in staging.",
    "We will use Redis, which keeps deployment simple (in staging).",
    "We will use Redis, which keeps it simple in staging.",
    "We will use Redis, which reduces costs in staging.",
    "We will use Redis, which simplifies operations in production.",
    "Services must not use Redis, as discussed in the payments review in staging.",
    "Services must not use Redis, based on the benchmark in staging.",
    "Services must not use Redis, given payments.",
    "Services must not use Redis, to reduce ops cost in staging.",
    "Services must not use Redis, to keep it simple in tests.",
    "Services must not use Redis, to cut costs in staging.",
    "Services must not use Redis, to protect PII.",
    "Services must not use Redis, to protect payments data.",
    "Services must not use Redis to protect PII.",
    "Services must not use Redis to protect payments data.",
    "Services must not use Redis to cache PII.",
    "Services must not use Redis to store PII.",
    "We will use Redis Streams instead of Kafka for analytics.",
    "We will use Redis Streams instead of Kafka in staging.",
    "We will use Redis Streams instead of Kafka per service.",
    "We will use Redis Streams instead of Kafka across services.",
    "We will use Redis Streams instead of Kafka across the payments domain.",
    "We will use Redis Streams instead of Kafka as a queue.",
    "We will use Redis Streams instead of Kafka to store sessions.",
    "We will use Redis Streams instead of Kafka (in staging).",
    "We will use Redis Streams rather than Kafka in staging.",
    "We will use Redis Streams rather than Kafka for analytics.",
    "We will use Redis Streams over Kafka in staging.",
    "We will use Redis Streams over Kafka for analytics.",
    "We will use Redis Streams and not Kafka in staging.",
    "We will use Redis Streams, not Kafka, in staging.",
    "We will use Redis Streams, not Kafka, for analytics.",
    "Instead of Kafka, we will use Redis Streams in staging.",
    "Instead of Kafka in staging, we will use Redis Streams.",
    "In staging, instead of Kafka, we will use Redis Streams.",
    "Services must use Redis Streams instead of Kafka in the payments module only.",
    "Services must use Redis Streams instead of Kafka when running in CI.",
    "Services must use Redis Streams instead of Kafka in new services.",
    "Services must use Redis Streams instead of Kafka unless approved.",
    "Services must use Redis Streams instead of Kafka until Q3.",
    "Services must use Redis Streams instead of Kafka at the edge.",
    "Services must use Redis Streams instead of Kafka on mobile.",
    "Services must use Redis Streams instead of Kafka on AWS.",
    "Services must use Redis Streams instead of Kafka for new code.",
    "Services must use Redis Streams instead of Kafka with the legacy system.",
    "Services must use Redis Streams instead of Kafka to talk to billing.",
    "Services must use Redis Streams instead of Kafka to publish events.",
    "Services must use Redis Streams instead of Kafka as primary.",
    "Services must use Redis Streams instead of Kafka per environment.",
    "Services must use Redis Streams instead of Kafka given a valid token.",
    "We will use Redis Streams instead of Kafka given a valid token.",
    "We will use Redis Streams instead of Kafka, given our expertise in staging.",
    "Instead of Kafka for analytics, we will use Redis Streams.",
    "We will use Redis Streams in place of Kafka in staging.",
    "We will use Redis Streams in lieu of Kafka for analytics.",
    "We will phase out Kafka in favour of Redis Streams in staging.",
    "We will phase out Kafka in favour of Redis Streams.",
    "Kafka will be replaced by Redis Streams in staging.",
    "When running locally, services must not use Redis.",
    "When running locally we will use Redis.",
    "When running in CI, Redis is the only cache.",
    "When deploying to production, services must not use Redis.",
    "When using Python, we will use Django.",
    "When using Python we will use Django.",
    "When writing new services, we will use Django.",
    "When deploying, only adapters/ may import boto3.",
    "When there is doubt, we will use Redis.",
    "When in production, we will use Redis.",
    "When it matters, we will use Redis.",
    "When appropriate, we will use Redis.",
    "When needed, we will use Redis.",
    "when running locally, we will use Redis.",
    "WHEN RUNNING LOCALLY, we will use Redis.",
    "Whenever we deploy, we will use Redis.",
    "Whenever running locally, we will use Redis.",
    "While running locally, we will use Redis.",
    "While deploying to production, we will use Redis.",
    "While in production, services must not use Redis.",
    "Once deployed, services must not use Redis.",
    "Once in production, services must not use Redis.",
    "After deployment, services must not use Redis.",
    "Before deployment, services must not use Redis.",
    "Until Q3, we will use Redis.",
    "Until further notice, we will use Redis.",
    "By Q3, we will use Redis.",
    "By default, we will use Redis.",
    "By default, services must not use Redis.",
    "In production, we will use Redis.",
    "In staging, we will use Redis.",
    "In tests, we will use Redis.",
    "In CI, we will use Redis.",
    "In the payments service, we will use Redis.",
    "In new services, we will use Redis.",
    "In this service, we will use Redis.",
    "Within the payments domain, we will use Redis.",
    "For the payments service, we will use Redis.",
    "For new services, we will use Redis.",
    "For this repository, we will use Redis.",
    "For this project, we will use Redis.",
    "For tests, we will use Redis.",
    "For CI, we will use Redis.",
    "For production, we will use Redis.",
    "For staging, we will use Redis.",
    "For now, we will use Redis.",
    "For the moment, we will use Redis.",
    "For the time being, we will use Redis.",
    "For the pilot, we will use Redis.",
]


@pytest.mark.parametrize("s", DROP_CONTROLS)
def test_scope_condition_hedge_or_rejection_yields_no_claim(s):
    assert claims(s) == []


def test_curated_corpus_has_at_least_300_decorated_sentences():
    n = (
        len(KEEP)
        + len(DROP_CONTROLS)
        + sum(len(v) for v in DEFECTS.values())
        + len(N1)
        + len(N2)
        + len(N3)
        + len(N5)
    )
    assert n >= 300, n


# ================================================================= defects (strict xfail)

D1 = [
    "Services must not use Redis, to reduce ops cost for payments.",
    "We will use Kafka, to reduce ops cost for audit events.",
    "Services must not use Redis, to reduce ops cost at the edge.",
    "Services must not use Redis, to reduce ops cost across the payments domain.",
    "Services must not use Redis, to reduce ops cost per region.",
    "Services must not use Redis, to reduce ops cost as a cache.",
    "Services must not use Redis, due to licensing concerns for payments.",
    "Services must not use Redis, due to licensing concerns in the EU.",
    "Due to licensing concerns in the EU, services must not use Redis.",
    "Based on the benchmark results for analytics, we will use Redis.",
    "Services must not use Redis, in line with ADR-5 for payments.",
    "Services must not use Redis, as discussed in ADR-0003 for payments.",
    "Services must not use Redis, given our expertise, across regions.",
    "PostgreSQL is the only datastore, in order to reduce ops cost for audit logging.",
    "Only adapters/ may import boto3, to reduce risk for payments.",
    "All traffic must go through the gateway, to reduce risk for payments.",
    "We will use Redis, to reduce complexity on mobile.",
    "We will use Redis, to lower costs for the web tier.",
    "Handlers must use requests, to reduce ops cost with the legacy system.",
]
D2 = [
    "We will use Redis in order to store sessions.",
    "We will use Redis in order to serve analytics.",
    "We will use Redis to reduce latency of sessions.",
    "We will use Redis to ensure sessions are fast.",
    "We will use Redis to simplify payments.",
    "We will use Redis to keep payments simple.",
    "We will use Kafka to simplify the checkout flow.",
    "Services must not use Redis, to simplify payments.",
    "Services must not use Redis, to ensure consistency in payments.",
    "Services must not use Redis, to speed up payments.",
    "Services must not use Redis, to keep the payments stack simple.",
    "Services must not use Redis, to reduce payments risk.",
    "Services must not use Redis in order to store sessions.",
]
D3 = [
    "Given the staging environment, services must use Redis.",
    "Given the staging environment, services must not use Redis.",
    "Given the payments domain, we will use Kafka.",
    "Services must not use Redis, given the payments domain.",
    "Services must not use Redis given the staging environment.",
    "Services must not use Redis, given that we are in staging.",
    "Given that the flag is on, we will use Kafka.",
    "Services must not use Redis, given that the flag is on.",
    "Services must not use Redis, given the flag is on.",
    "Given that this is production, we will use Kafka.",
]
D4 = [
    "We will use Redis, which only runs in production.",
    "Services must not use Redis, which is only for staging.",
    "PostgreSQL is the only datastore, which is only for staging.",
    "Only adapters/ may import boto3, which only runs in production.",
    "We will use Redis, which is used only in staging.",
    "Services must not use Redis, which is deployed only in the payments service.",
]
D5 = [
    "Do not use Redis for performance.",
    "Do not use Redis for resilience.",
    "Do not use Redis for security.",
    "Do not use Redis for cost.",
    "Do not use Redis for simplicity.",
    "Do not use Redis for maintainability.",
    "Do not use Redis for compliance reasons.",
    "Services must not use Kafka for scalability.",
]
D6 = [
    "Services must not use Redis (see ADR-7) only in staging.",
    "Chosen option: Redis only in staging.",
    "Chosen option: Redis for analytics.",
    "We will use Redis everywhere.",
    "Services must not use Redis everywhere.",
    "Services must not use Redis by default.",
    "Services must not use Redis with the legacy system.",
    "We will use Redis between services.",
    "Do not use Redis which stores PII.",
    "Services must not use the datastore which stores PII.",
    "Do not use the broker that serves payments.",
]
D7 = [
    "We will use Redis Streams instead of Kafka between services.",
    "Services must use Redis Streams instead of Kafka between services.",
    "We will use Redis Streams instead of Kafka to reduce ops cost for analytics.",
    "We will use Redis Streams instead of Kafka due to licensing concerns in the EU.",
    "We will use Redis Streams instead of Kafka, to reduce ops cost for audit events.",
]
D8 = [
    "Services must use Kafka, while batch jobs must use RabbitMQ.",
    "While Redis is fast, services must not use Redis.",
    "While Redis is popular, we will use Kafka.",
]
D9 = [
    "Services must not use Redis, to avoid vendor lock-in in staging.",
    "Services must not use Redis, to avoid vendor lock-in in production.",
    "Services must not use Redis, to avoid vendor lock-in outside tests.",
    "Services must not use Redis, to avoid vendor lock-in, but only in staging.",
    "We will use Redis, to avoid vendor lock-in for new services.",
    "We will use Redis, to avoid vendor lock-in in production.",
    "We will use Redis, to avoid vendor lock-in only in staging.",
    "Services must not use Redis, due to vendor lock-in in staging.",
    "Services must not use Redis because of vendor lock-in in staging.",
    "Services must not use Redis, to reduce vendor lock-in in staging.",
    "We will use Kafka, to reduce call volume in production.",
    "We will use Kafka, to reduce access latency in production.",
    "We will use Kafka, to reduce run costs in production.",
    "We will use Kafka, to reduce deploy time in production.",
    "We will use Kafka, to reduce install size in staging.",
    "We will use Kafka, to reduce use of memory in staging.",
    "We will use Kafka, to reduce import time in staging.",
    "Services must not use Redis, to reduce call volume in staging.",
]
DEFECTS = {"D1": D1, "D2": D2, "D3": D3, "D4": D4, "D5": D5, "D6": D6, "D7": D7, "D8": D8, "D9": D9}


def _bare(s: str) -> list:
    """Claims that carry no qualifier key although the sentence states a scope."""
    return [
        (k, r)
        for k, r in claims(s)
        if not (
            r.keys()
            - {
                "forbid",
                "require",
                "only",
                "target",
                "allowed_in",
                "via",
                "action",
                "between",
                "category",
            }
        )
    ]


@pytest.mark.xfail(
    strict=True, reason="L-024 D1: a purpose / rationale marker swallows everything after it"
)
@pytest.mark.parametrize("s", D1)
def test_D1_purpose_or_rationale_does_not_swallow_a_trailing_scope(s):
    """D1 (NEW vs main, HIGH). 1. Requirement: 'a scope qualifier is never whitelisted'
    (rules.py docstring) -- 'for payments', 'in the EU', 'across regions', 'at the edge',
    'per region', 'as a cache', 'on mobile', 'with the legacy system' after a purpose
    ('to reduce ops cost'), 'due to ...', 'based on ...', 'in line with', 'as discussed in'
    must still drop the claim. 2. rules.py ``_content()``: ``gap = gap[: p.start()]`` throws
    away the whole rest of the gap after the first ``_PURPOSE`` hit, and the only guard is
    the narrow ``_SCOPE_TAIL`` (only/except/until/when/if/outside + in|on|for production,
    staging, dev, tests, ci, local, new, legacy). 3. HIGH: an unconditional ban/requirement
    is emitted for a rule the ADR scopes ('must not use Redis, to reduce ops cost for
    payments' becomes repo-wide) -> false VIOLATED. 9,988 of 26,784 purpose x scope pairs
    (37.3 %) leak; main leaks 2,778 of them."""
    assert _bare(s) == []


@pytest.mark.xfail(strict=True, reason="L-024 D2: operational / domain-object purpose is a scope")
@pytest.mark.parametrize("s", D2)
def test_D2_purpose_that_names_an_operation_or_domain_is_a_scope(s):
    """D2 (NEW, MEDIUM). 1. 'to <verb> payments' / 'in order to store sessions' state WHERE
    or WHAT the choice is for ('serve analytics', 'handle payments' are dropped, but
    'simplify payments' is kept). 2. rules.py ``_PURPOSE``: the bare alternative
    ``in order to`` / ``so as to`` accepts any verb, and ``to (reduce|simplify|ensure|
    keep ... simple|speed up|...)`` never inspects the object. 3. MEDIUM: 'We will use Redis
    in order to store sessions' becomes 'require Redis' repo-wide."""
    assert claims(s) == []


@pytest.mark.xfail(strict=True, reason="L-024 D3: 'given <condition>' is treated as rationale")
@pytest.mark.parametrize("s", D3)
def test_D3_given_as_a_condition_is_not_rationale(s):
    """D3 (mostly NEW, MEDIUM). 1. 'given the staging environment', 'given the payments
    domain', 'given that we are in staging' / 'the flag is on' condition the rule (the
    docstring lists 'given' as rationale only for 'our expertise'-type phrases; 'given a
    valid token' is correctly dropped). 2. ``_PURPOSE``: ``given\\s+(our|the|its|their|this|
    these|that|how|what)`` accepts any object; ``_RATIONALE`` also swallows ``given that ...``
    in full. 3. MEDIUM: leading and trailing condition becomes an unconditional rule;
    main kept scope=['staging'] for 'given that we are in staging', the branch discards it.
    ('Given that the flag is on' / 'this is production' leak on main too.)"""
    assert _bare(s) == []


@pytest.mark.xfail(
    strict=True, reason="L-024 D4: relative clause with an explicit scope word is kept"
)
@pytest.mark.parametrize("s", D4)
def test_D4_relative_clause_with_scope_word_drops_the_claim(s):
    """D4 (pre-existing, MEDIUM). 1. docstring: a purpose / relative gap that 'carries a scope
    word ("only", "except", "until", "when", "if", "outside", "in production", ...)' drops
    the claim. 2. ``_PURPOSE`` alternative ``,\\s*which\\b``: the relative clause is matched
    by ``_clauses()`` as its own clause (it has a verb), so ``_content()`` never sees
    'only' / 'production' as a tail of the claim's gap. 3. MEDIUM: 'We will use Redis,
    which only runs in production' -> unscoped require (same on main; the whitelist makes
    the docstring promise false). Non-restrictive ', which stores PII' is accepted by
    design (3,380 NEW harmless-ish passes in the matrix, ambiguous)."""
    assert _bare(s) == []


@pytest.mark.xfail(
    strict=True, reason="L-024 D5: forbid + 'for <abstract noun>' is read as rationale"
)
@pytest.mark.parametrize("s", D5)
def test_D5_forbid_for_abstract_noun_is_a_workload_not_a_reason(s):
    """D5 (NEW, LOW, arguable). 1. 'for <noun>' purpose vs workload: 'Do not use Redis for
    performance' most naturally bans Redis FOR performance-critical paths (scope), yet
    'for latency' / 'for audit' / 'for performance-critical paths' are dropped while
    'for performance' is kept as an unscoped ban. 2. rules.py ``_PURPOSE_NOUNS`` /
    ``_PURPOSE_FOR`` (performance, security, resilience, cost, scalability, ...). 3. LOW:
    a blanket ban from a scoped one; only forbid is risky (require 'for performance' is
    the intended rationale). Main dropped all of these."""
    assert claims(s) == []


@pytest.mark.xfail(strict=True, reason="L-024 D6: scope text ends up inside the claim term")
@pytest.mark.parametrize("s", D6)
def test_D6_claim_terms_are_clean_names(s):
    """D6 (pre-existing except the first, MEDIUM for require / only / boundary). 1. R12:
    claim terms are technology names. 'Redis only in staging', 'Redis for analytics',
    'Redis everywhere', 'Redis by default', 'Redis between services', 'Redis which stores
    PII' are scope / clause text. 2. rules.py ``clean_term()`` / ``_STOP``: 'everywhere',
    'by default', 'with', 'between', 'which', 'that' do not end a term (the L-024 whitelist
    only added 'across', 'throughout', 'per'); the first sentence is NEW ('(see ADR-7) only
    in staging' -> forbid 'Redis only' + scope staging). 3. MEDIUM: an unsatisfiable
    require ('Redis everywhere') is a guaranteed false VIOLATED; a forbid never fires."""
    for _, rule in claims(s):
        for t in terms_of(rule):
            assert not re.search(
                r"\b(?:only|everywhere|by default|between|with the|for|which|that|in staging)\b",
                t,
                re.I,
            ), (s, rule)


@pytest.mark.xfail(
    strict=True, reason="L-024 D7: N5 residual -- some 'instead of Y <scope>' still keep the claim"
)
@pytest.mark.parametrize("s", D7)
def test_D7_instead_of_with_residual_scope_is_dropped(s):
    """D7 (pre-existing, MEDIUM). 1. N5: 'X instead of Y <scope>' keeps the scope or drops.
    'in staging', 'for analytics', 'per service', 'as a queue' are fixed; 'between services',
    'to reduce ops cost for analytics' and 'due to licensing concerns in the EU' (purpose
    + scope, see D1) still yield a bare 'require Redis Streams'. 2. rules.py ``_CONTRAST``
    consumes up to three words of Y, and a purpose tail is dropped by ``_content()`` (D1).
    3. MEDIUM: same class as the original N5 for the residual scopes."""
    assert _bare(s) == []


@pytest.mark.xfail(
    strict=True, reason="L-024 D8: contrastive / concessive 'while' now drops real rules"
)
@pytest.mark.parametrize("s", D8)
def test_D8_contrastive_or_concessive_while_does_not_drop_a_real_rule(s):
    """D8 (NEW recall regression, LOW). 1. Recall delta vs main should be 0 for real rules:
    'Services must use Kafka, while batch jobs must use RabbitMQ' (2 claims on main) and
    'While Redis is fast, services must not use Redis' (concession) now yield nothing.
    2. rules.py leading / any 'while' guard added for N1 (documented Known limit).
    3. LOW: fail-closed (a missed rule, never a wrong one); filed so the rate is tracked."""
    assert claims(s) != []


@pytest.mark.xfail(
    strict=True, reason="L-024 D9: a clause-verb homograph hides an explicit scope word"
)
@pytest.mark.parametrize("s", D9)
def test_D9_noun_that_looks_like_a_verb_does_not_hide_the_scope(s):
    """D9 (forbid + 'vendor lock-in' variants NEW; require variants pre-existing, HIGH).
    1. 'to avoid vendor lock-in in staging', 'to reduce call volume in production',
    '... outside tests', ', but only in staging' contain EXPLICIT scope words yet leak.
    2. rules.py ``_VERBS`` lists vendor/call/access/run/deploy/install/include/add/use/
    import as clause verbs, so ``_clauses()`` cuts the purpose phrase there; the tail
    ('lock-in in staging') becomes a clause that 'has a verb', is not an orphan fragment, and
    never reaches ``_SCOPE_TAIL``. 3. HIGH: 'vendor lock-in' is the most common rationale in
    ADRs; the scope that follows it is silently lost. Main drops the forbid variants."""
    assert _bare(s) == []


# ================================================================ generator-level (xfail)


@pytest.mark.xfail(
    strict=True, reason="L-024 D1-D4/D6/D9: scope leaks remain in the decorated matrix"
)
def test_D0_matrix_has_zero_scope_leaks(matrix):
    """Aggregate of D1-D4, D6, D9 over the generated matrix (24k sample by default; the full
    231,205-sentence run leaks 8,697 of 135,846 S / C sentences, main 12,616, 5,092 new; the
    pairs matrix leaks 12,435 of 26,784, main 2,778)."""
    tally, bad = matrix
    assert tally["LEAK"] == 0, tally["LEAK"]


# ======================================================================= fixtures / G1

FIXTURE_CLAIMS = {
    ("basic", "ADR-0001", "require"): {"require": ["Architecture Decision Records"]},
    ("basic", "ADR-0002", "only"): {"only": ["PostgreSQL"], "category": "datastore"},
    ("basic", "ADR-0002", "forbid"): {
        "forbid": ["database", "cache-as-database", "document store"],
        "action": "add",
    },
    ("basic", "ADR-0003", "only"): {"only": ["event bus"], "between": "Services"},
    ("basic", "ADR-0003", "forbid"): {"forbid": ["Synchronous service-to-service HTTP calls"]},
    ("basic", "ADR-0004", "boundary"): {
        "target": ["Cloud provider SDKs"],
        "allowed_in": ["adapters/"],
    },
    ("basic", "ADR-0005", "require"): {"require": ["FastAPI"]},
    ("basic", "ADR-0006", "require"): {"require": ["structlog"]},
    ("basic", "ADR-0007", "require"): {"require": ["server-rendered templates"]},
    ("basic", "ADR-0008", "require"): {"require": ["in-process LRU cache"]},
    ("basic", "ADR-0011", "require"): {"require": ["RabbitMQ"], "for": "message broker"},
    ("basic", "ADR-0012", "require"): {"require": ["UTF-8"]},
}


def test_fixture_recall_delta_is_zero_and_all_g1_verified(fixture_repo):
    """Offline claims on both fixtures equal main's (12 on 'basic', 0 on 'adr_tools'), each
    with a VERIFIED G1 quote."""
    got = {}
    for fx in ("basic", "adr_tools"):
        repo = fixture_repo(fx)
        for d in scan_adrs(repo).decisions:
            for c in structure_decision(d, repo, mode="offline").claims:
                got[(fx, c.decision_id, c.kind)] = c.rule
                assert verify_source_quote(repo, c.source).status == "VERIFIED"
    assert got == FIXTURE_CLAIMS


def test_basic_fixture_scan_12_of_12_verified(fixture_repo, tmp_path):
    from typer.testing import CliRunner

    from driftwarden.cli import app

    repo = fixture_repo("basic")
    res = CliRunner().invoke(app, ["scan", str(repo), "--out", str(tmp_path / "out")])
    assert res.exit_code == 0, res.output
    assert "12/12 VERIFIED" in res.output and "100.0%" in res.output


def _decorated_adr_sentences(n: int) -> list[str]:
    """n decorated sentences with pairwise different terms (the dispatcher de-duplicates
    identical claims), each of which keeps its claim."""
    rnd = random.Random(99)
    heads = [t for t in BASES if t[1].count("{T}") == 1]
    leads = [d for d, c in LEADS if c == "H"] + [""] * 6
    trails = [d for d, c in TRAILS if c == "H"] + [""] * 6
    out: list[str] = []
    i = 0
    while len(out) < n:
        i += 1
        _, tpl = rnd.choice(heads)
        body = tpl.format(S=rnd.choice(SUBJ), T=f"Lib{i}", U="Other")
        sent = _attach(body, rnd.choice(leads), rnd.choice(trails), None)
        if len(claims(sent)) == 1:
            out.append(sent)
    return out


def test_G1_decorated_adr_all_verified_and_every_tamper_caught(make_repo):
    """300 decorated sentences, one paragraph each: every claim VERIFIED; for each claim
    4 mutations (inserted word, swapped term, range shifted +2, range shifted -1) are all caught
    (100 %)."""
    sents = _decorated_adr_sentences(300)
    assert len(sents) == 300
    repo, cs = offline(make_repo, adr("\n\n".join(sents)))
    assert cs.unverified == []
    assert len(cs.claims) >= 280, len(cs.claims)
    caught = total = 0
    for c in cs.claims:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
        q = c.source.quote
        muts = [
            c.source.model_copy(update={"quote": q.replace(" ", " really ", 1)}),
            c.source.model_copy(update={"quote": re.sub(r"[Ll]ib(\d+)", r"Lab\1", q, count=1)}),
            c.source.model_copy(
                update={"line_start": c.source.line_start + 2, "line_end": c.source.line_end + 2}
            ),
            c.source.model_copy(
                update={"line_start": c.source.line_start - 1, "line_end": c.source.line_end - 1}
            ),
        ]
        for m in muts:
            total += 1
            caught += verify_source_quote(repo, m).status != "VERIFIED"
    print(f"\nG1 tamper on decorated ADR: {caught}/{total} caught ({len(cs.claims)} claims)")
    assert caught == total


def test_decorated_sentences_inside_one_paragraph_keep_exact_provenance(make_repo):
    text = adr(
        "Decision: We will use Kafka, to reduce ops cost (see ADR-0007). Services must not use Redis,\n"
        "given our expertise. Note that only adapters/ may import boto3 as a rule."
    )
    repo, cs = offline(make_repo, text)
    assert [c.kind for c in cs.claims] == ["require", "forbid", "boundary"]
    assert cs.unverified == []
    for c in cs.claims:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
        assert c.source.quote in text.replace("\n", " ") or c.source.quote.replace(
            "\n", " "
        ) in text.replace("\n", " ")


# ===================================================================== perf (held)


def timed(fn, *a):
    t = time.perf_counter()
    fn(*a)
    return time.perf_counter() - t


K = 100_000


@pytest.mark.parametrize(
    ("name", "s", "limit"),
    [
        ("decorations (see ADR)", "We will use Kafka " + "(see ADR-0007) " * 6600 + ".", 5),
        ("lead Note that", "Note that " * 10000 + "we will use Kafka.", 5),
        ("trail to reduce cost", "We will use Kafka" + ", to reduce cost" * 6600 + ".", 8),
        (
            "trail in order to",
            "We will use Kafka" + ", in order to reduce ops cost" * 3400 + ".",
            8,
        ),
        ("trail which keeps", "We will use Kafka" + ", which keeps it simple" * 4400 + ".", 8),
        ("trail due to", "We will use Kafka" + ", due to licensing concerns" * 3800 + ".", 8),
        ("trail for consistency", "We will use Kafka" + " for consistency" * 6200 + ".", 8),
        (
            "trail across the organization",
            "We will use Kafka" + " across the organization" * 4100 + ".",
            8,
        ),
        ("parens (((", "We will use Kafka " + "(" * K + ".", 8),
        ("parens (see (see", "We will use Kafka " + "(see " * 20000 + ".", 8),
        ("to to to", "We will use Kafka " + "to " * 33000 + ".", 12),
        ("as per as per", "We will use Kafka, " + "as per " * 14000 + ".", 12),
        ("given given", "Do not use Redis, " + "given " * 16600 + ".", 12),
        ("for for", "We will use Kafka " + "for " * 25000 + ".", 12),
        ("instead of chain", "We will use A " + "instead of B " * 7600 + ".", 12),
        (
            "term list + rationale",
            "Do not use " + ", ".join(f"T{i}" for i in range(16000)) + ", given our expertise.",
            8,
        ),
    ],
)
def test_perf_100kb_single_sentence_decorated(name, s, limit):
    assert 90_000 < len(s) < 125_000, len(s)
    dt = timed(match_sentence, s)
    print(f"\n{name}: {dt:.2f}s")
    assert dt < limit


def test_perf_scaling_is_linear_for_the_worst_pattern():
    a = timed(match_sentence, "We will use Kafka " + "to " * 8000 + ".")
    b = timed(match_sentence, "We will use Kafka " + "to " * 32000 + ".")
    assert b < max(a, 0.05) * 8  # 4x input, well below quadratic (16x)


def test_perf_100kb_decorated_paragraph_sentence_spans():
    s = "Decision: We will use Kafka, to reduce ops cost (see ADR-0007). " * 1500
    assert timed(lambda t: [match_sentence(t[a:b]) for a, b in sentence_spans(t)], s) < 20


def test_perf_5000_claim_decorated_adr_end_to_end(make_repo):
    body = "\n".join(
        f"Decision: Module m{i} must not import legacy{i}, to reduce ops cost (see ADR-0007)."
        for i in range(5000)
    )
    t = time.perf_counter()
    repo, cs = offline(make_repo, adr(body))
    dt = time.perf_counter() - t
    print(f"\n5000 decorated claims end to end: {dt:.1f}s")
    assert len(cs.claims) == 5000 and cs.unverified == []
    assert dt < 120
    for c in cs.claims[:: 5000 // 100]:
        assert verify_source_quote(repo, c.source).status == "VERIFIED"
