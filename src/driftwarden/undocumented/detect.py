"""Undocumented-decision detector (pipeline step 8). Deterministic: no LLM, no network.

Finds architectural technology choices present in the repository at one commit
that no ADR covers, and the commits that introduced them.

**What counts as a choice.** Every production occurrence (manifest dependency,
infra image, Terraform provider, import) of a catalog technology
(``judge.catalog``) in one of :data:`DETECTED_CATEGORIES`:

=================  ==========================================================
category           meaning
=================  ==========================================================
``datastore``      a database (PostgreSQL, MongoDB, ...)
``cache``          Redis, Memcached
``queue``          a broker / queue / task queue (Kafka, RabbitMQ, SQS, ...)
``search``         Elasticsearch / OpenSearch
``web-framework``  Django, FastAPI, Express, Spring Boot, Gin, ...
``cloud-sdk``      AWS / GCP / Azure SDKs
``vendor-sdk``     SaaS SDKs (Stripe, Twilio, Sentry, ...)
``http-client``    outbound service calls through an HTTP client library
``iac-provider``   a Terraform/OpenTofu provider (``required_providers`` or
                   a ``provider`` block). Catalog providers keep their catalog
                   id (``hashicorp/aws`` -> ``aws-sdk``); any other provider is
                   named by its type (``cloudflare/cloudflare`` -> ``cloudflare``).
                   Utility providers (random, null, local, time, tls, ...) and
                   modules are not choices.
=================  ==========================================================

Logging libraries, ORMs and frontend frameworks are not reported (they are
code-level choices, not architecture). Occurrences that do not ship -- test
files, dev/test/build/optional scopes, ``requirements-dev.txt``,
``docker-compose.test.yml`` and the rest of ``judge.evidence``'s rules -- never
make a record on their own: a technology seen only there is listed in
``UndocumentedScan.nonproduction``. Vendored third-party trees
(``node_modules/``, ``vendor/``, ``third_party/``, ``.venv/`` ...; see
:data:`VENDORED_DIRS`) are ignored altogether.

**Documented.** A technology is documented when the text of an ADR *as it is at
the scanned commit* mentions it (ADRs added later never document an older
commit). The searched text is each decision's title, context, decision,
consequences and chosen option, whatever the ADR's status: a superseded ADR, or
a rejected ADR whose own decision is about the technology ("We will not use
MongoDB"), still documents the choice -- whether the code obeys it is the
judge's business. Product decision (D-1, Fable): a technology named only as a
*considered / rejected alternative* in an options list (MADR "Considered
Options", a Nygard "Considered Options" section) is **not** documentation of
using it, so those sections are not searched and such a technology is flagged.
"Mentions" is a
case-insensitive whole-word match (letters, digits and ``_`` delimit words) of
any of :func:`technology_terms`: the catalog id and aliases, plus the package /
module / image / provider names the evidence uses (an ADR that says
``psycopg2`` documents PostgreSQL usage through it). The searched ADR text is
each decision's title, context, decision, consequences and chosen option, plus
the quote and rule terms of any claims passed in. Short aliases that are also
English words (``requests``, ``got``, ``echo``) can mark a technology as
documented by accident: that loses recall, never precision.

**Introducing commits.** For every evidence item the detector walks the file's
history back from the scanned commit: from the newest commit that changed the
file, while a parent still uses the technology *in production* in that file, it
moves to the newest commit at or below that parent that changed the file. The
commit whose parents all lack a production use (or lack the file) is the
introducing commit, so a dev-only dependency promoted to production is
introduced by the promotion. The record lists the distinct introducing commits
oldest first in topological order (an ancestor always before its descendants;
never by timestamp). A version bump does not move the introduction (the
technology was already there), unlike ``git blame``. In a shallow clone, a walk
that reaches a boundary commit (``.git/shallow``: parents unavailable) cannot
show absence before it, so that evidence has no introduction and the record is
*Could not verify*; the verifier rejects a boundary commit as an introduction.

Terraform ``provider "<local>"`` blocks are resolved through the module's
``required_providers`` (all ``*.tf`` / ``*.tofu`` files in the same directory,
at the same commit): ``provider "cf"`` with ``cf = { source =
"cloudflare/cloudflare" }`` is Cloudflare, never a technology called ``cf``. An
unmapped local name stays as written (implied ``hashicorp/<local>``). Because a
provider block's meaning depends on its module's other files, the history walk
for a Terraform file follows every commit that touched its directory: a source
change in ``versions.tf`` (``hashicorp/aws`` -> ``hashicorp/google``) introduces the
new provider for an unchanged ``provider`` block in ``main.tf`` too.

The verifier also re-runs the walk: a claimed introduction must be the commit the
walk gives for the occurrence at the scanned commit, so an obsolete introduction
(added at A, removed at B, re-added at C) never verifies for a scan at C.

**Grounding (fail closed).** :func:`verify_undocumented` re-checks a record from
scratch: G2 on every evidence line and G3 (``verify_dependency``) on every
manifest item, at the scanned commit; that the cited line really is a
production occurrence of *this* technology in *this* category (the manifest is
re-parsed, the import re-extracted) and that the evidence says so
(``Evidence.production``); that ``introducing_commits`` are in topological
order; G5 (``verify_commits_exist``) on every
introducing commit, which must also be an ancestor of the scanned commit; G2 on
the introducing line at the introducing commit; presence there and absence at
every parent; and, when ADRs are given, that none of them mentions the
technology. Any failure turns the record into ``status=UNKNOWN,
grounding=MISMATCH`` with the reasons: it is reported as *Could not verify*,
never as a finding, and never dropped. Free-text fields (``title``, ``notes``,
``Evidence.detail``, ``searched_terms``) are descriptive, not evidential, and
are not verified.

Known limits: name-based (see ``judge.catalog``), so technologies reached
through generic clients, connection URLs or vendored code are not seen; the
history walk follows one file path (a file renamed with the technology in it is
"introduced" by the rename); outbound calls are seen only through HTTP client
libraries, never through URLs in code or config.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from driftwarden import git
from driftwarden.config import Config
from driftwarden.discover.adr import scan_adrs_at
from driftwarden.grounding.ledger import Ledger
from driftwarden.grounding.verify import (
    commit_problem,
    verify_commits_exist,
    verify_source_quote,
)
from driftwarden.index.files import SNIFF_BYTES, detect_language
from driftwarden.index.imports import (
    _js_package,
    extract_go,
    extract_java,
    extract_js,
    extract_python,
)
from driftwarden.index.manifests import canonical_package, parse_manifest
from driftwarden.index.manifests.terraform import provider_sources
from driftwarden.judge import catalog
from driftwarden.judge.evidence import (
    Snapshot,
    _occurrences,
    _snippet,
    is_nonproduction_manifest,
    is_test_path,
    is_weak_scope,
    load_snapshot,
)
from driftwarden.judge.judge import verify_evidence
from driftwarden.models import (
    WORKTREE,
    Claim,
    Decision,
    Evidence,
    GroundingResult,
    Introduction,
    Provenance,
    UndocumentedDecision,
)
from driftwarden.text import decode_text, split_lines

IAC_CATEGORY = "iac-provider"
DETECTED_CATEGORIES: tuple[str, ...] = (
    "datastore",
    "cache",
    "queue",
    "search",
    "web-framework",
    "cloud-sdk",
    "vendor-sdk",
    "http-client",
    IAC_CATEGORY,
)
CATEGORY_LABELS = {
    "datastore": "datastore",
    "cache": "cache",
    "queue": "queue / message broker",
    "search": "search engine",
    "web-framework": "web framework",
    "cloud-sdk": "cloud SDK",
    "vendor-sdk": "vendor SDK",
    "http-client": "outbound service calls (HTTP client)",
    IAC_CATEGORY: "infrastructure-as-code provider",
}
# Terraform providers that are tooling, not an infrastructure choice.
UTILITY_PROVIDERS = frozenset(
    "random null local time tls archive external template http cloudinit terraform".split()
)
DEFAULT_MAX_EVIDENCE = 10
MAX_HISTORY_STEPS = 2000

Key = tuple[str, str]  # (technology id, category)


# --------------------------------------------------------------------------- classification


def _provider_name(source: str) -> str:
    return source.strip().lower().rstrip("/").rsplit("/", 1)[-1]


def occurrence_keys(namespace: str, names: Iterable[str], ecosystem: str | None) -> list[Key]:
    """The (technology, category) choices one occurrence stands for, or []."""
    names = [n for n in names if n]
    if not names:
        return []
    if namespace == "terraform":
        if ecosystem != "terraform-provider":
            return []  # required_version, modules: not a provider choice
        hits = [
            t
            for t in catalog.TECHNOLOGIES
            if not t.literal and catalog.name_matches(t, "terraform", names)
        ]
        if hits:
            return [(t.id, IAC_CATEGORY) for t in hits]
        name = _provider_name(names[0])
        if not name or name in UTILITY_PROVIDERS or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
            return []
        return [(name, IAC_CATEGORY)]
    return [
        (t.id, t.category)
        for t in catalog.TECHNOLOGIES
        if t.category in DETECTED_CATEGORIES
        and not t.literal
        and catalog.name_matches(t, namespace, names)
    ]


# Third-party code checked into the repository: never this repository's choice.
VENDORED_DIRS = frozenset(
    {"node_modules", "vendor", "vendors", "third_party", "third-party", "thirdparty",
     "bower_components", "jspm_packages", "site-packages", ".venv", "venv", "Pods"}
)  # fmt: skip


def is_vendored(path: str) -> bool:
    """True when ``path`` lies in a vendored / third-party directory (any depth)."""
    return any(seg in VENDORED_DIRS for seg in path.split("/")[:-1])


def _dep_production(dep) -> bool:
    path = dep.manifest_path
    return not (
        is_weak_scope(dep.scope)
        or is_test_path(path)
        or is_nonproduction_manifest(path)
        or is_vendored(path)
    )


class _Keys:
    """Memoised ``occurrence_keys`` for one run (large manifests repeat the same
    names at every commit; matching each name against the catalog once is enough)."""

    def __init__(self) -> None:
        self._memo: dict[tuple, list[Key]] = {}

    def __call__(self, namespace: str, names: Iterable[str], ecosystem: str | None) -> list[Key]:
        k = (namespace, tuple(names), ecosystem)
        if k not in self._memo:
            self._memo[k] = occurrence_keys(namespace, k[1], ecosystem)
        return self._memo[k]


# --------------------------------------------------------------------------- per-file presence


@dataclass(frozen=True)
class _Hit:
    line_start: int
    line_end: int
    production: bool
    package: str | None = None  # manifest items: the declared package
    line: int | None = None  # manifest items: the declared line
    names: tuple[str, ...] = ()  # the package / module names on the line


TF_SUFFIXES = (".tf", ".tofu")


def ref_names(ref, tf_sources: dict[str, str] | None = None) -> tuple[str, ...]:
    """The names a dependency ref is matched by. A Terraform ``provider "cf"`` block is
    resolved through its module's ``required_providers`` (``cf`` ->
    ``cloudflare/cloudflare``), so an explicitly mapped local name never becomes a
    technology of its own; an unmapped local name stays as written."""
    if (
        ref.ecosystem == "terraform-provider"
        and ref.scope == "provider-block"
        and tf_sources
        and ref.package in tf_sources
    ):
        return (tf_sources[ref.package],)
    return (ref.package,)


def _import_names(path: str, text: str) -> list[tuple[int, int, tuple[str, ...], str]]:
    """``(line, end_line, names, namespace)`` for each non-relative import in one file.

    The language is detected from the name *and* the content prefix, as
    ``load_snapshot`` does, so extensionless shebang scripts (``bin/worker`` with
    ``#!/usr/bin/env python3``) are read the same way in history and verification."""
    lang = detect_language(path, text.encode("utf-8", "replace")[:SNIFF_BYTES])
    out: list[tuple[int, int, tuple[str, ...], str]] = []
    if lang == "python":
        raws, _ = extract_python(text)
        for r in raws:
            if r.level or not r.module:
                continue
            q = tuple(f"{r.module}.{n}" for n in r.names if n and n != "*")
            names = tuple(dict.fromkeys((r.module.split(".")[0], r.module, *q)))
            out.append((r.line, max(r.end_line, r.line), names, "py"))
    elif lang in ("javascript", "typescript"):
        for r in extract_js(text):
            if not r.module or r.module.startswith((".", "/")):
                continue
            names = tuple(dict.fromkeys((_js_package(r.module), r.module)))
            out.append((r.line, max(r.end_line, r.line), names, "npm"))
    elif lang == "java":
        _, raws = extract_java(text)
        for r in raws:
            out.append((r.line, max(r.end_line, r.line), (r.module,), "java"))
    elif lang == "go":
        for r in extract_go(text):
            out.append((r.line, max(r.end_line, r.line), (r.module,), "go"))
    return out


def file_hits(
    path: str,
    text: str,
    key: Key,
    kind: str,
    *,
    keys: Callable[[str, Iterable[str], str | None], list[Key]] = occurrence_keys,
    refs: list | None = None,
    tf_sources: dict[str, str] | None = None,
) -> list[_Hit]:
    """Lines of ``path`` (with content ``text``) where the technology ``key`` occurs.

    ``kind`` is the evidence kind: ``dependency`` / ``infra`` re-parse the file as a
    manifest (or use the already parsed ``refs``), ``import`` re-extracts its import
    statements. Each hit says whether that occurrence ships (``production``).
    ``tf_sources`` is the module's provider local-name map (default: this file's)."""
    hits: list[_Hit] = []
    if kind in ("dependency", "infra"):
        if tf_sources is None and path.endswith(TF_SUFFIXES):
            tf_sources = provider_sources(text)
        for ref in refs if refs is not None else parse_manifest(path, text).refs:
            ns = catalog.ECOSYSTEM_NAMESPACE.get(ref.ecosystem or "")
            if ns is None or ref.line is None:
                continue
            names = ref_names(ref, tf_sources)
            if key in keys(ns, names, ref.ecosystem):
                hits.append(
                    _Hit(ref.line, ref.line, _dep_production(ref), ref.package, ref.line,
                         tuple(dict.fromkeys((ref.package, *names))))
                )  # fmt: skip
    elif kind == "import":
        prod = not (is_test_path(path) or is_vendored(path))
        for start, end, names, ns in _import_names(path, text):
            if key in keys(ns, names, None):
                hits.append(_Hit(start, end, prod, names=names))
    return hits


class _History:
    """File contents at commits, cached by blob, for presence checks."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._blob: dict[tuple[str, str], str | None] = {}
        self._text: dict[str, str] = {}
        self._hits: dict[tuple[str, str, Key, str], list[_Hit]] = {}
        self._refs: dict[tuple[str, str], list] = {}
        self._parents: dict[str, list[str]] = {}
        self._order: dict[str, dict[str, int]] = {}
        self._tf: dict[tuple[str, str], dict[str, str]] = {}
        self._shallow: frozenset[str] | None = None
        self.keys = _Keys()

    @property
    def shallow(self) -> frozenset[str]:
        """Shallow-clone boundary commits (their parents are not available)."""
        if self._shallow is None:
            self._shallow = git.shallow_boundary(self.root)
        return self._shallow

    def tf_sources(self, commit: str, path: str) -> dict[str, str]:
        """Provider local name -> source for the Terraform module (directory) holding
        ``path``, at ``commit``."""
        d = path.rsplit("/", 1)[0] if "/" in path else ""
        k = (commit, d)
        if k not in self._tf:
            out: dict[str, str] = {}
            for f in sorted(git.list_dir(self.root, commit, d)):
                if f.endswith(TF_SUFFIXES):
                    out.update(provider_sources(self.text(commit, f) or ""))
            self._tf[k] = out
        return self._tf[k]

    def text(self, commit: str, path: str) -> str | None:
        k = (commit, path)
        if k not in self._blob:
            self._blob[k] = git.blob_at(self.root, commit, path)
        blob = self._blob[k]
        if blob is None:
            return None
        if blob not in self._text:
            self._text[blob] = decode_text(git.read_blobs(self.root, [blob])[blob])
        return self._text[blob]

    def hits(self, commit: str, path: str, key: Key, kind: str) -> list[_Hit]:
        text = self.text(commit, path)
        if text is None:
            return []
        blob = self._blob[(commit, path)]
        tf = None
        if kind in ("dependency", "infra") and path.endswith(TF_SUFFIXES):
            tf = self.tf_sources(commit, path)
        hk = (blob or "", path, key, kind, tuple(sorted(tf.items())) if tf else ())
        if hk not in self._hits:
            refs = None
            if kind in ("dependency", "infra"):
                rk = (blob or "", path)
                if rk not in self._refs:
                    self._refs[rk] = parse_manifest(path, text).refs
                refs = self._refs[rk]
            self._hits[hk] = file_hits(
                path, text, key, kind, keys=self.keys, refs=refs, tf_sources=tf
            )
        return self._hits[hk]

    def production_hits(self, commit: str, path: str, key: Key, kind: str) -> list[_Hit]:
        return [h for h in self.hits(commit, path, key, kind) if h.production]

    def topo_index(self, tip: str) -> dict[str, int]:
        """Position of every commit reachable from ``tip`` in topological order,
        ancestors first (so an ancestor always sorts before its descendants)."""
        if tip not in self._order:
            shas = git.rev_list_topo(self.root, tip)
            self._order[tip] = {c: i for i, c in enumerate(shas)}
        return self._order[tip]

    def parents(self, commit: str) -> list[str]:
        if commit not in self._parents:
            self._parents[commit] = git.parents(self.root, commit)
        return self._parents[commit]


def _introduction(
    hist: _History, scan_commit: str, ev: Evidence, key: Key
) -> tuple[Introduction | None, str]:
    """The commit that brought ``key`` into ``ev``'s file *as a production occurrence*
    (a dev-only dependency later promoted to production is introduced by the
    promotion), or (None, why).

    A Terraform file's meaning also depends on the other ``*.tf`` files of its module
    (``required_providers`` maps a provider block's local name), so for those the walk
    follows every commit that touched the module directory, not just the file."""
    path = ev.ref.path
    track = path
    if path.endswith(TF_SUFFIXES):
        track = path.rsplit("/", 1)[0] + "/" if "/" in path else "."
    cur = git.last_commit_touching(hist.root, scan_commit, track)
    seen: set[str] = set()
    while cur is not None and cur not in seen and len(seen) < MAX_HISTORY_STEPS:
        seen.add(cur)
        here = hist.production_hits(cur, path, key, ev.kind)
        if not here:
            return None, f"{path}: technology not found at {cur[:12]} while walking history"
        if cur in hist.shallow:
            return None, (
                f"{path}: history is truncated at shallow-clone boundary {cur[:12]} (its "
                "parents are not available); the introducing commit cannot be established"
            )
        present = [p for p in hist.parents(cur) if hist.production_hits(p, path, key, ev.kind)]
        if not present:
            lines = split_lines(hist.text(cur, path) or "")
            h = here[0]
            quote = "\n".join(lines[h.line_start - 1 : h.line_end])
            ref = Provenance(
                path=path, line_start=h.line_start, line_end=h.line_end, commit=cur, quote=quote
            )
            return Introduction(
                evidence_id=ev.id, commit=cur, parents=list(hist.parents(cur)), ref=ref
            ), ""
        cur = git.last_commit_touching(hist.root, present[0], track)
    return None, f"{path}: no introducing commit found"


# --------------------------------------------------------------------------- ADR coverage


def technology_terms(technology: str, category: str, packages: Iterable[str] = ()) -> list[str]:
    """Words that, found in an ADR, document this technology: catalog id + aliases (or
    the provider name) and the package / module / image names the code uses."""
    terms: list[str] = [technology]
    tech = catalog.technology(technology)
    if tech is not None:
        terms.extend(tech.aliases)
    for p in packages:
        if not p:
            continue
        terms.append(p)
        if category == IAC_CATEGORY:
            terms.append(_provider_name(p))
    out: list[str] = []
    for t in terms:
        t = " ".join(t.split())
        if t and t.lower() not in (o.lower() for o in out):
            out.append(t)
    return out


def _term_regex(terms: Iterable[str]) -> re.Pattern[str] | None:
    parts = [r"\s+".join(map(re.escape, t.split())) for t in terms if t.strip()]
    if not parts:
        return None
    alt = "|".join(sorted(parts, key=len, reverse=True))
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{alt})(?![A-Za-z0-9_])", re.IGNORECASE)


def _adr_texts(decisions: Iterable[Decision], claims: Iterable[Claim]) -> dict[str, list[str]]:
    texts: dict[str, list[str]] = {}
    for d in decisions:
        parts = [d.title, d.context, d.decision_text, d.consequences, d.chosen_option]
        texts.setdefault(d.id, []).extend(p for p in parts if p)
    for c in claims:
        bucket = texts.setdefault(c.decision_id, [])
        bucket.append(c.source.quote)
        for v in c.rule.values():
            if isinstance(v, str):
                bucket.append(v)
            elif isinstance(v, list):
                bucket.extend(x for x in v if isinstance(x, str))
    return texts


def adr_mentions(
    terms: Iterable[str], decisions: Iterable[Decision], claims: Iterable[Claim] = ()
) -> list[str]:
    """Ids of the decisions whose text (or claims) mentions any of ``terms``."""
    rx = _term_regex(terms)
    if rx is None:
        return []
    return [
        did
        for did, parts in _adr_texts(decisions, claims).items()
        if any(rx.search(p) for p in parts)
    ]


# --------------------------------------------------------------------------- verification


def _key_of(rec: UndocumentedDecision) -> Key:
    return (rec.technology, rec.category)


def _semantic(
    root: Path, rec: UndocumentedDecision, ev: Evidence, hist: _History, names: list[str]
) -> list[str]:
    """Problems with ``ev`` as production evidence of ``rec``'s technology, re-derived
    from the file at the record's commit ([] when it holds). The names found on the
    cited lines are added to ``names``."""
    problems: list[str] = []
    loc = f"{ev.ref.path}:{ev.ref.line_start}-{ev.ref.line_end}"
    if ev.technology != rec.technology:
        problems.append(f"evidence is about {ev.technology!r}, record is {rec.technology!r}")
    if ev.kind not in ("dependency", "infra", "import"):
        return [*problems, f"evidence kind {ev.kind!r} cannot show a technology choice"]
    if ev.kind in ("dependency", "infra") and ev.dependency is None:
        return [*problems, "manifest evidence without a dependency record (G3)"]
    if ev.kind == "import" and ev.dependency is not None:
        problems.append("import evidence must not carry a dependency record")
    if not ev.production:
        problems.append("evidence is marked non-production; only production use is a finding")
    if ev.ref.commit != rec.commit or commit_problem(root, rec.commit) is not None:
        return problems  # reported by the commit checks
    try:
        hits = hist.hits(rec.commit, ev.ref.path, _key_of(rec), ev.kind)
    except git.GitError as exc:
        return [*problems, f"{loc}: could not read file ({exc})"]
    inside = [h for h in hits if ev.ref.line_start <= h.line_start <= ev.ref.line_end]
    if ev.dependency is not None:
        d = ev.dependency
        eco = d.ecosystem
        inside = [
            h
            for h in inside
            if h.line == d.line
            and h.package is not None
            and canonical_package(eco, h.package) == canonical_package(eco, d.package)
        ]
    for h in inside:
        names.extend(n for n in h.names if n not in names)
    if not inside:
        problems.append(
            f"{loc}: no {ev.kind} of {rec.technology} ({rec.category}) at the cited lines"
        )
    elif not any(h.production for h in inside):
        problems.append(f"{loc}: the occurrence is test/dev-only, not a production choice")
    return problems


def _check(ok: bool, reason: str, prov=None, subject: str | None = None, cid: str = "G5"):
    return GroundingResult(
        check_id=cid,
        status="VERIFIED" if ok else "MISMATCH",
        reason=reason,
        provenance=prov,
        subject=subject,
    )


def verify_undocumented(
    repo: str | Path,
    rec: UndocumentedDecision,
    *,
    decisions: Iterable[Decision] | None = None,
    claims: Iterable[Claim] = (),
    _hist: _History | None = None,
) -> UndocumentedDecision:
    """Re-verify every fact ``rec`` states (see the module docstring). Returns the
    record with ``checks`` replaced, and ``status/grounding/reasons`` set: VERIFIED
    and UNDOCUMENTED, or UNKNOWN / MISMATCH with every reason. Never raises for bad
    provenance; raises only if ``repo`` is not a git repository."""
    root = git.repo_root(repo)
    hist = _hist or _History(root)
    checks: list[GroundingResult] = []
    reasons: list[str] = []
    subj = rec.id

    def fail(reason: str, prov=None, cid: str = "G5") -> None:
        checks.append(_check(False, reason, prov, subj, cid))
        reasons.append(reason)

    try:
        bad = commit_problem(root, rec.commit) if rec.commit != WORKTREE else "WORKTREE"
        if bad is not None:
            fail(f"scanned commit: {bad} (a pinned commit is required)")
        if rec.category not in DETECTED_CATEGORIES:
            fail(f"category {rec.category!r} is not a detected category")
        if not rec.evidence:
            fail("no evidence cited")
        ids = [e.id for e in rec.evidence]
        if len(set(ids)) != len(ids):
            fail("duplicate evidence ids")
        # G2 / G3 at the scanned commit, then: is it really this technology, in production?
        names: list[str] = []
        for ev in rec.evidence:
            for r in verify_evidence(root, ev, commit=rec.commit, subject=f"{subj}/{ev.id}"):
                checks.append(r)
                if r.status != "VERIFIED":
                    reasons.append(f"{ev.id}: {r.reason}")
            for p in _semantic(root, rec, ev, hist, names):
                fail(f"{ev.id}: {p}", ev.ref, "G2")
        # G5: introducing commits.
        by_id = {e.id: e for e in rec.evidence}
        covered = {i.evidence_id for i in rec.introductions}
        for e in rec.evidence:
            if e.id not in covered:
                fail(f"{e.id}: no introducing commit")
        intro_commits = {i.commit for i in rec.introductions}
        if set(rec.introducing_commits) != intro_commits:
            fail(
                "introducing_commits do not match the introductions: "
                f"{sorted(c[:12] for c in rec.introducing_commits)} vs "
                f"{sorted(c[:12] for c in intro_commits)}"
            )
        if len(set(rec.introducing_commits)) != len(rec.introducing_commits):
            fail("introducing_commits lists a commit twice")
        anchor = rec.commit if bad is None else None
        if anchor is not None:
            order = hist.topo_index(anchor)
            listed = list(rec.introducing_commits)
            if all(c in order for c in listed) and listed != _oldest_first(listed, order):
                fail("introducing_commits are not oldest first (topological order)")
        for r in verify_commits_exist(
            root, sorted(intro_commits | set(rec.introducing_commits)) or [], ancestor_of=anchor,
            subject=subj,
        ):  # fmt: skip
            checks.append(r)
            if r.status != "VERIFIED":
                reasons.append(r.reason)
        for intro in rec.introductions:
            _verify_intro(root, rec, intro, by_id.get(intro.evidence_id), hist, fail, checks)
        # Coverage: still undocumented?
        if decisions is not None:
            terms = technology_terms(rec.technology, rec.category, names)
            terms += [t for t in rec.searched_terms if t not in terms]
            hit = adr_mentions(terms, decisions, claims)
            if hit:
                fail(f"documented: {', '.join(hit)} mention(s) {rec.technology}", cid="G5")
    except git.NotAGitRepoError:
        raise
    except Exception as exc:  # bad provenance is a MISMATCH, never a crash
        fail(f"could not verify ({type(exc).__name__}: {exc})")

    data = rec.model_dump()
    data["checks"] = checks
    if reasons:
        data.update(status="UNKNOWN", grounding="MISMATCH", reasons=reasons)
    else:
        data.update(status="UNDOCUMENTED", grounding="VERIFIED", reasons=[])
    return UndocumentedDecision.model_validate(data)


def _verify_intro(
    root: Path,
    rec: UndocumentedDecision,
    intro: Introduction,
    ev: Evidence | None,
    hist: _History,
    fail: Callable[..., None],
    checks: list[GroundingResult],
) -> None:
    tag = f"{intro.evidence_id} introduced at {str(intro.commit)[:12]}"
    if ev is None:
        fail(f"{tag}: no such evidence item")
        return
    if intro.ref.commit != intro.commit:
        fail(f"{tag}: introducing line is from commit {intro.ref.commit[:12]}")
        return
    if intro.ref.path != ev.ref.path:
        fail(f"{tag}: introducing line is in {intro.ref.path}, evidence in {ev.ref.path}")
        return
    if commit_problem(root, intro.commit) is not None:
        return  # reported by verify_commits_exist
    if intro.commit in hist.shallow:
        fail(
            f"{tag}: commit is a shallow-clone boundary (parents unavailable); "
            "absence before it cannot be checked",
            intro.ref,
        )
        return
    g2 = verify_source_quote(root, intro.ref, check_id="G2", subject=f"{rec.id}/{tag}")
    checks.append(g2)
    if g2.status != "VERIFIED":
        fail(f"{tag}: {g2.reason}", intro.ref, "G2")
        return
    key = _key_of(rec)
    here = hist.production_hits(intro.commit, intro.ref.path, key, ev.kind)
    if not any(intro.ref.line_start <= h.line_start <= intro.ref.line_end for h in here):
        fail(
            f"{tag}: no production use of {rec.technology} at the cited lines of that commit",
            intro.ref,
        )
        return
    actual = hist.parents(intro.commit)
    if sorted(actual) != sorted(intro.parents):
        fail(f"{tag}: parents are {[p[:12] for p in actual]}, record says otherwise", intro.ref)
        return
    for p in actual:
        if hist.production_hits(p, intro.ref.path, key, ev.kind):
            fail(
                f"{tag}: {rec.technology} is already used in production in {intro.ref.path} "
                f"at parent {p[:12]}"
            )
            return
    # Continuity: the introduction must be the one that leads, without a removal in
    # between, to the occurrence at the scanned commit -- i.e. the commit the detector
    # itself computes now. An obsolete introduction (added, removed, re-added) fails.
    if commit_problem(root, rec.commit) is None:
        mine, why = _introduction(hist, rec.commit, ev, key)
        if mine is None or mine.commit != intro.commit:
            got = f"{mine.commit[:12]}" if mine is not None else f"none ({why})"
            fail(
                f"{tag}: not the introduction of the occurrence at {rec.commit[:12]} "
                f"(the history walk gives {got}); it was removed or replaced in between",
                intro.ref,
            )
            return
    checks.append(
        _check(
            True,
            f"{tag}: present in {intro.ref.path} at the commit, absent at "
            f"{len(actual) or 'no'} parent(s), continuous up to the scanned commit",
            intro.ref,
            rec.id,
        )
    )


# --------------------------------------------------------------------------- detection


class UndocumentedScan(BaseModel):
    """Result of :func:`detect_undocumented` at one commit."""

    commit: str
    findings: list[UndocumentedDecision] = Field(
        default_factory=list, description="VERIFIED undocumented decisions."
    )
    could_not_verify: list[UndocumentedDecision] = Field(
        default_factory=list, description="Records that failed verification (UNKNOWN)."
    )
    documented: dict[str, list[str]] = Field(
        default_factory=dict, description='"category/technology" -> ids of ADRs mentioning it.'
    )
    nonproduction: list[str] = Field(
        default_factory=list, description='"category/technology" seen only in dev/test code.'
    )
    notes: list[str] = Field(default_factory=list)

    @property
    def records(self) -> list[UndocumentedDecision]:
        return [*self.findings, *self.could_not_verify]

    @property
    def checks(self) -> list[GroundingResult]:
        return [c for r in self.records for c in r.checks]


@dataclass
class _Group:
    key: Key
    items: list[tuple[tuple, dict]] = field(default_factory=list)
    production: bool = False
    packages: list[str] = field(default_factory=list)


def _oldest_first(commits: Iterable[str], order: dict[str, int]) -> list[str]:
    """``commits`` in topological order (an ancestor always before its descendants);
    commits outside ``order`` go last, by SHA."""
    return sorted(commits, key=lambda c: (order.get(c, len(order)), c))


def _collect(snap: Snapshot, keys_of: _Keys) -> tuple[dict[Key, _Group], list[str]]:
    groups: dict[Key, _Group] = {}
    notes: list[str] = []
    seen: set[tuple] = set()
    tf_by_dir: dict[str, dict[str, str]] = {}
    for p in sorted(snap.texts):
        if p.endswith(TF_SUFFIXES):
            d = p.rsplit("/", 1)[0] if "/" in p else ""
            tf_by_dir.setdefault(d, {}).update(provider_sources(snap.texts[p]))
    for o in _occurrences(snap):
        if is_vendored(o.path):
            continue  # third-party code checked in: not this repository's choice
        eco = o.dep.ecosystem if o.dep is not None else None
        names = o.names
        if o.dep is not None and o.path.endswith(TF_SUFFIXES):
            d = o.path.rsplit("/", 1)[0] if "/" in o.path else ""
            names = ref_names(o.dep, tf_by_dir.get(d))
        keys = keys_of(o.namespace, names, eco)
        if not keys:
            continue
        if o.edge is not None:
            e = o.edge
            start, end, path = e.line, max(e.end_line, e.line), e.source
            production = not is_test_path(path)
            detail, dep, pkg = f"{path}:{start} imports {e.module}", None, None
        else:
            d = o.dep
            assert d is not None
            if d.line is None:
                notes.append(f"{d.manifest_path}: {d.package} has no line; not citable")
                continue
            start = end = d.line
            path = d.manifest_path
            production = _dep_production(d)
            ver = f" {d.version_spec}" if d.version_spec else ""
            scope = f" [{d.scope}]" if d.scope else ""
            detail, dep, pkg = f"{path}:{start} declares {d.package}{ver}{scope}", d, d.package
        snippet = _snippet(snap, path, start, end)
        for key in keys:
            sk = (key, o.kind, path, start, end, pkg)
            if sk in seen:
                continue
            seen.add(sk)
            g = groups.setdefault(key, _Group(key))
            g.production = g.production or production
            for n in names:  # resolved names (a provider block's source, not its alias)
                if n and n not in g.packages:
                    g.packages.append(n)
            if not production:
                continue
            if snippet is None:
                notes.append(f"{path}:{start}-{end}: no source text; not citable")
                continue
            ref = Provenance(
                path=path, line_start=start, line_end=end, commit=snap.commit, quote=snippet
            )
            order = (0 if o.kind != "import" else 1, path, start)
            g.items.append(
                (
                    order,
                    {
                        "kind": o.kind,
                        "ref": ref,
                        "dependency": dep,
                        "technology": key[0],
                        "production": True,
                        "detail": detail,
                    },
                )
            )
    return groups, notes


def _title(key: Key) -> str:
    tech, cat = key
    t = catalog.technology(tech)
    name = (t.aliases[0] if t is not None and t.aliases else tech).title()
    if cat == IAC_CATEGORY:
        return f"Provision infrastructure with the {name} Terraform provider"
    return f"Use {name} as {CATEGORY_LABELS.get(cat, cat)}"


def detect_undocumented(
    repo: str | Path,
    commit: str = "HEAD",
    *,
    decisions: list[Decision] | None = None,
    claims: list[Claim] | None = None,
    config: Config | None = None,
    snapshot: Snapshot | None = None,
    ledger: Ledger | None = None,
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
) -> UndocumentedScan:
    """Technology choices at ``commit`` that no ADR (``decisions``, and ``claims`` if
    given) mentions, each re-verified. ``decisions=None`` discovers the ADRs *as they
    are at the scanned commit* (``scan_adrs_at``); the working tree is never read.
    ``commit`` must name a commit (WORKTREE has no history).

    Every record's checks are appended to ``ledger`` when one is given. Raises
    git.GitError if ``commit`` is not a commit, ValueError for WORKTREE.
    """
    if commit == WORKTREE or (snapshot is not None and snapshot.commit == WORKTREE):
        raise ValueError("undocumented-decision detection needs a commit, not the working tree")
    root = git.repo_root(repo)
    snap = snapshot or load_snapshot(root, commit, config)
    if decisions is None:
        # The ADRs as they were at the scanned commit -- never HEAD or the working tree,
        # so a later ADR cannot document (or a later edit undocument) an older commit.
        decisions = scan_adrs_at(root, snap.commit, config).decisions
    claims = list(claims or [])
    hist = _History(root)
    groups, notes = _collect(snap, hist.keys)
    result = UndocumentedScan(commit=snap.commit, notes=notes)
    for key in sorted(groups):
        g = groups[key]
        label = f"{key[1]}/{key[0]}"
        terms = technology_terms(key[0], key[1], g.packages)
        mentioned = adr_mentions(terms, decisions, claims)
        if mentioned:
            result.documented[label] = mentioned
            continue
        if not g.items:
            result.nonproduction.append(label)
            continue
        ordered = [d for _, d in sorted(g.items, key=lambda it: it[0])]
        rec_notes: list[str] = []
        if len(ordered) > max_evidence:
            rec_notes.append(f"{len(ordered) - max_evidence} further occurrence(s) not listed")
            ordered = ordered[:max_evidence]
        evidence = [Evidence(id=f"e{i}", **d) for i, d in enumerate(ordered, 1)]
        intros: list[Introduction] = []
        for ev in evidence:
            try:
                intro, why = _introduction(hist, snap.commit, ev, key)
            except git.NotAGitRepoError:
                raise
            except git.GitError as exc:
                intro, why = None, f"{ev.ref.path}: history walk failed ({exc})"
            if intro is None:
                rec_notes.append(f"{ev.id}: {why}")
            else:
                intros.append(intro)
        commits = _oldest_first({i.commit for i in intros}, hist.topo_index(snap.commit))
        rec = UndocumentedDecision.model_construct(
            id=f"UD-{key[1]}-{key[0]}",
            technology=key[0],
            category=key[1],
            title=_title(key),
            status="UNDOCUMENTED",
            commit=snap.commit,
            evidence=evidence,
            introductions=intros,
            introducing_commits=commits,
            searched_terms=terms,
            grounding="VERIFIED",
            reasons=[],
            checks=[],
            notes=rec_notes,
        )
        rec = verify_undocumented(root, rec, decisions=decisions, claims=claims, _hist=hist)
        if ledger is not None:
            ledger.extend(rec.checks)
        (result.could_not_verify if rec.could_not_verify else result.findings).append(rec)
    return result


__all__ = [
    "CATEGORY_LABELS",
    "DETECTED_CATEGORIES",
    "IAC_CATEGORY",
    "UndocumentedScan",
    "adr_mentions",
    "detect_undocumented",
    "file_hits",
    "occurrence_keys",
    "technology_terms",
    "verify_undocumented",
]
