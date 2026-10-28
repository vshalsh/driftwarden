"""Evidence collection per claim (pipeline step 5). Deterministic: no LLM, no network.

``load_snapshot(repo, commit)`` reads the repository *as it is at one commit*
(``git ls-tree`` + ``git cat-file --batch``, the same bytes ``git show`` gives
the verifiers) and builds its import graph and manifest list. Passing
``WORKTREE`` reads the working tree instead. ``collect_evidence(claim, snap)``
then gathers candidate :class:`~driftwarden.models.Evidence` for one claim.
Every item carries G2 provenance (path, line range, the verbatim source lines
as ``quote``, commit); dependency and infra items also carry the G3
``DependencyRef`` produced by the non-LLM manifest parsers.

Evidence kinds: ``import`` (an import statement), ``dependency`` (a manifest
declaration), ``infra`` (a container image or Terraform provider/module:
compose, Dockerfile, Kubernetes, Terraform), ``code`` (a source line that
mentions a claim term; context for the model only, never used by the rules).
``commit`` evidence is reserved for the drift timeline (L-011) and is not
produced here.

What is collected per rule kind (terms are resolved by ``judge.catalog``):

``forbid``
    Every dependency, infra image and import of a forbidden technology
    (relation ``forbidden``), restricted to ``scope`` paths when the rule has one.
``require``
    The required technology (``required``) and, when the category is known
    (``for`` or the technology's own category), every *other* member of that
    category (``alternative``).
``only``
    The allowed technology (``allowed``) and every other member of the
    category (``alternative``). The category comes from the rule's ``category``
    or, when the rule has none, from the allowed technology itself. A
    ``category`` (or a require's ``for``) phrase that is not a catalog category
    ("session storage", "service-to-service communication") is never widened to
    the technology's own category: the claim is UNKNOWN (fail closed, L-026).
``boundary``
    Imports of the target (a technology, a category such as "cloud SDK", or a
    repository directory such as ``payments/``) inside the ``allowed_in`` paths
    (``inside_boundary``) and outside them (``outside_boundary``). Manifests are
    repository-wide and are not boundary evidence.
``free`` and anything the rules cannot map
    No rule evidence; ``EvidenceSet.undecidable`` says why. Keyword (``code``)
    candidates are added so the model has something to cite.

Each item is flagged ``production=False`` when it sits in a test file
(``tests/``, ``test_*.py``, ``*.spec.ts``...), is a dev/test/build-scoped
dependency, or comes from a manifest whose name or directory marks it as
non-shipping (``requirements-dev.txt``, ``requirements/test.txt``,
``docker-compose.ci.yml``, ``docs/requirements.txt``; see
``is_nonproduction_manifest``); the rules then call the claim DRIFTING rather
than VIOLATED.

A claim with an ``actor`` ("Handlers must not import boto3 outside adapters/")
counts only occurrences in the actor's code: directories or modules named like
it (``handlers/``, ``handler.py``; see ``resolve_actor``). Whole-codebase actors
("code", "modules") need no filter; an actor that names nothing in the
repository makes the claim UNKNOWN ("actor scope not resolvable"), never
VIOLATED. "Alternative" evidence never includes an occurrence that also matches
the allowed/required technology (``ioredis`` is not a second cache next to
itself). The per-claim cap keeps up to ``max_per_relation`` items per
(relation, kind, production, technology) group, so a flood of one package can
never hide another technology the verdict depends on; truncation is noted.

Python ``from mysql import connector`` is matched as ``mysql`` *and*
``mysql.connector``, so dotted catalog patterns apply. A bare boundary target
("payments") that names an existing repository directory is that directory,
unless a package of that name is actually used, in which case both are
evaluated. Directory names are matched ignoring case when the exact spelling
does not exist and exactly one other spelling does ("Payments" -> payments/);
with no directory, a module file that local imports target (payments.py) is the
target (L-026).

Commit and WORKTREE snapshots select files the same way (by name, symlinks never
followed) and decode them like the verifiers (``text.decode_text``), so UTF-16
manifests are citable and both modes see the same evidence.

Files too large to read (source over ``MAX_PARSE_BYTES``) are listed in
``Snapshot.skipped``; every rule claim then carries an "incomplete evidence" note,
and a HOLDING verdict says so in its rationale. Policy: the verdict is not forced
to UNKNOWN (one generated file would otherwise blank every claim), but the gap
is never silent.

Known limits: Python imports are matched by module name, so a distribution
whose import name differs from every catalog/literal pattern is found only
through its manifest entry. Dynamic imports with computed names, and
technologies reached through generic clients or connection URLs, are not seen.
"""

from __future__ import annotations

import posixpath
import re
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from driftwarden import git
from driftwarden.config import Config
from driftwarden.index.files import (
    MAX_PARSE_BYTES,
    SNIFF_BYTES,
    FileEntry,
    FileIndex,
    _Excludes,
    detect_language,
    index_files,
    is_binary,
)
from driftwarden.index.imports import IMPORT_LANGUAGES, ImportEdge, ImportGraph, build_import_graph
from driftwarden.index.manifests import (
    ManifestError,
    ManifestResult,
    _prepare,
    detect,
    parse_manifest,
    scan_manifests,
)
from driftwarden.judge import catalog
from driftwarden.judge.catalog import Resolution, Technology
from driftwarden.models import (
    WORKTREE,
    Claim,
    DependencyRef,
    Evidence,
    EvidenceKind,
    EvidenceRelation,
    Provenance,
)
from driftwarden.text import decode_text, split_lines

# Languages whose text is kept for snippets and keyword search. Prose (markdown,
# rst, html) is left out: ADRs and docs are not evidence about the code.
TEXT_LANGUAGES = frozenset(
    {
        *IMPORT_LANGUAGES,
        "kotlin", "scala", "groovy", "csharp", "ruby", "rust", "php", "swift", "c", "cpp",
        "shell", "powershell", "sql", "terraform", "hcl", "yaml", "json", "toml", "xml", "ini",
        "dockerfile", "go-mod", "make", "protobuf", "vue", "svelte",
    }
)  # fmt: skip

INFRA_ECOSYSTEMS = frozenset({"docker", "terraform", "terraform-provider", "terraform-module"})

DEFAULT_MAX_PER_RELATION = 50
DEFAULT_MAX_KEYWORDS = 10


# --------------------------------------------------------------------------- snapshot


@dataclass
class Snapshot:
    """The repository at one commit: files, imports, manifests and source texts."""

    root: Path
    commit: str
    files: FileIndex
    imports: ImportGraph
    manifests: list[ManifestResult]
    texts: dict[str, str] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    """``(path, reason)`` for source files that could hold evidence but were not read
    (over ``MAX_PARSE_BYTES``). Absence verdicts mention them in their notes."""
    _lines: dict[str, list[str]] = field(default_factory=dict, repr=False)

    def lines(self, path: str) -> list[str] | None:
        if path not in self._lines:
            text = self.texts.get(path)
            if text is None:
                return None
            self._lines[path] = split_lines(text)
        return self._lines[path]

    def directories(self) -> set[str]:
        out: set[str] = set()
        for f in self.files:
            d = posixpath.dirname(f.path)
            while d and d not in out:
                out.add(d)
                d = posixpath.dirname(d)
        return out

    def dependency_refs(self) -> Iterator[DependencyRef]:
        for m in self.manifests:
            yield from m.refs


def _safe(path: str) -> bool:
    p = path.split("/")
    return bool(path) and not path.startswith("/") and ".." not in p and "" not in p


def _wanted(path: str) -> bool:
    return detect_language(path) in TEXT_LANGUAGES or detect(path) is not None


def _as_text(data: bytes, path: str) -> str | None:
    """Decoded text of a file, or None if it is binary. Decoding follows
    ``text.decode_text`` (the verifiers' rule), so UTF-16/32 files (BOM or NUL
    pattern) are text too, and their lines are the lines G2 checks."""
    if is_binary(b"", path):  # binary extension
        return None
    text = decode_text(data)
    return None if "\x00" in text else text


def _maybe_script(path: str) -> bool:
    """An extensionless file the name alone cannot classify (``bin/worker``)."""
    name = path.rsplit("/", 1)[-1]
    return "." not in name and detect_language(path) is None


def _unparsed(manifests: list[ManifestResult]) -> list[tuple[str, str]]:
    """Manifests that matched but yielded nothing (too large, malformed): evidence gap."""
    return [
        (m.path, f"manifest not read: {'; '.join(m.errors)[:200]}")
        for m in manifests
        if m.errors and not m.refs
    ]


def _too_large(path: str, size: int) -> tuple[str, str] | None:
    if size > MAX_PARSE_BYTES and detect_language(path) in TEXT_LANGUAGES:
        return path, f"{size} bytes, over the {MAX_PARSE_BYTES} byte parse limit; not read"
    return None


def _manifest_at(path: str, text: str, commit: str) -> ManifestResult | None:
    """Parse ``path`` the way ``scan_manifests`` does (same detection and sniffing),
    so commit and WORKTREE snapshots see the same manifests."""
    if "node_modules/" in f"/{path}":
        return None
    parser = detect(path)
    if parser is None:
        return None
    if parser.sniff is not None:
        try:
            sniffed = _prepare(text)
        except ManifestError:
            return None
        if not parser.sniff(path, sniffed):
            return None
    res = parse_manifest(path, text)
    res.commit = commit
    res.refs = [r.model_copy(update={"commit": commit}) for r in res.refs]
    return res


def load_snapshot(repo: str | Path, commit: str = "HEAD", config: Config | None = None) -> Snapshot:
    """The repository at ``commit`` (resolved to a full SHA), or the working tree
    when ``commit`` is WORKTREE. ``config.exclude`` is honoured.

    Raises git.GitError if ``commit`` does not name a commit.
    """
    cfg = config or Config()
    root = git.repo_root(repo)
    if commit == WORKTREE:
        return _worktree_snapshot(root, cfg)
    sha = git.resolve_commit(root, commit)
    excludes = _Excludes(list(cfg.exclude))
    entries = [e for e in git.tree_entries(root, sha) if _safe(e.path) and not excludes(e.path)]
    want = [e for e in entries if e.mode != "120000" and e.size <= MAX_PARSE_BYTES]
    # Extensionless files may be scripts with a shebang (bin/worker): read them too and
    # keep the ones the indexer's shebang detection recognises.
    want = [e for e in want if _wanted(e.path) or _maybe_script(e.path)]
    blobs = git.read_blobs(root, [e.sha for e in want])
    wanted = {e.path for e in want}

    texts: dict[str, str] = {}
    skipped = [s for s in (_too_large(e.path, e.size) for e in entries if e.mode != "120000") if s]
    file_entries: list[FileEntry] = []
    with tempfile.TemporaryDirectory(prefix="driftwarden-snap-") as tmp:
        base = Path(tmp)
        for e in entries:
            if e.mode == "120000":
                file_entries.append(
                    FileEntry(
                        e.path, e.size, detect_language(e.path), is_symlink=True, tracked=True
                    )
                )
                continue
            if e.path not in wanted:
                binary = is_binary(b"", e.path)
                lang = None if binary else detect_language(e.path)
                file_entries.append(FileEntry(e.path, e.size, lang, binary, tracked=True))
                continue
            data = blobs[e.sha]
            text = _as_text(data, e.path)
            binary = text is None
            lang = None if binary else detect_language(e.path, data[:SNIFF_BYTES])
            file_entries.append(FileEntry(e.path, e.size, lang, binary, tracked=True))
            if text is None or (not _wanted(e.path) and lang not in TEXT_LANGUAGES):
                continue
            dest = base / e.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            texts[e.path] = text
        file_entries.sort(key=lambda f: f.path)
        graph = build_import_graph(FileIndex(root=base, files=file_entries, source="git"))

    manifests = [m for m in scan_manifests(root, sha) if not excludes(m.path)]
    skipped.extend(_unparsed(manifests))
    files = FileIndex(root=root, files=file_entries, source=f"git:{sha}")
    return Snapshot(
        root=root,
        commit=sha,
        files=files,
        imports=graph,
        manifests=manifests,
        texts=texts,
        skipped=skipped,
    )


def _worktree_snapshot(root: Path, cfg: Config) -> Snapshot:
    files = index_files(root, cfg.exclude)
    graph = build_import_graph(files)
    texts: dict[str, str] = {}
    manifests: list[ManifestResult] = []
    skipped: list[tuple[str, str]] = []
    # Same selection as the commit snapshot: by file name, not by the index's language
    # (requirements*.txt has none), symlinks never followed.
    for f in files:
        if f.is_symlink:
            continue
        is_manifest = detect(f.path) is not None
        if f.size > MAX_PARSE_BYTES and not is_manifest:
            big = _too_large(f.path, f.size)
            if big:
                skipped.append(big)
            continue
        if not (_wanted(f.path) or f.language in TEXT_LANGUAGES):  # shebang scripts too
            continue
        try:
            data = (root / f.path).read_bytes()
        except OSError:
            continue
        text = _as_text(data, f.path)
        if text is not None and f.size <= MAX_PARSE_BYTES:
            texts[f.path] = text
        res = _manifest_at(f.path, decode_text(data), WORKTREE)
        if res is not None:
            manifests.append(res)
    skipped.extend(_unparsed(manifests))
    return Snapshot(
        root=root,
        commit=WORKTREE,
        files=files,
        imports=graph,
        manifests=manifests,
        texts=texts,
        skipped=skipped,
    )


# --------------------------------------------------------------------------- helpers

_TEST_DIRS = frozenset(
    {"test", "tests", "testing", "__tests__", "spec", "specs", "e2e", "testdata", "fixtures"}
)
_TEST_FILE = re.compile(
    r"(?:^test_.*\.py|.*_test\.py|^conftest\.py|.*_test\.go|.*\.(?:test|spec)\.[cm]?[jt]sx?|"
    r".*Tests?\.(?:java|kt|cs))$"
)
_WEAK_SCOPES = frozenset({"dev", "test", "build", "plugin", "parent", "indirect", "peer"})


def is_test_path(path: str) -> bool:
    """True for files that are tests (by directory or file-name convention)."""
    parts = path.split("/")
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]):
        return True
    return bool(_TEST_FILE.match(parts[-1]))


# Words in a manifest's file name (or a requirements/ file's stem) that mark it as
# not shipping: requirements-dev.txt, dev-requirements.txt, requirements/test.txt,
# requirements-docs.txt, docker-compose.ci.yml, Dockerfile.test.
_NONPROD_NAME_WORDS = frozenset(
    {"dev", "devel", "develop", "development", "test", "tests", "testing", "ci", "docs", "doc",
     "lint", "linting", "typing", "bench", "benchmark", "benchmarks"}
)  # fmt: skip
# Directories whose manifests do not ship (test directories are covered by is_test_path).
# A bare "dev/" directory is deliberately NOT in the list: it often holds real
# service code ("dev/requirements.txt" of a service called dev).
_NONPROD_DIRS = frozenset({"ci", ".ci", "docs", "doc", "lint", ".github", "benchmarks"})


def is_nonproduction_manifest(path: str) -> bool:
    """True for manifests that by name or directory are dev/test/CI/docs/lint only."""
    parts = path.lower().split("/")
    if any(p in _NONPROD_DIRS for p in parts[:-1]):
        return True
    words = re.split(r"[-_.]+", parts[-1])
    return any(w in _NONPROD_NAME_WORDS for w in words)


# Whole words in a scope's name that mark it as non-shipping. "staging" is NOT in the
# list: a staging deployment still runs the technology, so a claim about it applies.
_NONPROD_SCOPE_WORDS = frozenset(
    {"dev", "devel", "development", "test", "tests", "testing", "e2e", "ci", "docs", "doc",
     "lint", "linting", "mock", "mocks", "fixture", "fixtures", "bench", "benchmark"}
)  # fmt: skip


def _words(name: str) -> list[str]:
    """``testImplementation`` -> [test, implementation]; ``test-db`` -> [test, db]."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def is_weak_scope(scope: str | None) -> bool:
    """True for dependency scopes that do not ship.

    The scope is read structurally, never by substring:

    * a bare scope (``dev``, ``test``, ``build``, ``plugin``, ``parent``,
      ``indirect``, ``peer``) is weak when it is one of those words or its words
      include a non-shipping word (``testImplementation``, ``androidTestApi``);
    * ``optional:<extra>`` and ``group:<name>`` (Python extras and dependency
      groups) are always weak;
    * ``<kind>:<name>`` / ``<Kind>/<name>`` (``service:web``, ``Deployment/api``,
      ``module:vpc``) is weak only if a whole word of the *name* is a
      non-shipping word: ``service:test-db`` and ``Deployment/e2e-runner`` are,
      ``service:contest``, ``Deployment/attestation``, ``service:latest`` and
      ``CronJob/protest`` are not. ``staging`` counts as shipping.
    """
    if not scope:
        return False
    s = scope.strip()
    low = s.lower()
    if low.startswith(("optional:", "group:")):
        return True
    m = re.match(r"^([A-Za-z][\w.-]*)[:/](.+)$", s)
    if m:
        return any(w in _NONPROD_SCOPE_WORDS for w in _words(m.group(2)))
    if low in _WEAK_SCOPES:
        return True
    return any(w in _NONPROD_SCOPE_WORDS for w in _words(s))


def in_dir(path: str, directory: str) -> bool:
    """``path`` is ``directory`` itself or inside it (at the root, or as a nested path
    segment: ``adapters`` contains ``src/app/adapters/s3.py``). Equality matters for
    Go, whose local import edges target the package directory itself."""
    if directory in ("", "."):
        return True
    if path == directory or path.endswith("/" + directory):
        return True
    return path.startswith(directory + "/") or f"/{directory}/" in f"/{path}"


def _str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v.strip()]
    return []


def dir_exists(directory: str, snap: Snapshot) -> bool:
    """A directory ``directory`` exists in ``snap`` (at the root or nested)."""
    return any(k == directory or k.endswith("/" + directory) for k in snap.directories())


def _dirs_ci(directory: str, snap: Snapshot) -> list[str]:
    """The spellings in ``snap`` of directories named ``directory`` ignoring case
    (as the trailing segments of an existing directory path)."""
    want = directory.lower().split("/")
    n = len(want)
    out: set[str] = set()
    for k in snap.directories():
        parts = k.split("/")
        if len(parts) >= n and [p.lower() for p in parts[-n:]] == want:
            out.add("/".join(parts[-n:]))
    return sorted(out)


def resolve_dir(raw: str, snap: Snapshot) -> str | None:
    """A repository directory named by ``raw``, or None.

    Explicit directory spellings ("adapters/", "`infra/aws/`", "./src/db") are
    taken as written. Anything else ("persistence", "internal/cloud") counts only
    if such a directory exists in the snapshot, so package names with a slash
    (``@aws-sdk/client-s3``, ``github.com/x/y``) are never mistaken for paths.

    Prose capitalises ("Payments may be imported only from billing/."): when no
    directory has the exact spelling, a directory whose name differs only in case
    is used, provided exactly one such spelling exists (L-026, D-L025-1). Two
    spellings (``Payments/`` and ``payments/``) are ambiguous: the explicit form
    is then kept as written and a bare name resolves to nothing."""
    t = raw.strip().strip("`'\"")
    explicit = t.endswith("/") or t.startswith("./")
    while t.startswith("./"):
        t = t[2:]
    t = t.strip("/")
    if not t or " " in t or ".." in t.split("/"):
        return None
    if dir_exists(t, snap):
        return t
    folded = _dirs_ci(t, snap)
    if len(folded) == 1:
        return folded[0]
    if explicit:
        return t
    return None


def module_files(name: str, snap: Snapshot) -> list[str]:
    """Local module files named ``name`` (``payments`` -> ``payments.py``,
    ``src/payments.ts``) that some local import edge actually targets, ignoring
    case (L-026, D-L025-10)."""
    low = name.lower()
    out: set[str] = set()
    for e in snap.imports:
        if e.category != "local" or not e.target:
            continue
        if posixpath.splitext(posixpath.basename(e.target))[0].lower() == low:
            out.add(e.target)
    return sorted(out)


# --------------------------------------------------------------------------- occurrences


@dataclass(frozen=True)
class _Occurrence:
    kind: EvidenceKind
    namespace: str
    names: tuple[str, ...]
    path: str
    edge: ImportEdge | None = None
    dep: DependencyRef | None = None


def _implicit_provider_dirs(snap: Snapshot) -> set[str]:
    """Directories (Terraform modules) where a ``provider "x" {}`` block certainly
    means ``hashicorp/x``: every ``required_providers`` source declared there is a
    ``hashicorp/*`` one. A non-hashicorp source could be declared under any local
    name, so its directory gets no implicit source (fail closed)."""
    dirs: set[str] = set()
    blocked: set[str] = set()
    for ref in snap.dependency_refs():
        if ref.ecosystem != "terraform-provider":
            continue
        d = posixpath.dirname(ref.manifest_path)
        if ref.scope == "provider-block":
            dirs.add(d)
        elif not ref.package.lower().startswith("hashicorp/"):
            blocked.add(d)
    return dirs - blocked


def _occurrences(snap: Snapshot) -> list[_Occurrence]:
    out: list[_Occurrence] = []
    implicit = _implicit_provider_dirs(snap)
    for ref in snap.dependency_refs():
        ns = catalog.ECOSYSTEM_NAMESPACE.get(ref.ecosystem or "")
        if ns is None:
            continue
        kind: EvidenceKind = "infra" if ref.ecosystem in INFRA_ECOSYSTEMS else "dependency"
        names: tuple[str, ...] = (ref.package,)
        if (
            ref.ecosystem == "terraform-provider"
            and ref.scope == "provider-block"
            and "/" not in ref.package
            and posixpath.dirname(ref.manifest_path) in implicit
        ):
            # provider "random" {} with no other source declared is hashicorp/random,
            # Terraform's implicit default (L-026, D-L025-3).
            names = (ref.package, f"hashicorp/{ref.package.lower()}")
        out.append(_Occurrence(kind, ns, names, ref.manifest_path, dep=ref))
    for e in snap.imports:
        if e.category not in ("external", "stdlib"):
            continue
        ns = catalog.LANGUAGE_NAMESPACE.get(e.language)
        if ns is None:
            continue
        module = e.module.lstrip(".")
        # "from mysql import connector" is mysql.connector: pass module + "." + name
        # too, so dotted catalog patterns (py:mysql.connector*, py:google.cloud*) match.
        qualified = tuple(f"{module}.{n}" for n in e.names if module and n and n != "*")
        names = tuple(dict.fromkeys(n for n in (e.package, module, *qualified) if n))
        out.append(_Occurrence("import", ns, names, e.source, edge=e))
    return out


def _snippet(snap: Snapshot, path: str, start: int, end: int) -> str | None:
    lines = snap.lines(path)
    if lines is None or start < 1 or end < start or end > len(lines):
        return None
    text = "\n".join(lines[start - 1 : end])
    return text if text.strip() else None


class EvidenceSet(BaseModel):
    """Candidate evidence for one claim at one commit."""

    claim_id: str
    commit: str
    candidates: list[Evidence] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list, description='E.g. "MongoDB -> mongodb".')
    unresolved: list[str] = Field(default_factory=list, description="Terms the rules cannot map.")
    undecidable: str | None = Field(
        default=None, description="Why the rules cannot decide this claim (-> UNKNOWN)."
    )
    fail_closed: str | None = Field(
        default=None,
        description="Set when the rules refused to guess a qualifier (communication scope, "
        "an unresolvable actor, a purpose that is not a catalog category). The resulting "
        "UNKNOWN is final: the model may not decide it either (L-026, D-L025-4).",
    )
    category: str | None = None
    searched: str = Field(default="", description="What was searched, for absence verdicts.")
    skipped: list[str] = Field(
        default_factory=list, description="Source files that were too large to read."
    )
    required_terms: dict[str, list[str]] = Field(
        default_factory=dict, description="require: each required term -> its technology ids."
    )
    notes: list[str] = Field(default_factory=list)

    def get(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.candidates if e.id == evidence_id), None)

    def with_relation(self, *relations: EvidenceRelation) -> list[Evidence]:
        return [e for e in self.candidates if e.relation in relations]


class _Collector:
    def __init__(self, claim: Claim, snap: Snapshot, max_per_relation: int) -> None:
        self.claim = claim
        self.snap = snap
        self.max = max_per_relation
        self.occ = _occurrences(snap)
        self.items: list[tuple[tuple, dict]] = []
        self.seen: set[tuple] = set()
        self.counts: dict[str, int] = {}
        self.notes: list[str] = []
        self.actor: Callable[[str], bool] | None = None
        """Only occurrences in files of the claim's actor count (None: whole repo)."""

    def add_occurrence(self, o: _Occurrence, relation: EvidenceRelation, tech: Technology) -> None:
        if o.edge is not None:
            e = o.edge
            start, end, path = e.line, max(e.end_line, e.line), e.source
            detail = f"{path}:{start} imports {e.module}"
            production = not is_test_path(path)
            dep = None
        else:
            d = o.dep
            assert d is not None
            if d.line is None:
                self.notes.append(f"{d.manifest_path}: {d.package} has no line; not citable")
                return
            start = end = d.line
            path = d.manifest_path
            ver = f" {d.version_spec}" if d.version_spec else ""
            scope = f" [{d.scope}]" if d.scope else ""
            detail = f"{path}:{start} declares {d.package}{ver}{scope}"
            production = not (
                is_weak_scope(d.scope) or is_test_path(path) or is_nonproduction_manifest(path)
            )
            dep = d
        key = (relation, o.kind, path, start, end, dep.package if dep else o.names)
        if key in self.seen:
            return
        self.seen.add(key)
        snippet = _snippet(self.snap, path, start, end)
        if snippet is None:
            self.notes.append(f"{path}:{start}-{end}: no source text; not citable")
            return
        self.counts[relation] = self.counts.get(relation, 0) + 1
        ref = Provenance(
            path=path, line_start=start, line_end=end, commit=self.snap.commit, quote=snippet
        )
        self.items.append(
            (
                (_RELATION_ORDER[relation], not production, o.kind, path, start, detail),
                {
                    "kind": o.kind,
                    "ref": ref,
                    "dependency": dep,
                    "relation": relation,
                    "technology": tech.id,
                    "production": production,
                    "detail": detail,
                },
            )
        )

    def scan(
        self,
        techs: Iterable[Technology],
        relation: EvidenceRelation,
        *,
        where=None,
        imports_only: bool = False,
    ) -> int:
        n = 0
        for tech in techs:
            for o in self.occ:
                if imports_only and o.kind != "import":
                    continue
                if where is not None and not where(o):
                    continue
                if self.actor is not None and not self.actor(o.path):
                    continue
                if catalog.name_matches(tech, o.namespace, o.names):
                    rel = relation(o) if callable(relation) else relation
                    if rel is None:
                        continue
                    self.add_occurrence(o, rel, tech)
                    n += 1
        return n

    def keywords(self, terms: list[str], limit: int) -> None:
        words = _keywords(terms)
        if not words or limit <= 0:
            return
        rx = re.compile(r"(?<![\w-])(?:" + "|".join(map(re.escape, words)) + r")(?![\w-])", re.I)
        covered = {(d["ref"].path, d["ref"].line_start) for _, d in self.items}
        found = 0
        for path in sorted(self.snap.texts):
            lines = self.snap.lines(path) or []
            for i, line in enumerate(lines, 1):
                if (path, i) in covered or not line.strip() or not rx.search(line):
                    continue
                ref = Provenance(
                    path=path, line_start=i, line_end=i, commit=self.snap.commit, quote=line
                )
                self.items.append(
                    (
                        (_RELATION_ORDER["keyword"], False, "code", path, i, ""),
                        {
                            "kind": "code",
                            "ref": ref,
                            "relation": "keyword",
                            "production": not is_test_path(path),
                            "detail": f"{path}:{i} mentions {rx.search(line).group(0)}",
                        },
                    )
                )
                found += 1
                if found >= limit:
                    return

    def build(self) -> list[Evidence]:
        ordered = sorted(self.items, key=lambda it: it[0])
        kept: list[dict] = []
        per: dict[tuple, int] = {}
        dropped = 0
        for _, d in ordered:
            # The cap is per (relation, kind, production) group, so many manifest
            # declarations can never crowd out the one decisive production import:
            # every group the verdict depends on keeps at least its first items.
            g = (d["relation"], d["kind"], d["production"], d.get("technology"))
            if d["relation"] != "keyword" and per.get(g, 0) >= self.max:
                dropped += 1
                continue
            per[g] = per.get(g, 0) + 1
            kept.append(d)
        if dropped:
            self.notes.append(f"{dropped} further evidence item(s) not listed (cap {self.max})")
        return [Evidence(id=f"e{i}", **d) for i, d in enumerate(kept, 1)]


_RELATION_ORDER: dict[str, int] = {
    "forbidden": 0,
    "outside_boundary": 0,
    "alternative": 1,
    "required": 2,
    "allowed": 2,
    "inside_boundary": 3,
    "keyword": 9,
}

_KW_STOP = frozenset(
    """the and for with from into only must not never use uses used using all any each every
    may can will shall should outside inside within through via between other another new
    service services module modules package packages library libraries layer code app
    calls call access direct directly is are be text""".split()
)


def _keywords(terms: list[str]) -> list[str]:
    out: list[str] = []
    for t in terms:
        for w in re.findall(r"[A-Za-z][\w.+-]{2,}", t):
            w = w.strip(".-+")
            if len(w) >= 3 and w.lower() not in _KW_STOP and w.lower() not in out:
                out.append(w.lower())
    return out[:12]


def _rule_terms(rule: dict) -> list[str]:
    out: list[str] = []
    for v in rule.values():
        out.extend(_str_list(v))
    return out


_ANOTHER = re.compile(r"\b(?:another|additional|other|new|second|extra|more|further)\b", re.I)


def _resolve_all(
    terms: list[str], es: EvidenceSet, *, allow_category: bool = True, quote: str = ""
) -> list[Resolution]:
    out: list[Resolution] = []
    for t in terms:
        r = catalog.resolve(t)
        if r is None:
            es.unresolved.append(t)
            continue
        if r.kind == "category" and not allow_category:
            es.unresolved.append(t)
            es.notes.append(f"{t!r} names a category, not one technology")
            continue
        if r.kind == "category" and _ANOTHER.search(quote):
            es.unresolved.append(t)
            es.notes.append(
                f"{t!r} names a category and the decision says 'another/other/new': which "
                "members are exempt is a judgement call"
            )
            continue
        es.resolved.append(f"{t} -> {r.label}")
        out.append(r)
    return out


def _techs(resolutions: Iterable[Resolution]) -> list[Technology]:
    seen: dict[str, Technology] = {}
    for r in resolutions:
        for t in r.technologies:
            seen.setdefault(t.id, t)
    return list(seen.values())


def _not_matching(techs: list[Technology]):
    """Occurrence filter: drop occurrences that match any of ``techs``, so one package
    (``ioredis``) is never both the allowed technology and an "alternative" (redis)."""

    def where(o: _Occurrence) -> bool:
        return not any(catalog.name_matches(t, o.namespace, o.names) for t in techs)

    return where


# Actors that name the whole codebase rather than a part of it.
_WHOLE_REPO_ACTORS = frozenset(
    """code codebase module modules package packages file files component components
    anyone anything nobody everyone project repository repo application app we they
    everything""".split()
)


_ACTOR_TAILS = frozenset(
    """layer layers module modules package packages code service services component
    components""".split()
)


def _actor_variants(actor: str) -> set[str]:
    """Directory / module names an actor may go by. The full name is always kept in
    every spelling (as-is, snake, kebab, joined, camel split), and the tail-stripped
    form is added ("billing_service" -> billing_service, billing-service,
    billingservice, billing; "domain layer" -> domain_layer, ..., domain), each with
    its plural/singular twin. ``resolve_actor`` takes the union of all matches."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", actor.strip())
    words = [w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w]
    words = [w for w in words if w not in ("the", "a", "an", "all", "any", "every", "each", "our")]
    if not words:
        return set()

    def forms(ws: list[str]) -> set[str]:
        return {"_".join(ws), "-".join(ws), "".join(ws)}

    out = forms(words) | {actor.strip().lower()}
    if len(words) > 1 and words[-1] in _ACTOR_TAILS:
        out |= forms(words[:-1])  # "billing service" -> billing as well
    out.add(words[-1] if words[-1] not in _ACTOR_TAILS else words[0])
    for v in list(out):
        if v.endswith("s") and len(v) > 3:
            out.add(v[:-1])
        else:
            out.add(v + "s")
    return {v for v in out if v}


_GENERIC_SUBJECTS = frozenset(
    """codebase technology chosen option communication service services microservice
    microservices system systems team teams developer developers engineer engineers""".split()
) | {"chosen option"}


def subject_actor(claim: Claim) -> list[str]:
    """The actor a claim's ``subject`` names, when it certainly names one.

    ``subject`` is descriptive ("what the claim is about"), so it is never an
    actor for boundary/only/free claims, and never when it carries a descriptive
    prefix (``module:payments``) -- only the explicit ``actor`` field scopes those.
    For rule-library forbid/require claims the subject is the sentence's subject;
    it is taken as the actor only when the sentence uses it as the acting subject
    ("Handlers must not ...", "No handler may ...") and it is not the claim's own
    target, term or category. In every other case: whole-repo scope.
    """
    if claim.origin != "rule" or claim.kind not in ("forbid", "require"):
        return []
    subj = " ".join(claim.subject.lower().split())
    if re.match(r"^[a-z]+:", subj):
        return []  # module:/package:/service:... is a label, not an actor
    bare = re.sub(r"^(?:the|all|every|each|any|our|no)\s+", "", subj)
    if (
        not bare
        or bare in _GENERIC_SUBJECTS
        or bare in _WHOLE_REPO_ACTORS
        or catalog.category_for(bare) is not None
    ):
        return []
    terms = " ".join(t.lower() for t in _rule_terms(claim.rule))
    if bare in terms or any(w in terms.split() for w in bare.split()):
        return []  # the subject is what is restricted, not who acts
    # Only when the decision sentence uses it as the acting subject; otherwise the
    # subject is just a label.
    return [bare] if _is_acting(bare, claim) else []


# Verbs that make the word before them the acting subject: modals, auxiliaries,
# adverbs of frequency and their negated contractions ("Handlers never import",
# "Handlers don't / won't / shouldn't / mustn't / cannot import"; L-026, D-L025-6).
_ACTING_VERBS = (
    r"(?:must|shall|should|may|might|can|could|will|would|are|is|do|does|need|needs|have|has"
    r"|never|cannot|always"
    r"|(?:must|should|ca|wo|do|does|did|sha|may|need|are|is|could|would)n['’]?t)"
)


def _is_acting(bare: str, claim: Claim) -> bool:
    """The decision sentence uses ``bare`` as its acting subject."""
    quote = " ".join(claim.source.quote.lower().split())
    word = re.escape(bare)
    return bool(
        re.search(
            rf"(?<![\w-]){word}s?\s+{_ACTING_VERBS}(?![\w-])"
            rf"|\bno\s+{word}s?\s+(?:may|shall|can|must|should|will)\b",
            quote,
        )
    )


# Generic subjects that may still name a part of the repository: "Services must not
# import requests" in a repository that has a services/ directory.
_AMBIGUOUS_GENERIC = frozenset({"service", "services", "microservice", "microservices"})


def ambiguous_generic_actor(claim: Claim, snap: Snapshot) -> str | None:
    """The generic subject ("services") of a rule-library forbid/require claim when
    the sentence uses it as the acting subject *and* a directory of that name
    exists. The claim then has two honest readings, whole codebase and that
    directory; the judge evaluates both and keeps a verdict only when they agree,
    UNKNOWN otherwise (L-026, D-L025-5). None in every other case."""
    if claim.origin != "rule" or claim.kind not in ("forbid", "require"):
        return None
    if _str_list(claim.rule.get("actor")):
        return None
    subj = " ".join(claim.subject.lower().split())
    bare = re.sub(r"^(?:the|all|every|each|any|our|no)\s+", "", subj)
    if bare not in _AMBIGUOUS_GENERIC or not _is_acting(bare, claim):
        return None
    names = _actor_variants(bare)
    if not any(posixpath.basename(d).lower() in names for d in snap.directories()):
        return None
    return bare


def resolve_actor(actors: list[str], snap: Snapshot) -> tuple[Callable[[str], bool] | None, str]:
    """A path filter for the claim's actor(s), and a reason when one cannot be built.

    An actor maps to the repository directories (or file stems) named like it:
    "Handlers" -> ``handlers/`` or ``handler.py``, "request handlers" ->
    ``request_handlers/``. Whole-codebase actors ("code", "modules") need no filter.
    Returns ``(None, "")`` for the whole repo, ``(None, reason)`` if unresolvable.
    """
    names: set[str] = set()
    for a in actors:
        clean = " ".join(a.lower().split())
        if clean in _WHOLE_REPO_ACTORS or clean.removeprefix("the ") in _WHOLE_REPO_ACTORS:
            return None, ""
        variants = _actor_variants(a)
        if not variants:
            return None, f"actor scope not resolvable: {a!r}"
        names |= variants
    dirs = {d for d in snap.directories() if posixpath.basename(d).lower() in names}
    stems = {
        f.path
        for f in snap.files
        if posixpath.splitext(posixpath.basename(f.path))[0].lower() in names
    }
    if not dirs and not stems:
        return None, (
            f"actor scope not resolvable: no directory or module named like "
            f"{', '.join(map(repr, actors))}"
        )

    def where(path: str) -> bool:
        return path in stems or any(path.startswith(d + "/") for d in dirs)

    return where, ""


def _scope_filter(paths: list[str]):
    def where(o: _Occurrence) -> bool:
        return any(in_dir(o.path, d) for d in paths)

    return where


# --------------------------------------------------------------------------- per kind


def _forbid(c: _Collector, es: EvidenceSet) -> None:
    rule = c.claim.rule
    res = _resolve_all(_str_list(rule.get("forbid")), es, quote=c.claim.source.quote)
    where = None
    scope_raw = _str_list(rule.get("scope"))
    if scope_raw:
        dirs = [d for d in (resolve_dir(s, c.snap) for s in scope_raw) if d]
        if not dirs:
            es.undecidable = f"scope {scope_raw} does not name a repository directory"
            return
        where = _scope_filter(dirs)
        es.notes.append(f"restricted to {', '.join(d + '/' for d in dirs)}")
    hits = c.scan(_techs(res), "forbidden", where=where)
    if not res:
        es.undecidable = f"cannot map {', '.join(map(repr, es.unresolved))} to a technology"
    elif es.unresolved and not hits:
        es.undecidable = (
            f"no evidence for the mapped terms, and {', '.join(map(repr, es.unresolved))} "
            "cannot be checked by the rules"
        )


def _purpose_not_in_catalog(es: EvidenceSet, phrase: str) -> None:
    """A 'for X' / category phrase that names no catalog category ("session storage",
    "audit logging", "service-to-service communication") narrows the claim to a
    purpose the evidence cannot show. It is never replaced by the technology's own
    (wider) category: fail closed (L-026, D-L025-7)."""
    es.undecidable = (
        f"purpose {phrase!r} is not a catalog category; which technologies serve it cannot "
        "be established from manifests and imports"
    )
    es.fail_closed = es.undecidable


def _require(c: _Collector, es: EvidenceSet) -> None:
    rule = c.claim.rule
    res = _resolve_all(_str_list(rule.get("require")), es)
    if es.unresolved or not res:
        es.undecidable = f"cannot map {', '.join(map(repr, es.unresolved))} to a technology"
        return
    raw_for = rule.get("for") if isinstance(rule.get("for"), str) else None
    cat = catalog.category_for(raw_for)
    if raw_for and raw_for.strip() and cat is None:
        _purpose_not_in_catalog(es, raw_for)
        return
    required = _techs(res)
    c.scan(required, "required")
    es.required_terms = {r.term: [t.id for t in r.technologies] for r in res}
    if cat is None and len(res) == 1 and res[0].kind == "technology":
        cat = res[0].category
    es.category = cat
    if cat is not None:
        ids = {t.id for t in required}
        c.scan(
            [t for t in catalog.members(cat) if t.id not in ids],
            "alternative",
            where=_not_matching(required),
        )


def _only(c: _Collector, es: EvidenceSet) -> None:
    rule = c.claim.rule
    if _str_list(rule.get("between")):
        # "Services communicate only via Kafka" restricts how the named participants
        # talk to each other. Manifests and imports do not show who talks to whom,
        # so another queue used for internal jobs proves nothing: fail closed.
        es.undecidable = (
            f"communication scope (between {', '.join(_str_list(rule.get('between')))}) cannot "
            "be established: the evidence does not show which participants talk to each other"
        )
        es.fail_closed = es.undecidable
        return
    res = _resolve_all(_str_list(rule.get("only")), es, allow_category=False)
    if es.unresolved or not res:
        es.undecidable = f"cannot map {', '.join(map(repr, es.unresolved))} to a technology"
        return
    raw_cat = rule.get("category") if isinstance(rule.get("category"), str) else None
    cat = catalog.category_for(raw_cat)
    if raw_cat and raw_cat.strip() and cat is None:
        _purpose_not_in_catalog(es, raw_cat)
        return
    if cat is None:
        own = {r.category for r in res if r.category}
        cat = own.pop() if len(own) == 1 else None
    if cat is None:
        es.undecidable = (
            f"category {raw_cat or rule.get('between')!r} is not in the catalog; cannot tell "
            "which other technologies it excludes"
        )
        return
    es.category = cat
    allowed = _techs(res)
    c.scan(allowed, "allowed")
    ids = {t.id for t in allowed}
    c.scan(
        [t for t in catalog.members(cat) if t.id not in ids],
        "alternative",
        where=_not_matching(allowed),
    )


def _boundary(c: _Collector, es: EvidenceSet) -> None:
    rule = c.claim.rule
    if "via" in rule and "allowed_in" not in rule:
        es.undecidable = "'go through' boundaries need the model (no deterministic rule)"
        return
    raw_dirs = _str_list(rule.get("allowed_in"))
    dirs = [d for d in (resolve_dir(s, c.snap) for s in raw_dirs) if d]
    if not dirs:
        es.undecidable = f"allowed_in {raw_dirs} does not name a repository directory"
        return
    if len(dirs) < len(raw_dirs):
        es.undecidable = f"some of allowed_in {raw_dirs} do not name a repository directory"
        return
    for d in dirs:
        if not dir_exists(d, c.snap):
            es.notes.append(f"allowed path {d}/ does not exist at this commit")

    def side(o: _Occurrence) -> EvidenceRelation:
        inside = any(in_dir(o.path, d) for d in dirs)
        return "inside_boundary" if inside else "outside_boundary"

    targets = _str_list(rule.get("target"))
    res: list[Resolution] = []
    local_dirs: list[str] = []
    module_paths: set[str] = set()
    for t in targets:
        # A repo directory only when spelled as one ("payments/") or when it exists;
        # otherwise a technology / package name such as "@aws-sdk/client-s3".
        d = resolve_dir(t, c.snap)
        if "/" in t:
            if d is not None:
                local_dirs.append(d)
                es.resolved.append(f"{t} -> directory {d}/")
            else:
                res.extend(_resolve_all([t], es))
            continue
        # A bare name ("payments"): a repo directory wins if it exists and no package
        # of that name is used; if both exist, both are evaluated.
        if d is None and len(_dirs_ci(t, c.snap)) > 1:
            es.undecidable = (
                f"target {t!r} names several directories that differ only in case "
                f"({', '.join(_dirs_ci(t, c.snap))})"
            )
            return
        r = catalog.resolve(t)
        used = r is not None and any(
            catalog.name_matches(tech, o.namespace, o.names)
            for tech in r.technologies
            for o in c.occ
        )
        if d is not None:
            local = [d]
            label = f"directory {d}/"
        else:
            # A flat layout: "payments" is payments.py (a module file that local
            # imports target), not a directory (L-026, D-L025-10).
            local = module_files(t, c.snap)
            module_paths.update(local)
            label = "module file(s) " + ", ".join(local)
        if local and (r is None or (r.kind == "literal" and not used)):
            local_dirs.extend(local)
            es.resolved.append(f"{t} -> {label}")
        elif local:
            local_dirs.extend(local)
            es.resolved.append(f"{t} -> {label} and {r.label}")
            res.extend(_resolve_all([t], es))
        else:
            res.extend(_resolve_all([t], es))
    if es.unresolved or not (res or local_dirs):
        es.undecidable = f"cannot map {', '.join(map(repr, es.unresolved))} to a technology"
        return
    c.scan(_techs(res), side, imports_only=True)
    for d in local_dirs:
        for e in c.snap.imports:
            if e.category != "local" or not e.target or not in_dir(e.target, d):
                continue
            if in_dir(e.source, d):
                continue  # a module importing its own package
            if c.actor is not None and not c.actor(e.source):
                continue
            o = _Occurrence("import", "local", (e.target,), e.source, edge=e)
            tid = d if d in module_paths else f"{d}/"
            c.add_occurrence(o, side(o), Technology(id=tid, category=None))


_KINDS = {"forbid": _forbid, "require": _require, "only": _only, "boundary": _boundary}


def collect_evidence(
    claim: Claim,
    snap: Snapshot,
    *,
    max_per_relation: int = DEFAULT_MAX_PER_RELATION,
    max_keywords: int | None = None,
) -> EvidenceSet:
    """Candidate evidence for ``claim`` in ``snap``. Deterministic; ids are ``e1..eN``
    in a stable order (violations first, then alternatives, support, keywords).

    ``max_keywords`` keyword (``code``) candidates are added for the model; ``None``
    means 10 when the rules cannot decide the claim and 0 otherwise.
    """
    es = EvidenceSet(claim_id=claim.id, commit=snap.commit)
    c = _Collector(claim, snap, max_per_relation)
    handler = _KINDS.get(claim.kind)
    actors = _str_list(claim.rule.get("actor")) or subject_actor(claim)
    if handler is None:
        es.undecidable = "free-form claim: no deterministic rule"
    else:
        if actors:
            c.actor, why = resolve_actor(actors, snap)
            if why:
                es.undecidable = es.fail_closed = why
            elif c.actor is not None:
                es.notes.append(f"restricted to the code of {', '.join(actors)}")
        if not es.undecidable:
            handler(c, es)
    n_manifests = sum(1 for _ in snap.manifests)
    es.searched = (
        f"{n_manifests} manifest(s), {len(snap.imports)} import edge(s) in "
        f"{len(snap.files)} file(s) at {snap.commit[:12]}"
    )
    limit = max_keywords
    if limit is None:
        limit = DEFAULT_MAX_KEYWORDS if es.undecidable else 0
    if limit:
        c.keywords(_rule_terms(claim.rule), limit)
    es.candidates = c.build()
    es.notes.extend(c.notes)
    if snap.skipped and claim.kind != "free":
        shown = "; ".join(f"{p} ({why})" for p, why in snap.skipped[:5])
        more = f" (+{len(snap.skipped) - 5} more)" if len(snap.skipped) > 5 else ""
        es.skipped = [p for p, _ in snap.skipped]
        es.notes.append(f"incomplete evidence: {len(snap.skipped)} file(s) skipped: {shown}{more}")
    return es
