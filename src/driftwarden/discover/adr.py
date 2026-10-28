"""Find and parse Architecture Decision Records.

Supported formats:

* **Nygard**: ``# 1. Title`` with ``## Status``, ``## Context``, ``## Decision``
  and ``## Consequences`` sections.
* **MADR**: H1 title, status from YAML front-matter or ``* Status:`` lines,
  ``## Context and Problem Statement``, ``## Decision Outcome``
  (``Chosen option: ...``) and ``## Consequences``.
* **Free-form**: anything else; the H1 is the title and the body is the decision.

Every Decision carries G1 provenance: the exact 1-based line range of the
decision section and its verbatim text, taken from HEAD via ``git show`` (so it
is reproducible), or from the working tree with commit ``WORKTREE`` when the
file is untracked or modified.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from driftwarden import git
from driftwarden.config import Config
from driftwarden.models import WORKTREE, AdrFormat, Decision, Provenance, Status
from driftwarden.text import split_lines

ADR_DIRS = (
    "docs/adr",
    "docs/adrs",
    "doc/adr",
    "adr",
    "adrs",
    "docs/decisions",
    "docs/architecture/decisions",
    "doc/architecture/decisions",
    "architecture/decisions",
    "docs/architecture-decisions",
)
ADR_SUFFIXES = (".md", ".markdown")
SKIP_NAMES = {"readme", "index", "_index", "template", "adr-template"}

MADR_SECTIONS = {
    "context and problem statement",
    "decision outcome",
    "considered options",
    "decision drivers",
    "pros and cons of the options",
}
CONSEQUENCE_SUBHEADINGS = {
    "consequences",
    "positive consequences",
    "negative consequences",
    "confirmation",
}

# --------------------------------------------------------------------------- discovery


def is_skipped_name(name: str) -> bool:
    """README/index/template files are not decisions."""
    stem = Path(name).stem.lower()
    if stem in SKIP_NAMES:
        return True
    if stem.endswith(("-template", "_template")):
        return True
    return stem.startswith("0000") and "template" in stem


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def _adr_dir_file(root: Path) -> list[str]:
    marker = root / ".adr-dir"
    if not marker.is_file():
        return []
    value = marker.read_text(encoding="utf-8", errors="replace").strip()
    return [value] if value else []


def discover_adr_files(root: str | Path, config: Config | None = None) -> list[str]:
    """Repo-relative POSIX paths of ADR files under ``root``, sorted."""
    root = Path(root).resolve()
    cfg = config or Config()
    candidates: list[str] = [*ADR_DIRS, *_adr_dir_file(root), *cfg.adr_paths]

    found: set[str] = set()
    for entry in candidates:
        targets = sorted(root.glob(entry)) if any(c in entry for c in "*?[") else [root / entry]
        for target in targets:
            if target.is_file():
                files = [target] if target.suffix.lower() in ADR_SUFFIXES else []
            elif target.is_dir():
                files = [p for p in target.rglob("*") if p.suffix.lower() in ADR_SUFFIXES]
            else:
                continue
            for f in files:
                if not f.is_file():
                    continue
                try:
                    rel = f.resolve().relative_to(root).as_posix()
                except ValueError:  # symlink or config path pointing outside the repo
                    continue
                if is_skipped_name(f.name) or _excluded(rel, cfg.exclude):
                    continue
                found.add(rel)
    return sorted(found)


# --------------------------------------------------------------------------- parsing

_H1 = re.compile(r"^#\s+(.+?)\s*#*\s*$")
_H2 = re.compile(r"^##\s+(.+?)\s*#*\s*$")
_H3 = re.compile(r"^###\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_META = re.compile(r"^\s*(?:[*+-]\s+)?\**([A-Za-z][A-Za-z ]*?)\**\s*:\s*\**\s*(.+?)\s*$")
_TITLE_NUM = re.compile(
    r"^(?:ADR[-_ ]?(\d+)\s*[.:\-–—)]?\s*|(\d+)\s*[.:\-–—)]\s*)(.+)$",
    re.IGNORECASE,
)
_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_SUPERSEDED_BY = re.compile(
    r"superseded\s+by\s*:?\s*(?:\[([^\]]+)\]\([^)]*\)|\[([^\]]+)\]|([^\s,;.]+(?:[ -]\d+)?))",
    re.IGNORECASE,
)
_CHOSEN = re.compile(r"chosen\s+option\s*:\s*(.+)", re.IGNORECASE)


@dataclass
class _Section:
    name: str  # normalised heading text
    heading_idx: int  # 0-based index of the heading line
    end_idx: int  # 0-based exclusive end of the section


@dataclass
class _Doc:
    lines: list[str]
    body_start: int  # first line after front-matter
    front_matter: dict[str, str] = field(default_factory=dict)
    h1_idx: int | None = None
    sections: list[_Section] = field(default_factory=list)
    code_lines: set[int] = field(default_factory=set)

    def section(self, *names: str) -> _Section | None:
        for name in names:
            for s in self.sections:
                if s.name == name:
                    return s
        return None


def _norm_heading(text: str) -> str:
    text = re.sub(r"^\d+(\.\d+)*[.)]?\s+", "", text.strip())
    return text.strip().rstrip(":").strip().strip("*_").lower()


def _parse_front_matter(lines: list[str]) -> tuple[dict[str, str], int]:
    if not lines or lines[0].strip() != "---":
        return {}, 0
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            fm: dict[str, str] = {}
            for raw in lines[1:i]:
                m = re.match(r"^([A-Za-z][\w-]*)\s*:\s*(.*)$", raw)
                if m:
                    fm[m.group(1).lower()] = m.group(2).strip().strip("\"'")
            return fm, i + 1
    return {}, 0  # unterminated: treat as body


def _structure(text: str) -> _Doc:
    lines = split_lines(text)
    fm, body_start = _parse_front_matter(lines)
    doc = _Doc(lines=lines, body_start=body_start, front_matter=fm)
    in_fence = False
    current: _Section | None = None
    for i in range(body_start, len(lines)):
        line = lines[i]
        if _FENCE.match(line):
            in_fence = not in_fence
            doc.code_lines.add(i)
            continue
        if in_fence:
            doc.code_lines.add(i)
            continue
        if doc.h1_idx is None and _H1.match(line):
            doc.h1_idx = i
            continue
        m = _H2.match(line)
        if m:
            if current:
                current.end_idx = i
            current = _Section(_norm_heading(m.group(1)), i, len(lines))
            doc.sections.append(current)
    return doc


def _trim(lines: list[str], start: int, end: int) -> tuple[int, int]:
    """Trim blank lines from [start, end); returns the new (start, end)."""
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return start, end


def _body_range(doc: _Doc, sec: _Section) -> tuple[int, int]:
    return _trim(doc.lines, sec.heading_idx + 1, sec.end_idx)


def _text(doc: _Doc, start: int, end: int) -> str:
    return "\n".join(doc.lines[start:end])


def _section_text(doc: _Doc, sec: _Section | None) -> str | None:
    if sec is None:
        return None
    s, e = _body_range(doc, sec)
    return _text(doc, s, e) or None


def _preamble_meta(doc: _Doc) -> dict[str, str]:
    """``Key: value`` lines between the H1 and the first H2 (adr-tools, MADR 2)."""
    start = (doc.h1_idx + 1) if doc.h1_idx is not None else doc.body_start
    end = doc.sections[0].heading_idx if doc.sections else len(doc.lines)
    meta: dict[str, str] = {}
    for i in range(start, end):
        if i in doc.code_lines:
            continue
        m = _META.match(doc.lines[i])
        if m:
            meta.setdefault(m.group(1).strip().lower(), m.group(2).strip())
    return meta


def normalise_status(raw: str | None) -> tuple[Status, str | None]:
    """Map free-text status to a lifecycle state, plus the superseding ADR if any.

    Precedence follows the lifecycle, so "Accepted, later superseded by ADR-5"
    is ``superseded``. "Supersedes ADR-2" does not make a decision superseded.
    """
    if not raw:
        return "unknown", None
    text = raw.replace("*", "").replace("_", " ").lower()
    superseded_by = None
    m = _SUPERSEDED_BY.search(raw)
    if m:
        superseded_by = next(g for g in m.groups() if g).strip()
    if re.search(r"\bsuperseded\b", text):
        return "superseded", superseded_by
    if re.search(r"\b(deprecated|obsolete|retired)\b", text):
        return "deprecated", None
    if re.search(r"\b(rejected|declined|abandoned)\b", text):
        return "rejected", None
    if re.search(r"\b(accepted|approved|adopted|agreed|decided|done|active)\b", text):
        return "accepted", None
    if re.search(r"\b(proposed|proposal|draft|pending|open|rfc|in review|under review)\b", text):
        return "proposed", None
    return "unknown", None


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    m = _DATE.search(value)
    if not m:
        return None
    try:
        return date.fromisoformat(m.group(1))
    except ValueError:
        return None


def _id_and_title(path: str, h1: str | None) -> tuple[str, str]:
    stem = Path(path).stem
    num: str | None = None
    m = re.match(r"^(?:adr[-_]?)?(\d+)", stem, re.IGNORECASE)
    if m:
        num = m.group(1)
    title = h1
    if h1:
        tm = _TITLE_NUM.match(h1)
        if tm:
            num = num or tm.group(1) or tm.group(2)
            title = tm.group(3).strip()
    if not title:
        title = re.sub(r"^\d+[-_]", "", stem).replace("-", " ").replace("_", " ").strip() or stem
    adr_id = f"ADR-{int(num):04d}" if num is not None else stem
    return adr_id, title


def _decision_range_madr(doc: _Doc, sec: _Section) -> tuple[tuple[int, int], str | None]:
    """Decision Outcome, cut before a ``### Consequences``-type subsection.

    Returns the decision range and the text of the consequences subsection.
    """
    s, e = sec.heading_idx + 1, sec.end_idx
    cut = e
    for i in range(s, e):
        if i in doc.code_lines:
            continue
        m = _H3.match(doc.lines[i])
        if m and _norm_heading(m.group(1)) in CONSEQUENCE_SUBHEADINGS:
            cut = i
            break
    conseq = None
    if cut < e:
        cs, ce = _trim(doc.lines, cut, e)
        conseq = _text(doc, cs, ce) or None
    return _trim(doc.lines, s, cut), conseq


def parse_adr(text: str, path: str, commit: str) -> Decision:
    """Parse one ADR's text. Never raises on odd content; falls back to free-form."""
    doc = _structure(text)
    h1 = doc.lines[doc.h1_idx] if doc.h1_idx is not None else None
    h1_text = _H1.match(h1).group(1) if h1 else None
    adr_id, title = _id_and_title(path, h1_text)
    meta = _preamble_meta(doc)
    names = {s.name for s in doc.sections}

    fmt: AdrFormat
    status_raw: str | None = None
    date_raw: str | None = None
    context = consequences = chosen = None
    rng: tuple[int, int] | None = None

    looks_madr = bool(doc.front_matter) or bool(names & MADR_SECTIONS)
    outcome = doc.section("decision outcome")
    decision_sec = doc.section("decision", "decisions")

    if looks_madr and (outcome or decision_sec):
        fmt = "madr"
        sec = outcome or decision_sec
        assert sec is not None
        rng, sub_conseq = _decision_range_madr(doc, sec)
        status_raw = (
            doc.front_matter.get("status")
            or meta.get("status")
            or _section_text(doc, doc.section("status"))
        )
        date_raw = doc.front_matter.get("date") or meta.get("date")
        context = _section_text(doc, doc.section("context and problem statement", "context"))
        consequences = _section_text(doc, doc.section("consequences")) or sub_conseq
    elif decision_sec is not None:
        fmt = "nygard"
        rng = _body_range(doc, decision_sec)
        status_raw = _section_text(doc, doc.section("status")) or meta.get("status")
        date_raw = meta.get("date") or doc.front_matter.get("date")
        context = _section_text(doc, doc.section("context"))
        consequences = _section_text(doc, doc.section("consequences"))
    else:
        fmt = "freeform"

    if rng is None or rng[0] >= rng[1]:
        # Free-form, or a structured ADR whose decision section is empty.
        fmt = "freeform"
        start = (doc.h1_idx + 1) if doc.h1_idx is not None else doc.body_start
        rng = _trim(doc.lines, start, len(doc.lines))
        if rng[0] >= rng[1] and doc.h1_idx is not None:
            rng = (doc.h1_idx, doc.h1_idx + 1)  # title-only file: quote the title
        status_raw = (
            status_raw
            or doc.front_matter.get("status")
            or meta.get("status")
            or _section_text(doc, doc.section("status"))
        )
        date_raw = date_raw or doc.front_matter.get("date") or meta.get("date")

    decision_text = _text(doc, rng[0], rng[1])
    if fmt == "madr":
        m = _CHOSEN.search(decision_text)
        if m:
            chosen = re.split(r",\s*because\b", m.group(1), maxsplit=1)[0].strip().strip("\"'")

    status, superseded_by = normalise_status(status_raw)
    if status == "superseded" and superseded_by is None:
        superseded_by = meta.get("superseded by") or doc.front_matter.get("superseded-by")

    return Decision(
        id=adr_id,
        title=title,
        status=status,
        date=_parse_date(date_raw),
        context=context,
        decision_text=decision_text,
        consequences=consequences,
        format=fmt,
        superseded_by=superseded_by,
        chosen_option=chosen,
        source=Provenance(
            path=path,
            line_start=rng[0] + 1 if decision_text else 1,
            line_end=rng[1] if decision_text else 1,
            commit=commit,
            quote=decision_text,
        ),
    )


# --------------------------------------------------------------------------- repo-level


@dataclass
class AdrScan:
    root: Path
    head: str | None
    decisions: list[Decision]
    errors: list[tuple[str, str]]  # (path, message)
    # ADR files that hold no decision text at all (0 bytes or whitespace only).
    # They are listed, not parsed: there is nothing to quote, so nothing to verify.
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, note)


EMPTY_NOTE = "empty file, no decision to verify"


def read_source(root: Path, head: str | None, rel: str) -> tuple[str, str]:
    """Return (text, commit): from HEAD when tracked and clean, else the working tree."""
    if head is not None and git.is_tracked_and_clean(root, rel):
        return git.show_file(root, head, rel), head
    return (root / rel).read_text(encoding="utf-8", errors="replace"), WORKTREE


def scan_adrs(path: str | Path, config: Config | None = None) -> AdrScan:
    """Discover and parse every ADR in the repository containing ``path``."""
    root = git.repo_root(path)
    try:
        head: str | None = git.head_sha(root)
    except git.NotAGitRepoError:
        raise
    except git.GitError:
        head = None  # repository with no commits yet: everything is WORKTREE
    decisions: list[Decision] = []
    errors: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    for rel in discover_adr_files(root, config):
        try:
            text, commit = read_source(root, head, rel)
            # D-003: str.strip() keeps U+FEFF, so a BOM-only file looked non-empty.
            # Emptiness check only; real ADR text (and its offsets) is untouched.
            if not text.replace("﻿", "").strip():
                skipped.append((rel, EMPTY_NOTE))
                continue
            dec = parse_adr(text, rel, commit)
        except (OSError, git.GitError, ValueError) as exc:
            errors.append((rel, str(exc)))
            continue
        n = seen.get(dec.id, 0) + 1
        seen[dec.id] = n
        if n > 1:
            dec = dec.model_copy(update={"id": f"{dec.id}~{n}"})
        decisions.append(dec)
    return AdrScan(root=root, head=head, decisions=decisions, errors=errors, skipped=skipped)


def _matches_entry(path: str, entry: str) -> bool:
    """``path`` is the ADR location ``entry`` names: the file itself, a file under that
    directory, or (for a glob) a file or directory matching it."""
    e = entry.strip().strip("/")
    while e.startswith("./"):
        e = e[2:]
    if not e:
        return False
    if any(c in e for c in "*?["):
        parts = path.split("/")
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        return any(fnmatch.fnmatchcase(p, e) for p in prefixes)
    return path == e or path.startswith(e + "/")


def discover_adr_files_at(root: str | Path, commit: str, config: Config | None = None) -> list[str]:
    """Like ``discover_adr_files``, but over the files tracked at ``commit`` (the
    ``.adr-dir`` marker is read at that commit too). Sorted repo-relative paths."""
    root = git.repo_root(root)
    cfg = config or Config()
    candidates: list[str] = [*ADR_DIRS, *cfg.adr_paths]
    try:
        marker = git.show_file(root, commit, ".adr-dir").strip()
    except git.NotAGitRepoError:
        raise
    except git.GitError:
        marker = ""
    if marker:
        candidates.append(marker)
    found: list[str] = []
    for rel in git.ls_tree(root, commit):
        name = rel.rsplit("/", 1)[-1]
        if not name.lower().endswith(ADR_SUFFIXES) or is_skipped_name(name):
            continue
        if _excluded(rel, cfg.exclude):
            continue
        if any(_matches_entry(rel, c) for c in candidates):
            found.append(rel)
    return sorted(found)


def scan_adrs_at(path: str | Path, commit: str, config: Config | None = None) -> AdrScan:
    """Discover and parse every ADR as it is at ``commit`` (resolved to a full SHA):
    every Decision's provenance names that commit. The working tree is never read."""
    root = git.repo_root(path)
    sha = git.resolve_commit(root, commit)
    decisions: list[Decision] = []
    errors: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    for rel in discover_adr_files_at(root, sha, config):
        try:
            text = git.show_file(root, sha, rel)
            if not text.replace("﻿", "").strip():
                skipped.append((rel, EMPTY_NOTE))
                continue
            dec = parse_adr(text, rel, sha)
        except (OSError, git.GitError, ValueError) as exc:
            errors.append((rel, str(exc)))
            continue
        n = seen.get(dec.id, 0) + 1
        seen[dec.id] = n
        if n > 1:
            dec = dec.model_copy(update={"id": f"{dec.id}~{n}"})
        decisions.append(dec)
    return AdrScan(root=root, head=sha, decisions=decisions, errors=errors, skipped=skipped)
