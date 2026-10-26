"""File walk, language detection and ignore rules.

The walk answers "which files make up this repository?" the way git does:

* Inside a git work tree it asks ``git ls-files -z --cached --others
  --exclude-standard``: tracked files plus untracked files that ``.gitignore``,
  ``.git/info/exclude`` and the global excludes file do not ignore. Tracked
  files are listed even if a later ``.gitignore`` matches them (git semantics).
  Tracked files deleted from the work tree are dropped, and submodules
  (gitlinks) are skipped.
* Outside git it walks the directory itself and applies every ``.gitignore`` it
  finds with :class:`GitIgnore`, a stdlib implementation of the gitignore
  pattern rules (negation, anchoring, ``**``, directory-only patterns).

Either way, the configured ``exclude`` globs (``Config.exclude``) are applied on
top, and ``.git/`` is never listed.

**Symlinks** are listed (``is_symlink=True``, with ``link_target``) but never
followed or read: the file they point to is indexed under its own path if it is
part of the repository, and a link that points outside the repository must not
pull outside content into the index. Directory symlinks are not descended into,
which also rules out cycles.

**Binary files** are detected by a NUL byte in the first 8 KiB (the heuristic git
itself uses) or by a well-known binary extension. They are listed with
``language=None`` and are never parsed.

Paths are repo-relative POSIX strings. Names that are not valid UTF-8 are kept
round-trippable with ``os.fsdecode`` (surrogate escapes) rather than mangled.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import subprocess
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from driftwarden import git
from driftwarden.config import DEFAULT_EXCLUDES

SNIFF_BYTES = 8192
"""How much of a file is read to decide whether it is binary."""

MAX_PARSE_BYTES = 2 * 1024 * 1024
"""Files larger than this are listed but not parsed for imports (generated/minified)."""

# --------------------------------------------------------------------------- languages

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".gradle": "groovy",
    ".cs": "csharp",
    ".csproj": "xml",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".hcl": "hcl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".markdown": "markdown",
    ".rst": "rst",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".vue": "vue",
    ".svelte": "svelte",
    ".proto": "protobuf",
}

FILENAME_LANGUAGES: dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "make",
    "gnumakefile": "make",
    "jenkinsfile": "groovy",
    "go.mod": "go-mod",
    "go.sum": "go-sum",
    "pom.xml": "maven",
    "package.json": "json",
}

SHEBANG_LANGUAGES: dict[str, str] = {
    "python": "python",
    "python3": "python",
    "python2": "python",
    "node": "javascript",
    "deno": "typescript",
    "ts-node": "typescript",
    "sh": "shell",
    "bash": "shell",
    "zsh": "shell",
    "dash": "shell",
}

BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff",
        ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
        ".class", ".so", ".dll", ".dylib", ".exe", ".o", ".a", ".lib", ".pyc", ".pyo",
        ".whl", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov",
        ".avi", ".wav", ".flac", ".ogg", ".webm", ".sqlite", ".db", ".bin", ".dat",
    }
)  # fmt: skip

_SHEBANG_RE = re.compile(rb"^#!\s*(\S+)(?:\s+(\S+))?")


def detect_language(rel_path: str, head: bytes | None = None) -> str | None:
    """Language of a file from its name, falling back to a shebang line in ``head``.

    Returns ``None`` when the language is not known. ``Dockerfile.prod`` and
    ``api.Dockerfile`` are recognised as Dockerfiles.
    """
    name = rel_path.rsplit("/", 1)[-1]
    lower = name.lower()
    if lower in FILENAME_LANGUAGES:
        return FILENAME_LANGUAGES[lower]
    if lower.startswith(("dockerfile.", "containerfile.")) or lower.endswith(".dockerfile"):
        return "dockerfile"
    if lower.endswith(".d.ts"):
        return "typescript"
    dot = lower.rfind(".")
    if dot > 0:
        lang = EXTENSION_LANGUAGES.get(lower[dot:])
        if lang is not None:
            return lang
    if head and dot <= 0:
        m = _SHEBANG_RE.match(head)
        if m:
            prog = os.fsdecode(m.group(1).rsplit(b"/", 1)[-1])
            if prog == "env" and m.group(2):
                prog = os.fsdecode(m.group(2))
            # "python3.12" -> "python3.12" miss -> "python" hit
            return SHEBANG_LANGUAGES.get(prog) or SHEBANG_LANGUAGES.get(prog.rstrip("0123456789."))
    return None


def is_binary(head: bytes, rel_path: str = "") -> bool:
    """True if the content looks binary (NUL byte in the sniffed head) or the
    extension is a known binary format."""
    dot = rel_path.rfind(".")
    if dot >= 0 and rel_path[dot:].lower() in BINARY_EXTENSIONS:
        return True
    return b"\x00" in head[:SNIFF_BYTES]


# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One file of the repository."""

    path: str
    """Repo-relative POSIX path."""
    size: int
    language: str | None
    is_binary: bool = False
    is_symlink: bool = False
    link_target: str | None = None
    """The raw symlink target (as stored in the link), when ``is_symlink``."""
    tracked: bool | None = None
    """True/False in a git repo (tracked by git or untracked-but-not-ignored); None outside git."""

    @property
    def parseable(self) -> bool:
        """True if import extraction may read this file."""
        return (
            not self.is_binary
            and not self.is_symlink
            and self.language is not None
            and self.size <= MAX_PARSE_BYTES
        )


@dataclass
class FileIndex:
    """The result of :func:`index_files`."""

    root: Path
    files: list[FileEntry]
    source: str
    """``"git"`` (git ls-files) or ``"walk"`` (filesystem walk with .gitignore rules)."""
    skipped: list[tuple[str, str]] = field(default_factory=list)
    """``(path, reason)`` for entries that were listed but could not be indexed."""

    def __post_init__(self) -> None:
        self._by_path = {f.path: f for f in self.files}

    def __len__(self) -> int:
        return len(self.files)

    def __iter__(self) -> Iterator[FileEntry]:
        return iter(self.files)

    def __contains__(self, path: object) -> bool:
        return path in self._by_path

    def get(self, path: str) -> FileEntry | None:
        return self._by_path.get(path)

    def by_language(self, language: str) -> list[FileEntry]:
        return [f for f in self.files if f.language == language]

    def languages(self) -> dict[str, int]:
        """File count per detected language, most common first (binary/unknown excluded)."""
        counts = Counter(f.language for f in self.files if f.language and not f.is_binary)
        return dict(counts.most_common())


# --------------------------------------------------------------------------- gitignore


@dataclass(frozen=True)
class _Rule:
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


def _translate(pattern: str) -> str:
    """Translate one gitignore glob (already stripped of ``!``, leading and trailing
    ``/``) to a regex body matching a POSIX path relative to the .gitignore's dir."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                at_start = i == 0 or pattern[i - 1] == "/"
                j = i + 2
                at_end = j == n or pattern[j] == "/"
                if at_start and at_end:
                    if j == n:  # trailing "/**" or bare "**": everything below
                        out.append(".*")
                    else:  # "**/": zero or more directories
                        out.append("(?:.*/)?")
                        j += 1
                    i = j
                    continue
                out.append("[^/]*")  # "**" not delimited by slashes acts like "*"
                i = j
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j]
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        elif c == "\\" and i + 1 < n:
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class GitIgnore:
    """Rules from one ``.gitignore`` file, rooted at ``base`` (repo-relative, "" for root).

    Implements the gitignore(5) rules: blank lines and ``#`` comments are ignored,
    ``!`` negates, a trailing ``/`` matches directories only, a pattern with a ``/``
    in the beginning or middle is anchored to the .gitignore's directory, otherwise it
    matches at any depth, and ``**`` spans directories.
    """

    def __init__(self, lines: Iterable[str], base: str = "") -> None:
        self.base = base.strip("/")
        self.rules: list[_Rule] = []
        for raw in lines:
            line = raw.rstrip("\n").rstrip("\r")
            # Trailing spaces are ignored unless escaped.
            while line.endswith(" ") and not line.endswith("\\ "):
                line = line[:-1]
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            if negate:
                line = line[1:]
            elif line.startswith("\\!") or line.startswith("\\#"):
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            line = line.lstrip("/")
            body = _translate(line)
            prefix = "" if anchored else "(?:.*/)?"
            self.rules.append(_Rule(re.compile(f"^{prefix}{body}$", re.S), negate, dir_only))

    @classmethod
    def from_file(cls, path: Path, base: str = "") -> GitIgnore:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        return cls(text.splitlines(), base)

    def match(self, rel: str, is_dir: bool) -> bool | None:
        """``True`` ignored, ``False`` re-included by a negation, ``None`` no rule applies.

        ``rel`` is relative to the repository root.
        """
        if self.base:
            if not rel.startswith(self.base + "/"):
                return None
            rel = rel[len(self.base) + 1 :]
        result: bool | None = None
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(rel):
                result = not rule.negate
        return result


def _ignored(rel: str, is_dir: bool, stack: list[GitIgnore]) -> bool:
    # Deeper .gitignore files take precedence; within one file, the last match wins.
    for gi in reversed(stack):
        m = gi.match(rel, is_dir)
        if m is not None:
            return m
    return False


# --------------------------------------------------------------------------- walking


ALWAYS_SKIP_DIRS = frozenset({".git", ".driftwarden"})
"""Directory names never indexed, at any depth: git internals and DriftWarden's own output."""

_DIR_PATTERN = re.compile(r"^([^/*?\[\]]+)/\*\*$")


class _Excludes:
    """``Config.exclude`` globs (fnmatch on repo-relative paths).

    A pattern of the form ``name/**`` (one literal directory name) matches that
    directory at any depth, so ``node_modules/**`` also excludes
    ``packages/x/node_modules/...``. Other patterns match the whole path as written.
    """

    def __init__(self, patterns: list[str]) -> None:
        self.dir_names = set(ALWAYS_SKIP_DIRS)
        self.globs: list[str] = []
        for pat in patterns:
            m = _DIR_PATTERN.match(pat)
            if m:
                self.dir_names.add(m.group(1))
            else:  # a leading "/" anchors to the root, which fnmatch on rel paths does anyway
                self.globs.append(pat.lstrip("/"))

    def dir_excluded(self, name: str) -> bool:
        return name in self.dir_names

    def __call__(self, rel: str) -> bool:
        parts = rel.split("/")
        if any(p in self.dir_names for p in parts[:-1]) or parts[-1] in ALWAYS_SKIP_DIRS:
            return True
        return any(fnmatch.fnmatchcase(rel, pat) for pat in self.globs)


def _git_listing(root: Path, untracked: bool) -> tuple[list[str], set[str]] | None:
    """(all paths, tracked paths) from git, or None if ``root`` is not a git work tree."""
    if not git.is_repo(root):
        return None

    def ls(*extra: str) -> list[str]:
        proc = subprocess.run(
            ["git", "-c", "core.quotePath=false", "ls-files", "-z", *extra, "--", "."],
            cwd=str(root),
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise git.GitError(proc.stderr.decode("utf-8", "replace").strip())
        return [os.fsdecode(p) for p in proc.stdout.split(b"\0") if p]

    # ``git ls-files`` run from a subdirectory prints paths relative to that directory,
    # so the listing is always relative to ``root`` even when root is not the top level.
    tracked = ls("--cached")
    paths = list(dict.fromkeys(tracked))  # de-duplicate (unmerged entries repeat)
    tracked_set = set(paths)
    if untracked:
        for p in ls("--others", "--exclude-standard"):
            if p not in tracked_set:
                paths.append(p)
    return paths, tracked_set


def _walk_listing(root: Path, excludes: _Excludes) -> list[str]:
    """Filesystem walk applying nested .gitignore files. Does not follow symlinks, and
    does not descend into excluded directories (``node_modules`` etc.)."""
    out: list[str] = []
    stacks: dict[str, list[GitIgnore]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        parent = rel_dir.rsplit("/", 1)[0] if "/" in rel_dir else ""
        stack = list(stacks.get(parent, [])) if rel_dir else []
        if ".gitignore" in filenames:
            stack.append(GitIgnore.from_file(Path(dirpath) / ".gitignore", rel_dir))
        stacks[rel_dir] = stack

        keep_dirs = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            full = Path(dirpath) / d
            if excludes.dir_excluded(d):
                continue
            if full.is_symlink():
                # Listed as a file entry (a link), never descended into.
                if not _ignored(rel, False, stack):
                    out.append(rel)
                continue
            if _ignored(rel, True, stack):
                continue
            keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for f in sorted(filenames):
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if not _ignored(rel, False, stack):
                out.append(rel)
    return out


def _entry(root: Path, rel: str, tracked: bool | None) -> FileEntry | None:
    full = root / rel
    try:
        st = full.lstat()
    except OSError:
        return None  # deleted from the work tree, or unreadable
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(full)
        except OSError:
            target = None
        return FileEntry(
            path=rel,
            size=st.st_size,
            language=detect_language(rel),
            is_symlink=True,
            link_target=target,
            tracked=tracked,
        )
    if stat.S_ISDIR(st.st_mode):
        return None  # a submodule (gitlink) or nested repository
    if not stat.S_ISREG(st.st_mode):
        return None  # fifo, socket, device
    head = b""
    if st.st_size:
        try:
            with open(full, "rb") as fh:
                head = fh.read(SNIFF_BYTES)
        except OSError:
            return None
    binary = is_binary(head, rel)
    return FileEntry(
        path=rel,
        size=st.st_size,
        language=None if binary else detect_language(rel, head),
        is_binary=binary,
        tracked=tracked,
    )


def index_files(
    root: str | Path,
    exclude: list[str] | None = None,
    *,
    untracked: bool = True,
    use_git: bool = True,
) -> FileIndex:
    """List and classify the files of the repository at ``root``.

    ``exclude`` are fnmatch globs on repo-relative paths (defaults to
    ``config.DEFAULT_EXCLUDES``); ``name/**`` patterns match that directory at any
    depth. ``.git`` and ``.driftwarden`` directories are always skipped, at any depth.
    ``untracked=False`` lists only files git tracks. ``use_git=False`` forces the
    filesystem walk even inside a git work tree.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    excludes = _Excludes(list(DEFAULT_EXCLUDES if exclude is None else exclude))

    listing = _git_listing(root, untracked) if use_git else None
    if listing is not None:
        paths, tracked = listing
        source = "git"
    else:
        paths, tracked = _walk_listing(root, excludes), None
        source = "walk"

    files: list[FileEntry] = []
    skipped: list[tuple[str, str]] = []
    for rel in paths:
        if excludes(rel):
            continue
        entry = _entry(root, rel, None if tracked is None else rel in tracked)
        if entry is None:
            if (root / rel).is_dir():
                skipped.append((rel, "directory (submodule or nested repository)"))
            elif not os.path.lexists(root / rel):
                skipped.append((rel, "listed by git but missing from the work tree"))
            else:
                skipped.append((rel, "not a regular file or unreadable"))
            continue
        files.append(entry)
    files.sort(key=lambda f: f.path)
    return FileIndex(root=root, files=files, source=source, skipped=skipped)
