"""Deterministic git repo builder that records ground truth while it builds.

Truth rows are declared next to the files they describe. File:line and commit values
are never typed in: a row names ``(path, needle)`` and ``Repo.truth()`` resolves the
line at HEAD and the introducing commit from the in-memory history of every commit, so
the labels cannot drift from the fixtures.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = 1
LEGACY_NOTE = "see bench/README.md"

AUTHORS = [
    ("Priya Nair", "priya.nair@example.invalid"),
    ("Tomas Berg", "tomas.berg@example.invalid"),
    ("Aiko Tanaka", "aiko.tanaka@example.invalid"),
]

CONTEXTS = [
    "The team needs a single, well understood choice here so that new joiners do not have to "
    "learn several ways of doing the same thing.",
    "Operations asked for fewer moving parts in production and a predictable upgrade path.",
    "Several services solved this problem differently and reviews kept going back and forth.",
    "An audit asked us to show which choices were deliberate and who made them.",
    "On-call engineers lost time to inconsistent setups between services.",
]
CONSEQUENCES = [
    "New code follows this decision; exceptions need a new ADR.",
    "Reviewers can point at this record when a change goes the other way.",
    "Existing code is migrated opportunistically when it is touched.",
]
MESSAGES = [
    "Tidy imports",
    "Add helper for string formatting",
    "Fix typo in README",
    "Refactor config loading",
    "Add small utility module",
    "Bump patch versions",
    "Improve error messages",
    "Add unit test scaffolding",
    "Clean up dead code",
    "Document local setup",
    "Rename internal helper",
    "Add pagination helper",
]


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        LC_ALL="C",
        TZ="UTC",
    )
    return env


GIT_FLAGS = [
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.autocrlf=false",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.fileMode=false",
]


@dataclass
class _Decision:
    num: int
    row: dict[str, Any]
    violation: list[tuple[str, str, str]]
    decoys: list[tuple[str, str, str]]
    proof: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass
class Repo:
    root: Path
    name: str
    seed: int
    ecosystem: str
    layout: str = "single"
    start: datetime = field(default_factory=lambda: datetime(2024, 2, 5, 9, 0, tzinfo=timezone.utc))

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.rng = random.Random(self.seed)
        self.tree: dict[str, str] = {}
        self.snaps: list[tuple[str, dict[str, str]]] = []
        self.clock = self.start
        self.n_fill = 0
        self._decisions: list[_Decision] = []
        self._undoc: list[dict[str, Any]] = []
        self._adr_text: list[str] = []
        self.styles: set[str] = set()
        self.pending: list[str] = []
        if self.root.exists():
            shutil.rmtree(self.root)  # the builder owns its directory: always start clean
        self.root.mkdir(parents=True)
        self._git("init", "-q", "--template=", "-b", "main")

    # ------------------------------------------------------------------ git
    def _git(self, *args: str, env: dict[str, str] | None = None) -> str:
        e = _clean_env()
        if env:
            e.update(env)
        p = subprocess.run(
            ["git", *GIT_FLAGS, *args],
            cwd=self.root,
            env=e,
            capture_output=True,
            text=True,
            check=True,
        )
        return p.stdout

    # ------------------------------------------------------------------ files
    def write(self, path: str, text: str) -> None:
        if not text.endswith("\n"):
            text += "\n"
        self.tree[path] = text

    def read(self, path: str) -> str:
        return self.tree[path]

    def remove(self, path: str) -> None:
        self.tree.pop(path, None)

    def append(self, path: str, text: str) -> None:
        self.write(path, self.tree.get(path, "") + text.rstrip("\n") + "\n")

    def insert_after(self, path: str, anchor: str, text: str) -> None:
        lines = self.tree[path].split("\n")
        for i, line in enumerate(lines):
            if anchor in line:
                lines[i + 1 : i + 1] = text.rstrip("\n").split("\n")
                self.tree[path] = "\n".join(lines)
                return
        raise KeyError(f"{path}: anchor {anchor!r} not found")

    def sub(self, path: str, old: str, new: str) -> None:
        if old not in self.tree[path]:
            raise KeyError(f"{path}: {old!r} not found")
        self.tree[path] = self.tree[path].replace(old, new, 1)

    # ------------------------------------------------------------------ commits
    def commit(self, msg: str, files: dict[str, str] | None = None) -> str:
        for p, t in (files or {}).items():
            self.write(p, t)
        # sync the working dir to self.tree
        on_disk = {
            p.relative_to(self.root).as_posix()
            for p in self.root.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(self.root).parts
        }
        for gone in on_disk - set(self.tree):
            (self.root / gone).unlink()
        for p, t in self.tree.items():
            f = self.root / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(t.encode("utf-8"))
        self.clock += timedelta(hours=self.rng.randint(5, 50))
        name, mail = AUTHORS[self.rng.randrange(len(AUTHORS))]
        stamp = self.clock.strftime("%Y-%m-%dT%H:%M:%S +0000")
        env = {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": mail,
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": mail,
            "GIT_COMMITTER_DATE": stamp,
        }
        self._git("add", "--all", "--", ".")
        self._git("commit", "-q", "--no-verify", "-m", msg, env=env)
        sha = self._git("rev-parse", "HEAD").strip()
        self.snaps.append((sha, dict(self.tree)))
        return sha

    def filler(self, n: int, maker: Any) -> None:
        """``n`` small unrelated commits. ``maker(k, rng) -> {path: text}``."""
        for _ in range(n):
            self.n_fill += 1
            files = maker(self.n_fill, self.rng)
            self.commit(self.rng.choice(MESSAGES), files)

    # ------------------------------------------------------------------ ADRs
    def decision(
        self,
        num: int,
        title: str,
        text: str,
        *,
        truth: str,
        style: str = "nygard",
        status: str = "Accepted",
        offline: str | None = None,
        phrasing: str = "supported",
        kind: str | None = None,
        violation: list[tuple[str, str, str]] | None = None,
        decoys: list[tuple[str, str, str]] | None = None,
        terms: tuple[str, ...] = (),
        proof: list[tuple[str, str, str]] | None = None,
        tags: tuple[str, ...] = (),
        context: str | None = None,
        hint: str | None = None,
        adr_dir: str = "docs/adr",
        superseded_by: int | None = None,
        raw: str | None = None,
        note: str = "",
        consequences: str | None = None,
    ) -> str:
        """Write an ADR and declare its ground truth. ``offline`` is None (the offline rule
        library is expected to reach ``truth``) or ``UNKNOWN_OR_SKIPPED`` (it cannot).

        Label audit (tests/test_l015_bench.py): ``terms`` is the vocabulary the label hinges
        on (case-insensitive substrings). HOLDING: no term may occur in production code at
        HEAD (tests, vendored code, dev/optional dependency sections and comments do not
        count). VIOLATED: every seeded violation line is production code and contains a term.
        DRIFTING: no production hit, at least one non-production hit. ``proof`` lists
        ``(path, needle, kind)`` lines that must exist, emitted as ``role=proof`` evidence
        rows with the resolved line; a HOLDING decision needs ``proof`` and/or ``terms``
        so its label is checkable.
        """
        assert truth in ("HOLDING", "VIOLATED", "DRIFTING", "UNKNOWN", "SKIPPED"), truth
        assert offline in (None, "UNKNOWN_OR_SKIPPED"), offline
        slug = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:40]
        slug = "-".join(p for p in slug.split("-") if p)
        path = f"{adr_dir}/{num:04d}-{slug}.md"
        ctx = context or self.rng.choice(CONTEXTS)
        cons = consequences or self.rng.choice(CONSEQUENCES)
        stat = status
        if superseded_by is not None:
            stat = f"Superseded by ADR-{superseded_by:04d}"
        date = (self.clock + timedelta(days=1)).strftime("%Y-%m-%d")
        if raw is not None:
            body = raw
        elif style in ("nygard", "adrtools"):
            link = ""
            if superseded_by is not None:
                link = f"Superseded by [{superseded_by}. later decision]({superseded_by:04d}-x.md)"
                stat = link
            body = (
                f"# {num}. {title}\n\nDate: {date}\n\n## Status\n\n{stat}\n\n"
                f"## Context\n\n{ctx}\n\n## Decision\n\n{text}\n\n## Consequences\n\n{cons}\n"
            )
        elif style == "madr":
            body = (
                f"# {title}\n\n* Status: {stat.lower()}\n* Date: {date}\n\n"
                f"## Context and Problem Statement\n\n{ctx}\n\n## Decision Outcome\n\n{text}\n\n"
                f"### Consequences\n\n{cons}\n"
            )
        elif style == "madr-fm":
            hint_block = f"driftwarden:\n{hint}\n" if hint else ""
            body = (
                f"---\nstatus: {stat.lower()}\ndate: {date}\n{hint_block}---\n\n# {title}\n\n"
                f"## Context and Problem Statement\n\n{ctx}\n\n## Decision Outcome\n\n{text}\n\n"
                f"### Consequences\n\n{cons}\n"
            )
        elif style == "freeform":
            body = f"# {title}\n\nStatus: {stat}\n\n{ctx}\n\n{text}\n"
        else:
            raise ValueError(style)
        self.write(path, body)
        self.styles.add(style if style != "adrtools" else "adr-tools")
        self._adr_text.append(body.lower())
        did = f"ADR-{num:04d}"
        row = {
            "type": "claim",
            "decision_id": did,
            "title": title,
            "adr_path": path,
            "adr_style": style,
            "adr_status": stat,
            "status": truth,
            "expected_offline": offline or truth,
            "phrasing": phrasing,
            "kind": kind,
            "tags": list(tags),
            "note": note,
            "terms": list(terms),
        }
        self._decisions.append(_Decision(num, row, violation or [], decoys or [], proof or []))
        return path

    # ------------------------------------------------------------------ undocumented
    def undocumented(
        self,
        technology: str,
        category: str,
        items: list[tuple[str, str]],
        *,
        role: str = "positive",
        reason: str = "",
    ) -> None:
        """role=positive: an undocumented production technology. role=negative: must NOT be
        reported (``reason``: documented | nonproduction | comment-only | vendored)."""
        self._undoc.append(
            {
                "technology": technology,
                "category": category,
                "items": items,
                "role": role,
                "reason": reason,
            }
        )

    # ------------------------------------------------------------------ truth
    def _line(self, tree: dict[str, str], path: str, needle: str) -> list[int]:
        if path not in tree:
            return []
        return [i + 1 for i, ln in enumerate(tree[path].split("\n")) if needle in ln]

    def _locate(self, path: str, needle: str) -> tuple[int, str, str]:
        """(line at HEAD, introducing sha, its short message-free index)."""
        head = self._line(self.tree, path, needle)
        if len(head) != 1:
            raise ValueError(f"{self.name}: {path}: {needle!r} matches {len(head)} lines at HEAD")
        first = None
        for i, (_sha, tr) in enumerate(self.snaps):
            if self._line(tr, path, needle):
                first = i
                break
        assert first is not None
        for _sha, tr in self.snaps[first:]:
            assert self._line(tr, path, needle), f"{path}: {needle!r} not continuous"
        return head[0], self.snaps[first][0], str(first)

    def truth(self) -> dict[str, Any]:
        head = self.snaps[-1][0]
        adr_blob = "\n".join(self._adr_text)
        records: list[dict[str, Any]] = []
        for d in self._decisions:
            row = dict(d.row)
            row["id"] = f"{self.name}:{row['decision_id']}"
            row["repo"] = self.name
            records.append(row)
            for path, needle, kind in d.violation:
                line, sha, _ = self._locate(path, needle)
                records.append(
                    {
                        "type": "evidence",
                        "role": "violation",
                        "repo": self.name,
                        "id": f"{self.name}:{row['decision_id']}:v:{path}:{line}",
                        "decision_id": row["decision_id"],
                        "path": path,
                        "line": line,
                        "kind": kind,
                        "introduced_commit": sha,
                    }
                )
            for path, needle, kind in d.proof:
                line, sha, _ = self._locate(path, needle)
                records.append(
                    {
                        "type": "evidence",
                        "role": "proof",
                        "repo": self.name,
                        "id": f"{self.name}:{row['decision_id']}:p:{path}:{line}",
                        "decision_id": row["decision_id"],
                        "path": path,
                        "line": line,
                        "kind": kind,
                        "needle": needle,
                        "introduced_commit": sha,
                    }
                )
            for path, needle, kind in d.decoys:
                line, sha, _ = self._locate(path, needle)
                records.append(
                    {
                        "type": "evidence",
                        "role": "decoy",
                        "repo": self.name,
                        "id": f"{self.name}:{row['decision_id']}:d:{path}:{line}",
                        "decision_id": row["decision_id"],
                        "path": path,
                        "line": line,
                        "decoy_kind": kind,
                        "introduced_commit": sha,
                    }
                )
        for u in self._undoc:
            term = u["technology"].lower()
            if u["role"] == "positive":
                assert not re.search(rf"(?<![a-z0-9_]){re.escape(term)}(?![a-z0-9_])", adr_blob), (
                    f"{self.name}: ADR text mentions {term}"
                )
            evid = []
            for path, needle in u["items"]:
                line, sha, idx = self._locate(path, needle)
                evid.append({"path": path, "line": line, "commit": sha, "_i": int(idx)})
            evid.sort(key=lambda e: e["_i"])
            for e in evid:
                e.pop("_i")
            rec = {
                "type": "undocumented",
                "repo": self.name,
                "technology": u["technology"],
                "category": u["category"],
                "role": u["role"],
                "reason": u["reason"],
                "id": f"{self.name}:ud:{u['technology']}:{u['role']}",
                "evidence": evid,
                "introducing_commits": list(dict.fromkeys(e["commit"] for e in evid)),
                "first_commit": evid[0]["commit"],
            }
            records.append(rec)
        counts: dict[str, int] = {}
        for r in records:
            k = r["type"] if r["type"] != "evidence" else f"evidence_{r['role']}"
            counts[k] = counts.get(k, 0) + 1
        return {
            "schema": SCHEMA,
            "repo": self.name,
            "ecosystem": self.ecosystem,
            "layout": self.layout,
            "head": head,
            "commits": len(self.snaps),
            "adr_styles": sorted(self.styles),
            "counts": counts,
            "records": records,
        }
