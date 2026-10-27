"""Token and cost log: one JSONL line per LLM attempt.

Default location is ``<repo>/.driftwarden/logs/llm/<run-id>.jsonl`` (the same
self-ignored ``.driftwarden`` directory as the grounding ledger). When that
directory cannot be written, the log falls back to a per-repo directory in the
user cache dir, then the temp dir (with a warning), as the grounding ledger does
(L-022 / D-004). If nothing is writable the records are kept in memory only and a
warning is issued once: a cost log must never abort a scan.

Never logged: prompt or reply text, API keys, request headers.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftwarden.grounding.ledger import new_run_id

OUT_DIR = ".driftwarden"
_SUBDIR = Path("logs") / "llm"


def _writable(base: Path) -> bool:
    try:
        target = base / _SUBDIR
        target.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target, prefix=".probe-"):
            pass
        return True
    except OSError:
        return False


def _fallback_dirs(root: Path) -> list[Path]:
    tag = f"{root.name or 'repo'}-{hashlib.sha256(str(root).encode()).hexdigest()[:10]}"
    cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    user = os.environ.get("USER") or str(os.getuid() if hasattr(os, "getuid") else "user")
    return [
        Path(cache) / "driftwarden" / tag,
        Path(tempfile.gettempdir()) / f"driftwarden-{user}" / tag,
    ]


def resolve_base(root: Path) -> Path | None:
    """``<root>/.driftwarden`` if writable, else a fallback dir, else None."""
    base = root / OUT_DIR
    if _writable(base):
        ignore = base / ".gitignore"
        if not ignore.exists():
            try:
                ignore.write_text("# Written by driftwarden; run output, not source.\n*\n")
            except OSError:
                pass
        return base
    for alt in _fallback_dirs(root):
        if _writable(alt):
            warnings.warn(
                f"cannot write {base}; writing the LLM cost log to {alt} instead",
                RuntimeWarning,
                stacklevel=3,
            )
            return alt
    return None


class CostLog:
    """Append-only token/cost log.

    ``root`` is the scanned repository root; ``base_dir`` overrides the output
    directory (records go to ``base_dir/logs/llm``). With neither, records are
    kept in memory only (``records``).
    """

    def __init__(
        self,
        root: str | Path | None,
        *,
        base_dir: str | Path | None = None,
        run_id: str | None = None,
    ) -> None:
        self.root = Path(root).resolve() if root is not None else None
        self.base_dir = Path(base_dir) if base_dir is not None else None
        self.run_id = run_id or new_run_id()
        self.records: list[dict[str, Any]] = []
        self._path: Path | None = None
        self._resolved = False
        self._warned = False

    @property
    def path(self) -> Path | None:
        """The JSONL file, resolved on first use (None when logging in memory only)."""
        if not self._resolved:
            self._resolved = True
            base = self.base_dir
            if base is not None and not _writable(base):
                base = None
                self._warn(f"cannot write LLM cost log under {self.base_dir}")
            elif base is None and self.root is not None:
                base = resolve_base(self.root)
                if base is None:
                    self._warn(f"cannot write LLM cost log for {self.root}")
            if base is not None:
                self._path = base / _SUBDIR / f"{self.run_id}.jsonl"
        return self._path

    def _warn(self, msg: str) -> None:
        if not self._warned:
            self._warned = True
            warnings.warn(f"{msg}; keeping records in memory only", RuntimeWarning, stacklevel=4)

    def append(self, **fields: Any) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            **fields,
        }
        self.records.append(record)
        path = self.path
        if path is not None:
            try:
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError as exc:
                self._warn(f"cannot append to {path}: {exc.strerror or exc}")
        return record

    def totals(self) -> dict[str, Any]:
        """Token and cost totals across every attempt logged so far."""
        costs = [r.get("cost_usd") for r in self.records]
        known = [c for c in costs if c is not None]
        return {
            "calls": len(self.records),
            "input_tokens": sum(r.get("input_tokens", 0) for r in self.records),
            "output_tokens": sum(r.get("output_tokens", 0) for r in self.records),
            "cost_usd": round(sum(known), 8) if known else None,
            "cost_complete": len(known) == len(costs),
        }
