"""Grounding ledger: every verifier result of a run, as JSONL, plus a summary.

Layout under ``base_dir``::

    logs/grounding/<run-id>.jsonl          one GroundingResult per line
    logs/grounding/<run-id>.summary.json   counts and pass rate

Cross-record checks write rows too: ``G6`` (one per voted claim, VERIFIED when
the runs agreed; see ``judge.consistency``), so ``check_rate("G6")`` is the
consistency rate.
"""

from __future__ import annotations

import json
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftwarden.models import GroundingResult


def new_run_id() -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{now}-{secrets.token_hex(3)}"


class Ledger:
    def __init__(self, base_dir: str | Path = ".", run_id: str | None = None) -> None:
        self.run_id = run_id or new_run_id()
        self.dir = Path(base_dir) / "logs" / "grounding"
        self.path = self.dir / f"{self.run_id}.jsonl"
        self.summary_path = self.dir / f"{self.run_id}.summary.json"
        self._counts: Counter[tuple[str, str]] = Counter()

    def append(self, result: GroundingResult) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        record = {"run_id": self.run_id, **result.model_dump(mode="json")}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._counts[(result.check_id, result.status)] += 1

    def extend(self, results: list[GroundingResult]) -> None:
        for r in results:
            self.append(r)

    def summary(self) -> dict[str, Any]:
        total = sum(self._counts.values())
        verified = sum(v for (_, s), v in self._counts.items() if s == "VERIFIED")
        by_check: dict[str, dict[str, int]] = {}
        for (check, status), v in sorted(self._counts.items()):
            by_check.setdefault(check, {"VERIFIED": 0, "MISMATCH": 0})[status] = v
        return {
            "run_id": self.run_id,
            "total": total,
            "verified": verified,
            "mismatch": total - verified,
            # None, not 1.0, when nothing was checked: "100 % of zero" is not a pass.
            "pass_rate": (verified / total) if total else None,
            "by_check": by_check,
            "ledger": self.path.as_posix(),
        }

    def check_rate(self, check_id: str) -> float | None:
        """VERIFIED share of ``check_id`` rows (e.g. ``"G6"``: the consistency rate);
        None when there are none."""
        ok = self._counts[(check_id, "VERIFIED")]
        total = ok + self._counts[(check_id, "MISMATCH")]
        return ok / total if total else None

    def write_summary(self) -> dict[str, Any]:
        self.dir.mkdir(parents=True, exist_ok=True)
        data = self.summary()
        self.summary_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return data
