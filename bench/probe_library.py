"""Developer calibration probe: run the offline library modules directly on a corpus repo.

NOT the L-028 adapter and not part of the pipeline. It calls the existing building blocks
(``scan_adrs`` -> ``structure_scan`` -> ``judge_claims`` and ``detect_undocumented``) so the
corpus labels and the scorer can be checked against real offline output before
``run_scan`` exists. ``bench/run.py::predict`` is still the place L-028 plugs in.

    python -m bench.probe_library REPO_DIR [REPO_DIR ...]      # prints predictions + diffs
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

AGG_ORDER = ["VIOLATED", "DRIFTING", "UNKNOWN", "HOLDING"]


def predict_library(repo_path: str | Path) -> list[dict[str, Any]]:
    from driftwarden.claims.structure import structure_scan
    from driftwarden.discover.adr import scan_adrs
    from driftwarden.judge.judge import judge_claims
    from driftwarden.undocumented import detect_undocumented

    repo = str(repo_path)
    name = Path(repo).name
    scan = scan_adrs(repo)
    accepted = [d for d in scan.decisions if d.status == "accepted"]
    sets = structure_scan(accepted, repo, mode="offline")
    claims = [c for s in sets for c in s.claims]
    verdicts = judge_claims(repo, claims, mode="offline")
    by_dec: dict[str, list[Any]] = {}
    for c, v in zip(claims, verdicts, strict=True):
        by_dec.setdefault(c.decision_id, []).append(v)
    preds: list[dict[str, Any]] = []
    for did, vs in by_dec.items():
        statuses = [v.status for v in vs]
        status = next((s for s in AGG_ORDER if s in statuses), "UNKNOWN")
        if status == "HOLDING" and any(s != "HOLDING" for s in statuses):
            status = "UNKNOWN"
        ev = [
            {"path": e.ref.path, "line": e.ref.line_start, "line_end": e.ref.line_end}
            for v in vs
            if v.status == status
            for e in v.evidence
        ]
        grounding = "VERIFIED" if all(v.grounding == "VERIFIED" for v in vs) else "MISMATCH"
        preds.append(
            {
                "repo": name,
                "decision_id": did,
                "status": status,
                "evidence": ev,
                "grounding": grounding,
            }
        )
    for d in scan.decisions:
        if d.status != "accepted":
            preds.append(
                {
                    "repo": name,
                    "decision_id": d.id,
                    "status": "SKIPPED",
                    "evidence": [],
                    "grounding": "VERIFIED",
                }
            )
    ud = detect_undocumented(repo, decisions=scan.decisions, claims=claims)
    for r in ud.records:
        preds.append(
            {
                "repo": name,
                "kind": "undocumented",
                "technology": r.technology,
                "category": r.category,
                "introducing_commits": list(r.introducing_commits),
                "evidence": [{"path": e.ref.path, "line": e.ref.line_start} for e in r.evidence],
                "grounding": r.grounding,
            }
        )
    return preds


def main(argv: list[str]) -> int:
    for p in argv:
        print(json.dumps(predict_library(p), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
