"""Benchmark runner: build the corpus in a temp dir, run DriftWarden on each repo, score.

    python -m bench.run [--keep DIR] [--out bench/results] [--ledger-dir DIR]
                        [--predictor scan|library]

``predict(repo_path)`` is the single seam to the real pipeline. It is a stub until L-028
(``run_scan(...) -> Report``) is merged. ``--predictor library`` runs the interim
``bench.probe_library`` instead (existing offline building blocks called directly; a
calibration aid, not the product path).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from bench.build_corpus import build_corpus
from bench.score import render_markdown, score, write_results

RESULTS_DIR = Path(__file__).resolve().parent / "results"


# --------------------------------------------------------------------------- ADAPTER


def predict(repo_path: str | Path) -> list[dict[str, Any]]:
    """Run DriftWarden (offline mode) on one repo and return scorer predictions.

    ADAPTER: the only function that must change when L-028 lands.

    TODO(L-028): implement as::

        report = run_scan(repo_path, mode="offline")          # driftwarden.pipeline
        return report_to_predictions(report.model_dump(mode="json"), Path(repo_path).name)

    ``report_to_predictions`` below already documents and implements the Report JSON fields
    the benchmark needs; check them against the real ``Report`` model and
    ``driftwarden scan --json-out``.
    """
    raise NotImplementedError("needs L-028 run_scan")


def report_to_predictions(report: dict[str, Any], repo: str) -> list[dict[str, Any]]:
    """Map a Report JSON (dict) to scorer predictions.

    Fields read from the Report (names as in ``driftwarden.models``):

    * ``decisions``: list of Decision dumps; only ``id`` and ``status`` are used. Every
      decision whose status is not ``accepted`` is emitted as ``SKIPPED``.
    * ``verdicts``: list of Verdict dumps: ``claim_id`` (``"ADR-0007.c1"``: the decision id is
      the part before the last ``.c<n>``), ``status``, ``grounding``,
      ``evidence[].ref.{path,line_start,line_end}``. Claims of one decision are merged by
      ``bench.score.aggregate_status``.
    * ``undocumented``: UndocumentedDecision dumps (verified findings AND the could-not-verify
      records, so ``grounding`` is read): ``technology``, ``category``,
      ``introducing_commits``, ``grounding``, ``evidence[].ref.{path,line_start}``.
    """
    preds: list[dict[str, Any]] = []
    for d in report.get("decisions", []):
        if d.get("status") != "accepted":
            preds.append(
                {
                    "repo": repo,
                    "decision_id": d["id"],
                    "status": "SKIPPED",
                    "evidence": [],
                    "grounding": "VERIFIED",
                }
            )
    for v in report.get("verdicts", []):
        did = v["claim_id"].rsplit(".", 1)[0]
        preds.append(
            {
                "repo": repo,
                "decision_id": did,
                "status": v["status"],
                "evidence": [
                    {
                        "path": e["ref"]["path"],
                        "line_start": e["ref"]["line_start"],
                        "line_end": e["ref"].get("line_end", e["ref"]["line_start"]),
                    }
                    for e in v.get("evidence", [])
                ],
                "grounding": v.get("grounding", "VERIFIED"),
            }
        )
    for u in report.get("undocumented", []):
        preds.append(
            {
                "repo": repo,
                "kind": "undocumented",
                "technology": u["technology"],
                "category": u.get("category"),
                "introducing_commits": list(u.get("introducing_commits", [])),
                "evidence": [
                    {"path": e["ref"]["path"], "line": e["ref"]["line_start"]}
                    for e in u.get("evidence", [])
                ],
                "grounding": u.get("grounding", "VERIFIED"),
            }
        )
    return preds


# --------------------------------------------------------------------------- runner


def run(
    out_dir: str | Path = RESULTS_DIR,
    *,
    keep: str | Path | None = None,
    ledger_dir: str | Path | None = None,
    predictor: str = "scan",
    name: str = "latest",
) -> dict[str, Any]:
    if predictor == "library":
        from bench.probe_library import predict_library as fn
    elif predictor == "scan":
        fn = predict
    else:
        raise ValueError(f"unknown predictor {predictor!r}")
    ctx = tempfile.TemporaryDirectory(prefix="dw-bench-") if keep is None else None
    root = Path(ctx.name if ctx else keep)  # type: ignore[arg-type]
    try:
        truths = build_corpus(root)
        predictions: list[dict[str, Any]] = []
        for repo in sorted(truths):
            predictions.extend(fn(root / repo))
        res = score(
            truths, predictions, ledger_dir, meta={"predictor": predictor, "mode": "offline"}
        )
        write_results(res, out_dir, name)
        return res
    finally:
        if ctx:
            ctx.cleanup()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(RESULTS_DIR))
    ap.add_argument("--keep", help="build the corpus here and keep it")
    ap.add_argument("--ledger-dir", help="directory holding grounding-ledger *.jsonl files")
    ap.add_argument("--predictor", choices=["scan", "library"], default="scan")
    ap.add_argument("--name", default="latest")
    a = ap.parse_args(argv)
    try:
        res = run(a.out, keep=a.keep, ledger_dir=a.ledger_dir, predictor=a.predictor, name=a.name)
    except NotImplementedError as exc:
        print(
            f"bench.run: predict() is a stub: {exc}. "
            "Use --predictor library for the interim library-direct probe.",
            file=sys.stderr,
        )
        return 2
    sys.stdout.write(render_markdown(res))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    raise SystemExit(main())
