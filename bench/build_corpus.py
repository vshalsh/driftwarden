"""Build the benchmark corpus: fixture git repos plus their ground-truth labels.

    python -m bench.build_corpus OUT_DIR [--truth-dir bench/truth]

Everything is deterministic: fixed seeds, fixed author/committer identities and dates,
an isolated git config. Two builds produce identical commit SHAs, so the committed truth
files (which contain SHAs) can be checked against a fresh build.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any

REPOS = [
    "shopfront",
    "nodeapi",
    "ledgerboot",
    "fleetgate",
    "cloudbase",
    "megamono",
    "datahub",
    "gradlehub",
]
MIN_RECORDS = 200
MIN_REPOS = 6
TRUTH_DIR = Path(__file__).resolve().parent / "truth"


def build_corpus(out: str | Path, repos: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Create the repos under ``out`` and return ``{repo name: truth dict}``."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    truths: dict[str, dict[str, Any]] = {}
    for name in repos or REPOS:
        mod = importlib.import_module(f"bench.corpus.{name}")
        truths[name] = mod.build(out).truth()
    return truths


def write_truth(truths: dict[str, dict[str, Any]], truth_dir: str | Path) -> list[Path]:
    d = Path(truth_dir)
    d.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, t in sorted(truths.items()):
        p = d / f"{name}.json"
        p.write_text(
            json.dumps(t, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        paths.append(p)
    return paths


def summary(truths: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_repo = {n: dict(t["counts"], commits=t["commits"]) for n, t in sorted(truths.items())}
    total: dict[str, int] = {}
    for t in truths.values():
        for k, v in t["counts"].items():
            total[k] = total.get(k, 0) + v
    total["records"] = sum(sum(t["counts"].values()) for t in truths.values())
    return {"repos": len(truths), "by_repo": by_repo, "total": total}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", help="directory to build the fixture repos in")
    ap.add_argument("--truth-dir", default=str(TRUTH_DIR), help="where to write truth JSON")
    ap.add_argument("--repo", action="append", help="build only this repo (repeatable)")
    args = ap.parse_args(argv)
    truths = build_corpus(args.out, args.repo)
    write_truth(truths, args.truth_dir)
    print(json.dumps(summary(truths), indent=2))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    raise SystemExit(main())
