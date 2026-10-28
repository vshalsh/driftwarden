"""Benchmark scorer (G7). Pure Python, deterministic, no DriftWarden imports.

    score(truths, predictions, ledger_dir=None) -> dict       # the JSON result
    render_markdown(result) -> str
    write_results(result, out_dir, name="latest") -> (md_path, json_path)

Predictions (one list for all repos)::

    claim:        {repo, decision_id, status, evidence:[{path, line | line_start[, line_end]}],
                   grounding}                      status: HOLDING|VIOLATED|DRIFTING|UNKNOWN|SKIPPED
    undocumented: {repo, kind: "undocumented", technology, category, introducing_commits:[sha],
                   evidence:[{path, line}], grounding}

Conventions (also in bench/README.md):

* A decision with no prediction is ``NONE``. For a SKIPPED or UNKNOWN truth that is correct
  abstention; for HOLDING / VIOLATED / DRIFTING it is a miss.
* A prediction whose ``grounding`` is not VERIFIED is a "Could not verify" record, never a
  finding: it is scored as UNKNOWN (so it can never be a false VIOLATED) and counted.
* Several predictions for one decision (one per claim) are merged with
  :func:`aggregate_status`.
* Precision / recall / F1 are ``None`` when undefined (no predicted positives / no true
  positives to find). A ``None`` precision or recall never passes a threshold.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

THRESHOLDS = {
    "precision": 0.90,
    "recall": 0.85,
    "citation_accuracy": 0.90,
    "min_records": 200,
    "min_repos": 6,
    "min_ledger_rows": 200,
}
STATUSES = ["HOLDING", "VIOLATED", "DRIFTING", "UNKNOWN", "SKIPPED"]
CORE = ["HOLDING", "VIOLATED", "UNKNOWN"]
COLS = STATUSES + ["NONE"]
ABSTAIN = {"UNKNOWN", "SKIPPED", "NONE"}
AGG_ORDER = ["VIOLATED", "DRIFTING", "UNKNOWN", "HOLDING"]


# --------------------------------------------------------------------------- helpers


def aggregate_status(statuses: list[str]) -> str:
    """One decision from its claims' statuses: VIOLATED beats DRIFTING beats UNKNOWN; HOLDING
    only if every claim holds; SKIPPED only if every entry is SKIPPED."""
    sts = [normalise_status(s) for s in statuses]
    if not sts:
        return "NONE"
    if all(s == "SKIPPED" for s in sts):
        return "SKIPPED"
    sts = [s for s in sts if s != "SKIPPED"]
    for s in AGG_ORDER[:-1]:
        if s in sts:
            return s
    return "HOLDING" if all(s == "HOLDING" for s in sts) else "UNKNOWN"


def merge_decision(preds: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]], int]:
    """One decision from its per-claim predictions: (status, evidence, claims downgraded).

    The single rule shared by :func:`score` and ``bench.probe_library``: a claim whose
    grounding is not VERIFIED counts as UNKNOWN on its own (it never poisons a verified
    sibling), then :func:`aggregate_status` merges the claims. Evidence comes from the
    claims that carry the merged status."""
    eff, downgraded = [], 0
    for p in preds:
        q = dict(p, status=normalise_status(p.get("status")))
        if str(p.get("grounding", "VERIFIED")).upper() != "VERIFIED" and q["status"] not in (
            "UNKNOWN",
            "SKIPPED",
        ):
            q["status"] = "UNKNOWN"
            downgraded += 1
        eff.append(q)
    status = aggregate_status([q["status"] for q in eff])
    return (
        status,
        [e for q in eff if q["status"] == status for e in q.get("evidence", [])],
        downgraded,
    )


def normalise_status(s: Any) -> str:
    s = str(s or "").strip().upper()
    return s if s in STATUSES else "UNKNOWN"


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def prf(tp: int, fp: int, fn: int) -> dict[str, Any]:
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    if p is None or r is None:
        f1 = None
    else:
        f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def _path(p: Any) -> str:
    p = str(p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _span(e: dict[str, Any]) -> tuple[str, int, int] | None:
    start = e.get("line", e.get("line_start"))
    if start is None or not e.get("path"):
        return None
    try:
        start = int(start)
        end = int(e.get("line_end", start))
    except (TypeError, ValueError):
        return None
    return _path(e["path"]), start, max(start, end)


def _hits(evidence: list[dict[str, Any]], locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for loc in locations:
        for e in evidence or []:
            sp = _span(e)
            if sp and sp[0] == _path(loc["path"]) and sp[1] <= loc["line"] <= sp[2]:
                out.append(loc)
                break
    return out


def _same_commit(a: str, b: str) -> bool:
    a, b = (a or "").lower(), (b or "").lower()
    return len(a) >= 7 and len(b) >= 7 and (a.startswith(b) or b.startswith(a))


def _fmt(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.3f}"
    return str(x)


# --------------------------------------------------------------------------- ledger


# A ledger row verifies a model-produced citation when it is a G2/G3 row whose subject is
#   <claim id>/citation-<n>   judge.llm_verdict, a citation rejected before the verifiers
#   <claim id>/e<n>           judge.gate on cited evidence (claim ids contain a dot: ADR-1.c1)
#   draft:UD-.../<id>         undocumented.draft citations
# G1 (decision source, claim quotes), G5 and G6 (agreement votes) rows are not citations.
# Known limit: the ledger has no origin field, so the judge's rule-verdict gate rows
# (same subject shape, deterministic evidence) cannot be told apart from LLM ones.
_CITATION_SUBJECT = re.compile(
    r"^(?:draft:UD-[^/]+/[^/]+|(?!UD-)[^/:\s]+\.[^/\s]+/(?:e|citation-)\d+)$"
)


def is_citation_row(row: dict[str, Any]) -> bool:
    return row.get("check_id") in ("G2", "G3") and bool(
        _CITATION_SUBJECT.match(str(row.get("subject") or ""))
    )


def read_ledger(ledger_dir: str | Path | None) -> dict[str, Any] | None:
    """Grounding pass rate over every ``*.jsonl`` row under ``ledger_dir`` (recursive)
    (``rows``/``pass_rate``), and separately over citation rows only (``citation``, S4)."""
    if ledger_dir is None:
        return None
    rows = []
    for p in sorted(Path(ledger_dir).rglob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("status") in ("VERIFIED", "MISMATCH"):
                rows.append(row)
    by_check: dict[str, dict[str, int]] = defaultdict(lambda: {"VERIFIED": 0, "MISMATCH": 0})
    for row in rows:
        by_check[str(row.get("check_id", "?"))][row["status"]] += 1
    ok = sum(1 for r in rows if r["status"] == "VERIFIED")
    cit_rows = [r for r in rows if is_citation_row(r)]
    cit_ok = sum(1 for r in cit_rows if r["status"] == "VERIFIED")
    return {
        "citation": {
            "rows": len(cit_rows),
            "verified": cit_ok,
            "mismatch": len(cit_rows) - cit_ok,
            "pass_rate": _ratio(cit_ok, len(cit_rows)),
        },
        "rows": len(rows),
        "verified": ok,
        "mismatch": len(rows) - ok,
        "pass_rate": _ratio(ok, len(rows)),
        "by_check": {
            k: dict(v, pass_rate=_ratio(v["VERIFIED"], v["VERIFIED"] + v["MISMATCH"]))
            for k, v in sorted(by_check.items())
        },
    }


# --------------------------------------------------------------------------- scoring


def score(
    truths: dict[str, dict[str, Any]],
    predictions: list[dict[str, Any]],
    ledger_dir: str | Path | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score ``predictions`` against ``truths`` ({repo: truth dict as in bench/truth/*.json})."""
    claims: dict[tuple[str, str], dict[str, Any]] = {}
    evidence: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    undoc: dict[tuple[str, str], dict[str, Any]] = {}
    n_records = 0
    for repo, t in sorted(truths.items()):
        for rec in t["records"]:
            n_records += 1
            if rec["type"] == "claim":
                claims[(repo, rec["decision_id"])] = rec
            elif rec["type"] == "evidence":
                evidence[(repo, rec["decision_id"])].append(rec)
            elif rec["type"] == "undocumented":
                undoc[(repo, rec["technology"])] = rec

    # ---- normalise predictions
    claim_preds: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    ud_preds: dict[tuple[str, str], dict[str, Any]] = {}
    ungrounded = ud_ungrounded = 0
    grounding_seen = Counter()
    for p in predictions:
        repo = p.get("repo", "")
        g = str(p.get("grounding", "VERIFIED")).upper()
        grounding_seen[g] += 1
        if p.get("kind") == "undocumented":
            if g != "VERIFIED":
                ud_ungrounded += 1
                continue
            ud_preds.setdefault((repo, str(p.get("technology", ""))), p)
        else:
            claim_preds[(repo, str(p.get("decision_id", "")))].append(p)

    pred_status: dict[tuple[str, str], str] = {}
    pred_evidence: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for key, ps in claim_preds.items():
        pred_status[key], pred_evidence[key], n_down = merge_decision(ps)
        ungrounded += n_down

    # ---- VIOLATED precision / recall, overall and per repo
    counts: dict[str, Counter] = defaultdict(Counter)
    off_reach = Counter()
    matrix: dict[str, Counter] = {s: Counter() for s in STATUSES}
    errors: list[dict[str, Any]] = []
    for key, rec in sorted(claims.items()):
        repo = key[0]
        truth = rec["status"]
        got = pred_status.get(key, "NONE")
        matrix[truth][got] += 1
        for scope in (repo, "__all__"):
            if truth == "VIOLATED" and got == "VIOLATED":
                counts[scope]["tp"] += 1
            elif truth == "VIOLATED":
                counts[scope]["fn"] += 1
            elif got == "VIOLATED":
                counts[scope]["fp"] += 1
        if truth == "VIOLATED" and rec["expected_offline"] == "VIOLATED":
            off_reach["tp" if got == "VIOLATED" else "fn"] += 1
        ok = got == truth or (truth in ("UNKNOWN", "SKIPPED") and got in ABSTAIN)
        if not ok:
            errors.append(
                {
                    "repo": repo,
                    "decision_id": key[1],
                    "truth": truth,
                    "predicted": got,
                    "expected_offline": rec["expected_offline"],
                    "tags": rec.get("tags", []),
                }
            )
    unlabelled = sorted(k for k in pred_status if k not in claims)
    for key in unlabelled:
        if pred_status[key] == "VIOLATED":
            counts[key[0]]["fp"] += 1
            counts["__all__"]["fp"] += 1
            errors.append(
                {
                    "repo": key[0],
                    "decision_id": key[1],
                    "truth": "(unlabelled)",
                    "predicted": "VIOLATED",
                    "expected_offline": None,
                    "tags": [],
                }
            )

    repos = sorted(truths)
    violated = {
        "overall": prf(*(counts["__all__"][k] for k in ("tp", "fp", "fn"))),
        "per_repo": {r: prf(*(counts[r][k] for k in ("tp", "fp", "fn"))) for r in repos},
        "offline_reachable": {
            "tp": off_reach["tp"],
            "fn": off_reach["fn"],
            "recall": _ratio(off_reach["tp"], off_reach["tp"] + off_reach["fn"]),
            "note": "recall over VIOLATED decisions whose phrasing the offline rule library "
            "supports (expected_offline == VIOLATED); diagnostic, not the S2 number",
        },
    }

    # ---- evidence localisation (true-positive VIOLATED only)
    loc_total = loc_hit = decoy_cites = 0
    decoy_detail = []
    for key, rec in sorted(claims.items()):
        got = pred_status.get(key, "NONE")
        evs = evidence.get(key, [])
        if got == "VIOLATED":
            decoys = [e for e in evs if e["role"] == "decoy"]
            cited = _hits(pred_evidence.get(key, []), decoys)
            if cited:
                decoy_cites += 1
                decoy_detail.append(
                    {
                        "repo": key[0],
                        "decision_id": key[1],
                        "cited": [f"{c['path']}:{c['line']}" for c in cited],
                        "decoy_kinds": sorted({c.get("decoy_kind", "") for c in cited}),
                    }
                )
        if rec["status"] == "VIOLATED" and got == "VIOLATED":
            loc_total += 1
            if _hits(pred_evidence.get(key, []), [e for e in evs if e["role"] == "violation"]):
                loc_hit += 1
    localisation = {
        "true_positives": loc_total,
        "localised": loc_hit,
        "accuracy": _ratio(loc_hit, loc_total),
        "predicted_violated_citing_a_decoy": decoy_cites,
        "decoy_citations": decoy_detail,
    }

    # ---- confusion matrix
    full = {t: {c: matrix[t][c] for c in COLS} for t in STATUSES}

    def _fold(x: str) -> str:
        return x if x in CORE else "UNKNOWN"

    core: dict[str, dict[str, int]] = {t: {c: 0 for c in CORE} for t in CORE}
    for t in STATUSES:
        for c in COLS:
            core[_fold(t)][_fold(c)] += matrix[t][c]
    confusion = {
        "labels": COLS,
        "rows_are": "ground truth",
        "full": full,
        "core": {
            "labels": CORE,
            "matrix": core,
            "note": "DRIFTING / SKIPPED / no prediction are folded into UNKNOWN, on the "
            "truth rows and the prediction columns alike, so the matrix sums to the full count",
        },
    }

    # ---- subsets
    def subset(pred) -> dict[str, Any]:
        keys = [k for k, r in claims.items() if pred(r)]
        right = sum(1 for k in keys if _right(claims[k]["status"], pred_status.get(k, "NONE")))
        return {"records": len(keys), "correct": right, "accuracy": _ratio(right, len(keys))}

    def _right(truth: str, got: str) -> bool:
        return got == truth or (truth in ("UNKNOWN", "SKIPPED") and got in ABSTAIN)

    unsupported = [k for k, r in claims.items() if r["expected_offline"] == "UNKNOWN_OR_SKIPPED"]
    abstained = sum(1 for k in unsupported if pred_status.get(k, "NONE") in ABSTAIN)
    wrong_conf = sum(
        1
        for k in unsupported
        if pred_status.get(k, "NONE") not in ABSTAIN and pred_status[k] != claims[k]["status"]
    )
    flipped = sum(
        1
        for k, r in claims.items()
        if "prompt-injection" in r.get("tags", [])
        and r["status"] != "HOLDING"
        and pred_status.get(k) == "HOLDING"
    )
    adversarial_fp = sum(
        1
        for k, r in claims.items()
        if "adversarial" in r.get("tags", [])
        and r["status"] != "VIOLATED"
        and pred_status.get(k) == "VIOLATED"
    )
    breakdown = {
        "all_decisions": subset(lambda r: True),
        "supported_phrasing": subset(lambda r: r["expected_offline"] != "UNKNOWN_OR_SKIPPED"),
        "unsupported_phrasing": {
            "records": len(unsupported),
            "abstained": abstained,
            "confidently_wrong": wrong_conf,
            "fail_closed_rate": _ratio(abstained, len(unsupported)),
            "note": "records the offline library is not expected to decide: abstaining is "
            "correct fail-closed behaviour, a confident wrong status is a defect",
        },
        "adversarial": dict(
            subset(lambda r: "adversarial" in r.get("tags", [])), false_violations=adversarial_fp
        ),
        "prompt_injection": dict(
            subset(lambda r: "prompt-injection" in r.get("tags", [])), flipped_to_holding=flipped
        ),
        "skipped_status": subset(lambda r: r["status"] == "SKIPPED"),
        "qualifier_unknown": subset(lambda r: r["status"] == "UNKNOWN"),
    }

    # ---- undocumented decisions
    pos = {k for k, r in undoc.items() if r["role"] == "positive"}
    neg = {k: r for k, r in undoc.items() if r["role"] == "negative"}
    got_u = set(ud_preds)
    tp_u, fp_u, fn_u = got_u & pos, got_u - pos, pos - got_u
    intro_ok = sum(
        1
        for k in tp_u
        if any(
            _same_commit(undoc[k]["first_commit"], c)
            for c in ud_preds[k].get("introducing_commits", []) or []
        )
    )
    undocumented = dict(
        prf(len(tp_u), len(fp_u), len(fn_u)),
        introduction_accuracy=_ratio(intro_ok, len(tp_u)),
        negatives_total=len(neg),
        negatives_reported=sorted(
            f"{r}:{t} ({neg[(r, t)]['reason']})" for r, t in got_u if (r, t) in neg
        ),
        false_positives=sorted(f"{r}:{t}" for r, t in fp_u),
        missed=sorted(f"{r}:{t}" for r, t in fn_u),
        per_repo={
            r: prf(
                len({k for k in tp_u if k[0] == r}),
                len({k for k in fp_u if k[0] == r}),
                len({k for k in fn_u if k[0] == r}),
            )
            for r in repos
        },
    )

    # ---- grounding
    verified_preds = grounding_seen["VERIFIED"]
    total_preds = sum(grounding_seen.values())
    ledger = read_ledger(ledger_dir)
    grounding = {
        "predictions": total_preds,
        "predictions_verified": verified_preds,
        "predictions_pass_rate": _ratio(verified_preds, total_preds),
        "downgraded_to_unknown": ungrounded,
        "undocumented_not_verified": ud_ungrounded,
        "ledger": ledger,
    }

    # ---- thresholds
    lc = ledger["citation"] if ledger else None
    cit = lc["pass_rate"] if lc else None
    ov = violated["overall"]
    s2_p = ov["precision"] is not None and ov["precision"] >= THRESHOLDS["precision"]
    s2_r = ov["recall"] is not None and ov["recall"] >= THRESHOLDS["recall"]
    thresholds = {
        "S2": {
            "precision": ov["precision"],
            "precision_min": THRESHOLDS["precision"],
            "recall": ov["recall"],
            "recall_min": THRESHOLDS["recall"],
            "pass": s2_p and s2_r,
        },
        "S4": {
            "citation_accuracy": cit,
            "min": THRESHOLDS["citation_accuracy"],
            "ledger_rows": lc["rows"] if lc else 0,
            "grounding_pass_rate": ledger["pass_rate"] if ledger else None,
            "grounding_rows": ledger["rows"] if ledger else 0,
            "min_rows": THRESHOLDS["min_ledger_rows"],
            "pass": (
                None
                if ledger is None
                else bool(
                    cit is not None
                    and cit >= THRESHOLDS["citation_accuracy"]
                    and lc["rows"] >= THRESHOLDS["min_ledger_rows"]
                )
            ),
            "note": "S4 counts G2/G3 rows that verify a citation (judge, draft); G1/G5/G6 rows "
            "are in the overall grounding rate only. Meaningful only for a ledger written by "
            "an LLM-mode run, before the verifier filters; an offline ledger measures the "
            "rule library.",
        },
        "G7_corpus": {
            "repos": len(truths),
            "records": n_records,
            "min_repos": THRESHOLDS["min_repos"],
            "min_records": THRESHOLDS["min_records"],
            "pass": len(truths) >= THRESHOLDS["min_repos"]
            and n_records >= THRESHOLDS["min_records"],
        },
    }

    return {
        "schema": 1,
        "meta": meta or {},
        "corpus": {
            "repos": repos,
            "records": n_records,
            "claims": len(claims),
            "evidence": sum(len(v) for v in evidence.values()),
            "undocumented": len(undoc),
        },
        "violated": violated,
        "localisation": localisation,
        "confusion": confusion,
        "breakdown": breakdown,
        "undocumented": undocumented,
        "grounding": grounding,
        "thresholds": thresholds,
        "unlabelled_predictions": [f"{r}:{d}" for r, d in unlabelled],
        "errors": errors,
    }


# --------------------------------------------------------------------------- output


def render_markdown(res: dict[str, Any]) -> str:
    th, v = res["thresholds"], res["violated"]
    mark = {True: "PASS", False: "FAIL", None: "not measured"}
    o = v["overall"]
    p_ok = o["precision"] is not None and o["precision"] >= th["S2"]["precision_min"]
    r_ok = o["recall"] is not None and o["recall"] >= th["S2"]["recall_min"]
    L = ["# DriftWarden benchmark (G7)", ""]
    if res["meta"]:
        L += ["Run: " + ", ".join(f"{k}={val}" for k, val in sorted(res["meta"].items())), ""]
    c = res["corpus"]
    L += [
        f"Corpus: {len(c['repos'])} repos, {c['records']} labelled records "
        f"({c['claims']} decisions, {c['evidence']} evidence locations, "
        f"{c['undocumented']} undocumented items).",
        "",
        "## Thresholds",
        "",
        "| Criterion | Measured | Required | Result |",
        "|---|---|---|---|",
        f"| S2 precision (VIOLATED) | {_fmt(o['precision'])} | >= {th['S2']['precision_min']} | "
        f"{mark[p_ok]} |",
        f"| S2 recall (VIOLATED) | {_fmt(o['recall'])} | >= {th['S2']['recall_min']} | "
        f"{mark[r_ok]} |",
        f"| S4 citation accuracy | {_fmt(th['S4']['citation_accuracy'])} "
        f"({th['S4']['ledger_rows']} ledger rows) | >= {th['S4']['min']} over >= "
        f"{th['S4']['min_rows']} rows | {mark[th['S4']['pass']]} |",
        f"| G7 corpus size | {th['G7_corpus']['repos']} repos / {th['G7_corpus']['records']} "
        f"records | >= {th['G7_corpus']['min_repos']} / >= {th['G7_corpus']['min_records']} | "
        f"{mark[th['G7_corpus']['pass']]} |",
        "",
        f"S2 overall: **{mark[th['S2']['pass']]}**.",
        "",
        "## VIOLATED precision / recall",
        "",
        "| Repo | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, m in [("**all**", o), *sorted(v["per_repo"].items())]:
        L.append(
            f"| {name} | {m['tp']} | {m['fp']} | {m['fn']} | {_fmt(m['precision'])} | "
            f"{_fmt(m['recall'])} | {_fmt(m['f1'])} |"
        )
    L += [
        "",
        f"Recall over offline-supported phrasings only: {_fmt(v['offline_reachable']['recall'])} "
        f"({v['offline_reachable']['tp']} of "
        f"{v['offline_reachable']['tp'] + v['offline_reachable']['fn']}). Diagnostic only.",
        "",
    ]
    cm = res["confusion"]
    L += [
        "## Confusion matrix (rows: ground truth, columns: predicted)",
        "",
        "| truth \\ predicted | " + " | ".join(cm["labels"]) + " |",
        "|---|" + "---|" * len(cm["labels"]),
    ]
    for t in STATUSES:
        L.append(f"| {t} | " + " | ".join(str(cm["full"][t][x]) for x in cm["labels"]) + " |")
    L += ["", "## Evidence localisation", ""]
    lo = res["localisation"]
    L += [
        f"- True-positive VIOLATED that cite a seeded file and line: {lo['localised']} of "
        f"{lo['true_positives']} ({_fmt(lo['accuracy'])}).",
        f"- Predicted VIOLATED decisions that also cite a decoy location (comment, test, "
        f"dev dependency, vendored): {lo['predicted_violated_citing_a_decoy']}.",
    ]
    for d in lo["decoy_citations"]:
        L.append(
            f"  - {d['repo']} {d['decision_id']}: {', '.join(d['cited'])} "
            f"({', '.join(d['decoy_kinds'])})"
        )
    b = res["breakdown"]
    L += ["", "## Breakdown", "", "| Slice | Records | Correct | Accuracy |", "|---|---|---|---|"]
    for k in (
        "all_decisions",
        "supported_phrasing",
        "adversarial",
        "prompt_injection",
        "skipped_status",
        "qualifier_unknown",
    ):
        L.append(f"| {k} | {b[k]['records']} | {b[k]['correct']} | {_fmt(b[k]['accuracy'])} |")
    u = b["unsupported_phrasing"]
    L += [
        "",
        f"Unsupported phrasings: {u['records']} records, abstained {u['abstained']} "
        f"(fail-closed rate {_fmt(u['fail_closed_rate'])}), confidently wrong "
        f"{u['confidently_wrong']}.",
        f"Adversarial false VIOLATED: {b['adversarial']['false_violations']}. "
        f"Prompt-injection decisions flipped to HOLDING: "
        f"{b['prompt_injection']['flipped_to_holding']}.",
        "",
        "## Undocumented decisions",
        "",
    ]
    ud = res["undocumented"]
    L += [
        f"- Precision {_fmt(ud['precision'])}, recall {_fmt(ud['recall'])}, F1 {_fmt(ud['f1'])} "
        f"(TP {ud['tp']}, FP {ud['fp']}, FN {ud['fn']}).",
        f"- Introducing commit found for {_fmt(ud['introduction_accuracy'])} of true positives.",
        f"- Negative items (must not be reported): {ud['negatives_total']}, "
        f"reported anyway: {len(ud['negatives_reported'])}.",
    ]
    for k in ("false_positives", "missed", "negatives_reported"):
        if ud[k]:
            L.append(f"  - {k.replace('_', ' ')}: {', '.join(ud[k])}")
    g = res["grounding"]
    L += [
        "",
        "## Grounding",
        "",
        f"- Predictions VERIFIED: {g['predictions_verified']} of {g['predictions']} "
        f"({_fmt(g['predictions_pass_rate'])}); downgraded to UNKNOWN: "
        f"{g['downgraded_to_unknown']}.",
    ]
    if g["ledger"]:
        lg = g["ledger"]
        L.append(
            f"- Ledger, overall grounding: {lg['verified']} of {lg['rows']} rows VERIFIED "
            f"({_fmt(lg['pass_rate'])})."
        )
        lc = lg["citation"]
        L.append(
            f"- Ledger, citations only (S4): {lc['verified']} of {lc['rows']} rows VERIFIED "
            f"({_fmt(lc['pass_rate'])})."
        )
        for chk, m in lg["by_check"].items():
            L.append(
                f"  - {chk}: {m['VERIFIED']} of {m['VERIFIED'] + m['MISMATCH']} "
                f"({_fmt(m['pass_rate'])})"
            )
    else:
        L.append("- No ledger directory given: S4 not measured.")
    if res["errors"]:
        L += [
            "",
            "## Decisions not matching ground truth",
            "",
            "| Repo | Decision | Truth | Predicted | Offline expectation |",
            "|---|---|---|---|---|",
        ]
        for e in res["errors"]:
            L.append(
                f"| {e['repo']} | {e['decision_id']} | {e['truth']} | {e['predicted']} | "
                f"{e['expected_offline']} |"
            )
    return "\n".join(L) + "\n"


def write_results(
    res: dict[str, Any], out_dir: str | Path, name: str = "latest"
) -> tuple[Path, Path]:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    md, js = d / f"{name}.md", d / f"{name}.json"
    md.write_text(render_markdown(res), encoding="utf-8")
    js.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return md, js


def load_truth(truth_dir: str | Path) -> dict[str, dict[str, Any]]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(Path(truth_dir).glob("*.json"))
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Score predictions against bench/truth.")
    ap.add_argument("predictions", help="JSON file: list of prediction dicts")
    ap.add_argument("--truth-dir", default=str(Path(__file__).resolve().parent / "truth"))
    ap.add_argument("--ledger-dir")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "results"))
    ap.add_argument("--name", default="latest")
    a = ap.parse_args(argv)
    preds = json.loads(Path(a.predictions).read_text(encoding="utf-8"))
    res = score(load_truth(a.truth_dir), preds, a.ledger_dir)
    md, js = write_results(res, a.out, a.name)
    print(f"wrote {md} and {js}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
