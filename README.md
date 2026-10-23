# DriftWarden

**Keep your codebase honest to its own architecture decisions.**

DriftWarden reads your Architecture Decision Records and design docs, then checks your code, dependencies, infrastructure and git history to answer three questions:

1. **Which decisions still hold, which are drifting, and which are violated?**
2. **What has the code decided that nobody wrote down?** DriftWarden drafts the missing ADR for you.
3. **When did each decision start to rot, and which commit did it?**

Every finding comes with `file:line@commit` evidence that a deterministic verifier has checked. If the evidence doesn't check out, DriftWarden tells you it *could not verify* the finding rather than presenting a guess as fact.

> 🚧 **Under active development.** v0.1.0 is targeted for 2026-11-02. Progress is tracked in [DELIVERY_LOG.md](DELIVERY_LOG.md).

## Quick start (target for v0.1.0)

```bash
pip install driftwarden
cd your-repo
driftwarden scan .                          # uses ANTHROPIC_API_KEY if set, else offline mode
driftwarden scan . --mode offline           # no network, no key
driftwarden scan . --format html,sarif,md --out reports/
```

GitHub Action:

```yaml
- uses: vshalsh/driftwarden@v0
  with:
    mode: pr            # only claims touched by this PR's diff
    sarif: true         # findings appear in the Security → Code scanning tab
    comment: true
```

## What a finding looks like

```
VIOLATED  ADR-0007 "PostgreSQL is the only datastore"
  claim     only(datastore) = [postgresql]           docs/adr/0007-datastore.md:12-14 @ 9f2c1e0
  evidence  pymongo==4.6 added                        services/catalog/requirements.txt:18 @ a41d7b3
            from pymongo import MongoClient            services/catalog/repo.py:3 @ a41d7b3
  since     a41d7b3  "catalog: cache product docs"   (2026-07-14)
  grounding VERIFIED (G1, G2, G3, G4)
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). The short version is that **the LLM proposes and deterministic code disposes.**

## Grounding & traceability

DriftWarden is itself an AI system, so it is held to the standard it enforces. Every AI-produced statement carries a provenance record, and a plain Python function (no second model) checks it against the repository before the statement is shown as fact.

| # | What the AI produces | Provenance it must return | Verifier | Sample & threshold | Evidence | What the user sees on failure |
|---|---|---|---|---|---|---|
| G1 | A testable claim extracted from an ADR | `path, line_start, line_end, commit, quote` | `grounding/verify.py::verify_source_quote` | Every claim, every run; benchmark ≥ 200 records | `logs/grounding/*.jsonl`, ledger | Claim listed under *Could not verify* with the mismatch reason; it is not judged |
| G2 | Code evidence cited for a verdict | `path, line_start, line_end, commit, snippet` | `verify_source_quote` | Every cited item | same | Evidence removed. If no verified evidence remains, the verdict becomes `UNKNOWN` and is shown under *Could not verify* |
| G3 | "Dependency X is present / was added" | `manifest_path, package, version_spec, commit` | `verify_dependency` (non-LLM manifest parsers) | Every dependency claim | same | As G2 |
| G4 | "First violated at commit C" | `commit, parent, evidence_ref` | `verify_first_violation` | Every timeline entry | same | Timeline entry shown as "first seen: unknown" |
| G5 | Drafted ADR for an undocumented decision | `introducing_commits[], evidence_refs[]` | `verify_commits_exist` + G2 | Every draft | same | Draft not emitted; listed as a *candidate* with the reason |
| G6 | Verdict stability | 3 independent judgements | `judge/consistency.py` | Every LLM verdict | same | Disagreement → `UNKNOWN` |
| G7 | Whole-system accuracy | — | `bench/run.py` on seeded fixtures | ≥ 6 repos, ≥ 200 records; precision ≥ 0.90, recall ≥ 0.85; raw citation accuracy ≥ 90 % | `bench/results/` | Release blocked (Gate 3) |

**How do we know a "VIOLATED" is real?** The claim's quote was found verbatim at the cited lines of the ADR at that commit (G1). Each piece of evidence was found verbatim at its cited lines (G2). Any dependency was re-parsed from the manifest by a non-LLM parser (G3). A finding that fails any of these checks is never displayed as a violation.

## Development

Built with a fixed delivery crew: Vishal Sharma (Product Owner), Fable (PM and gate), Opus (developer + UI/UX), Sonnet (system tests) and Haiku (black-box customer tests). See [PROJECT_BRIEF.md](PROJECT_BRIEF.md) and [DELIVERY_LOG.md](DELIVERY_LOG.md).

## Licence

Apache-2.0 (pending Gate 1).
