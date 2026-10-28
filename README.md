# DriftWarden

**Keep your codebase honest to its own architecture decisions.**

DriftWarden reads your Architecture Decision Records and design docs, then checks your code, dependencies, infrastructure and git history to answer three questions:

1. **Which decisions still hold, which are drifting, and which are violated?**
2. **What has the code decided that nobody wrote down?** DriftWarden drafts the missing ADR for you.
3. **When did each decision start to rot, and which commit did it?**

Every finding comes with `file:line@commit` evidence that a deterministic verifier has checked. If the evidence doesn't check out, DriftWarden tells you it *could not verify* the finding rather than presenting a guess as fact.

> 🚧 **Under active development.** v0.1.0 is targeted for 2026-11-02. Progress is tracked in [DELIVERY_LOG.md](DELIVERY_LOG.md).

## Quick start

```bash
pip install -e ".[dev]"                     # from a checkout; not on PyPI before v0.1.0
cd your-repo
driftwarden scan .                          # auto: llm if ANTHROPIC_API_KEY is set, else offline
driftwarden scan . --mode offline           # no network, no key
driftwarden scan . --json-out report.json   # the full Report as JSON
driftwarden scan . --draft-adrs             # also draft ADRs for undocumented decisions (shown, never written)
driftwarden scan . --format json,md,sarif   # report files in .driftwarden/ (or --out DIR)
driftwarden report .driftwarden/driftwarden.json --format md,sarif --out out/   # re-render, no rescan
```

`scan` runs the whole pipeline: ADR discovery, claim structuring, evidence and judgement at
HEAD, undocumented-decision detection and (with `--draft-adrs`) ADR drafting. It prints the
decisions table, the verdicts grouped by status, everything it *could not verify* with the
reason, the undocumented decisions, each verified ADR draft in full (numbered consecutively,
never written into the repository) and a grounding summary; every verifier result goes to the
grounding ledger (`<repo>/.driftwarden/logs/grounding/`, or `--out DIR`). In auto mode, a
provider that fails to start falls back to offline mode with a warning; `--mode llm` exits 2
instead. The drift timeline (L-011) is not built yet.

### Report files

`--format` takes a comma list of `json`, `md`, `sarif` and `html`, and writes
`OUT/driftwarden.<ext>` for each one. `OUT` is `--out DIR`, or `<repo>/.driftwarden` by
default (that directory ignores itself, so a scan never dirties the repository). The
written paths are printed.

| Format | File | What it is |
|---|---|---|
| `json` | `driftwarden.json` | The canonical Report: pretty-printed, keys sorted, one trailing newline. Byte-identical to `--json-out` |
| `md` | `driftwarden.md` | A Markdown report for GitHub: header, summary, Violated, Drifting, Could not verify (always present), Undocumented decisions (drafts collapsed), Holding (collapsed), Unknown, grounding summary, drift timeline (when present) |
| `sarif` | `driftwarden.sarif` | SARIF 2.1.0 for GitHub code scanning (below) |
| `html` | `driftwarden.html` | The self-contained HTML report (L-013). In a build without it, `--format html` exits 2 with "html report not available in this build" before scanning |

`driftwarden report REPORT.json --format md,sarif,html --out DIR` renders the same files
from a saved Report JSON without rescanning (default format `md`, default `--out` the
directory of `REPORT.json`; exit 0, or 2 for an unreadable or invalid file). The GitHub
Action uses it.

All user-controlled text (ADR text, commit subjects, paths) is escaped in Markdown,
`@mentions` cannot ping anyone, and draft ADRs are shown as inert source. Every reporter
also re-checks, without git, that each evidence item matches its own VERIFIED verifier
record inside the report; a finding that fails (for example, a saved JSON edited by hand)
is shown under *Could not verify* and never becomes a violation or a SARIF location.

### GitHub code scanning (SARIF)

One rule per claim kind (`forbid`, `require`, `only`, `boundary`, `free`) plus
`undocumented-decision` and `could-not-verify`. VIOLATED is an `error`, DRIFTING a
`warning`, undocumented decisions and *Could not verify* items are `note`s; HOLDING and
UNKNOWN produce no alert. A finding is located at its first verified evidence line, with
the ADR lines and the other evidence as related locations; a *Could not verify* item is
located at the ADR line, never at the unverified code line. `partialFingerprints` leave
out commits and line numbers, so an alert keeps its identity across runs. Output stays
within GitHub's limits (25,000 results per run, 10 MB); anything cut is recorded in
`runs[0].properties.driftwarden.truncated`.

```yaml
# .github/workflows/driftwarden.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write      # needed to upload SARIF
jobs:
  driftwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # full history for undocumented-decision detection
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "driftwarden @ git+https://github.com/vshalsh/driftwarden"
      - run: driftwarden scan . --mode offline --format sarif,md --out dw-out || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dw-out/driftwarden.sarif
          category: driftwarden
```

`|| true` keeps the job going when the scan exits 1 (violations) or 3 (G1 mismatch) so
the SARIF is still uploaded; drop it to fail the job as well.

PR mode (`run_scan(..., changed_paths=[...])`, used by the Action in L-014) judges every
accepted claim exactly as a full scan does, so a change can never hide a violation and the
exit code counts every verified violation. The changed paths only tag each verdict
`in_change: true/false` (the claim's ADR file changed, a changed path is one of its evidence
files or a path its rule names, or, for require/only claims, a file was deleted or renamed or
a manifest changed), so reports can lead with what the change touches.

GitHub Action (arrives in L-014, not available yet):

```yaml
- uses: vshalsh/driftwarden@v0
  with:
    mode: pr            # judges every claim; leads with the ones this PR's diff touches
    sarif: true         # findings appear in the Security → Code scanning tab
    comment: true
```

## What a finding looks like

Real output of `driftwarden scan . --mode offline` on the `pyshop` test fixture
(`tests/fixtures/judge_repos/pyshop`), excerpt:

```
Verdicts (7 judged of 7 claim(s)): 3 VIOLATED, 1 DRIFTING, 2 HOLDING, 1 UNKNOWN
VIOLATED (3), grounding VERIFIED
  ADR-0001.c1  only(datastore) = [PostgreSQL]  docs/adr/0001-postgresql-only.md:13@f9f785c
    other datastore mongodb used (e1, e2)
    evidence  requirements.txt:2@f9f785c  declares pymongo ==4.6.1
    evidence  src/shop/legacy/catalog.py:3@f9f785c  imports pymongo
...
Undocumented UD-queue-kafka: Use Kafka as queue / message broker (introduced f9f785c)
    evidence  requirements.txt:6@f9f785c  declares kafka-python ==2.0.2
    evidence  src/shop/events.py:1@f9f785c  imports kafka
Grounding (all checks): 54/54 VERIFIED, pass rate 100.0% [G1 14/14, G2 23/23, G3 7/7, G4 n/a, G5 10/10, G6 n/a]
Summary: drift score 66.7% (decided claims not HOLDING), 1 UNKNOWN, 0 unverified item(s), 3 undocumented decision(s), 0 draft(s); exit code 1
```

Each verdict line is `claim id  rule  ADR file:line@commit`; each evidence line is
`file:line@commit` plus what is there. Only VERIFIED verdicts are listed under a status.
Anything that failed a verifier is printed as `Could not verify <kind> <id> [<check>]:
<reason>` instead. The drift score is the share of decided claims (HOLDING, DRIFTING,
VIOLATED) that are not HOLDING; UNKNOWN is counted separately.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No VIOLATED claim and no G1 grounding mismatch |
| 1 | At least one VERIFIED claim is VIOLATED |
| 2 | Usage or config error (including `--mode llm` with no usable provider) |
| 3 | G1 grounding mismatch: an ADR decision or claim quote is not at its cited lines. Wins over 1 |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). The short version is that **the LLM proposes and deterministic code disposes.**

## Grounding & traceability

DriftWarden is itself an AI system, so it is held to the standard it enforces. Every AI-produced statement carries a provenance record, and a plain Python function (no second model) checks it against the repository before the statement is shown as fact.

| # | What the AI produces | Provenance it must return | Verifier | Sample & threshold | Evidence | What the user sees on failure |
|---|---|---|---|---|---|---|
| G1 | A testable claim extracted from an ADR | `path, line_start, line_end, commit, quote` | `grounding/verify.py::verify_source_quote` | Every claim, every run; benchmark ≥ 200 records | `logs/grounding/*.jsonl`, ledger | Claim listed under *Could not verify* with the mismatch reason; it is not judged |
| G2 | Code evidence cited for a verdict | `path, line_start, line_end, commit, snippet` | `verify_source_quote` (via `judge/judge.py::gate`) | Every cited item | same | The verdict becomes `UNKNOWN` (grounding `MISMATCH`) and is shown under *Could not verify* with the verifier's reasons; the unverified evidence stays listed |
| G3 | "Dependency X is present / was added" | `manifest_path, package, version_spec, commit` | `verify_dependency` (non-LLM manifest parsers) | Every dependency claim | same | As G2 |
| G4 | "First violated at commit C" | `commit, parent, evidence_ref` | `verify_first_violation` | Every timeline entry | same | Timeline entry shown as "first seen: unknown" |
| G5 | Drafted ADR for an undocumented decision | `introducing_commits[], evidence_refs[]` | `verify_commits_exist` + G2 | Every draft | same | Draft not emitted; listed as a *candidate* with the reason |
| G6 | Verdict stability | 3 independent judgements | `judge/consistency.py` | Every LLM verdict | same | Disagreement → `UNKNOWN` |
| G7 | Whole-system accuracy | — | `bench/run.py` on seeded fixtures | ≥ 6 repos, ≥ 200 records; precision ≥ 0.90, recall ≥ 0.85; raw citation accuracy ≥ 90 % | `bench/results/` | Release blocked (Gate 3) |

**How do we know a "VIOLATED" is real?** The claim's quote was found verbatim at the cited lines of the ADR at that commit (G1). Each piece of evidence was found verbatim at its cited lines (G2). Any dependency was re-parsed from the manifest by a non-LLM parser (G3). A finding that fails any of these checks is never displayed as a violation. Every report format renders through one cross-record check, `report/view.py::build_view`: an evidence item is shown, or becomes a SARIF location, only when the report itself holds a VERIFIED G2 (and, for dependencies, G3) record for exactly that item; otherwise the finding moves to *Could not verify*.

## Development

Built with a fixed delivery crew: Vishal Sharma (Product Owner), Fable (PM and gate), Opus (developer + UI/UX), Sonnet (system tests) and Haiku (black-box customer tests). See [PROJECT_BRIEF.md](PROJECT_BRIEF.md) and [DELIVERY_LOG.md](DELIVERY_LOG.md).

## Licence

Apache-2.0 (pending Gate 1).
