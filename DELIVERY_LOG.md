# DriftWarden — Delivery Log

The ledger. Fable owns it, and every status change here needs evidence (a commit, a test run or a grounding log). Rows are updated as work moves, not at the end.

**Status values:** `planned` · `in-build` · `in-test` · `defect` · `blocked` · `merged` · `dropped`

## Gates

| Gate | What Vishal approves | GitHub issue | Status | Approved on |
|---|---|---|---|---|
| G-1 | Scope, success criteria, grounding regime (PROJECT_BRIEF.md) | [#1](https://github.com/vshalsh/driftwarden/issues/1) | open | — |
| G-2 | Design tokens (DESIGN_TOKENS.md) + architecture (ARCHITECTURE.md) | [#2](https://github.com/vshalsh/driftwarden/issues/2) | open | — |
| G-3 | Release v0.1.0 against the evidence in this log | opened on Day 10 | not yet | — |

## 10-day plan

| Day | Date | Tickets | Theme |
|---|---|---|---|
| 0 | 2026-10-23 | L-000 | Intake: brief, plan, design research, architecture, repo |
| 1 | 2026-10-24 | L-001, L-002 | Skeleton, CLI, CI; ADR parsing + G1 verifier |
| 2 | 2026-10-25 | L-003, L-004 | Repo indexer + manifest parsers (G3); evidence model |
| 3 | 2026-10-26 | L-005, L-006 | LLM provider layer + offline rules; claim structuring |
| 4 | 2026-10-27 | L-007, L-008 | Judge agent with cited verdicts; G2 + G6 consistency |
| 5 | 2026-10-28 | L-009, L-010 | Undocumented-decision detector + ADR drafter (G5) |
| 6 | 2026-10-29 | L-011, L-012 | Drift timeline / bisect (G4); JSON + Markdown + SARIF |
| 7 | 2026-10-30 | L-013, L-014 | HTML report (design tokens, AA); GitHub Action + PR comment |
| 8 | 2026-10-31 | L-015, L-016 | Seeded-fixture benchmark (G7); system test hardening |
| 9 | 2026-11-01 | L-017, L-018 | Black-box RC (Haiku) + fixes; real OSS demo scan |
| 10 | 2026-11-02 | L-020 | Empty ADR (0 bytes) → skip with a note instead of MISMATCH + exit 3 (Sonnet O-1) | Opus→Sonnet | L-020-empty-adr | Empty ADR listed as skipped; scan exit 0 | G1 | planned | |
| L-021 | Normaliser false-accept: stripping `_` makes `snakecase` match `snake_case` — strip emphasis only when paired around words (Sonnet O-2) | Opus→Sonnet | L-021-normaliser | Identifier underscores preserved; emphasis still stripped; tamper tests still pass | G1 | planned | |
| L-022 | Ledger location: default to `<scanned repo>/.driftwarden/logs/grounding` when `--out` not given; add formatter exclude for docs (Opus notes) | Opus→Sonnet | L-022-ledger-path | Ledger lands in scanned repo; `ruff format` no longer touches *.md | — | planned | |
| L-019 | Grounding run, docs final, Gate 3, tag v0.1.0 |

## Tickets

| Id | Title | Seat | Branch | Acceptance criteria | Grounding | Status | Evidence |
|---|---|---|---|---|---|---|---|
| L-000 | Intake & foundation | Fable | main | Brief, log, README, architecture, design tokens committed | — | merged | initial commits |
| L-001 | Package skeleton, `driftwarden` CLI (`scan`, `version`), config file, CI (lint + tests, py3.10–3.13) | Opus→Sonnet | L-001-skeleton | `pip install -e .` works; `driftwarden --help` and `driftwarden version` run; CI green | — | in-test (green; awaiting Gate 1/2 to merge) | Sonnet @40ad893: 45 pass, 2 xfail (D-001, fixed by L-002); CI workflow not yet run on GitHub |
| L-002 | ADR discovery + parser (Nygard, MADR, free-form); Decision model with provenance; `verify_source_quote()` | Opus→Sonnet | L-002-adr-parser | Finds ADRs in `docs/adr`, `doc/architecture/decisions`, `adr/`, etc.; parses title, status, date, decision text; every record has path+lines+quote+commit; the verifier passes on 100 % of fixture records and catches tampered quotes | G1 | in-test (green; awaiting Gate 1/2 to merge, stacked on L-001) | Sonnet @84b44a0: 150 pass, 0 fail; G1 13/13 VERIFIED; tamper detection 130/130 |
| L-003 | Repo indexer: files, languages, import graph (Py, JS/TS, Java, Go) | Opus→Sonnet | L-003-indexer | Index of a 5k-file repo in < 30 s; import edges correct on fixtures | — | planned | |
| L-004 | Manifest parsers + `verify_dependency()` (requirements/pyproject, package.json, pom/gradle, go.mod, csproj, Dockerfile, compose, Terraform, k8s) | Opus→Sonnet | L-004-manifests | Correct package lists on fixtures; verifier recomputes at any commit | G3 | planned | |
| L-005 | LLM provider layer: Anthropic, OpenAI-compatible, `offline`; JSON-schema-constrained output; cost + token log | Opus→Sonnet | L-005-llm | Swappable via config; offline mode needs no network; retries + schema validation | — | planned | |
| L-006 | Claim structuring: decision text → testable claims (forbid/require/only/boundary rules) | Opus→Sonnet | L-006-claims | Claims are typed; each points back to its G1 provenance; the offline rule library covers common patterns | G1 | planned | |
| L-007 | Judge agent: claim + evidence → verdict with citations | Opus→Sonnet | L-007-judge | Verdicts cite evidence; unverified evidence → *Could not verify* | G2 | planned | |
| L-008 | Consistency runner (3× vote, disagreement → UNKNOWN) | Opus→Sonnet | L-008-consistency | Deterministic on the offline path; vote recorded | G6 | planned | |
| L-009 | Undocumented-decision detector (new datastore/queue/framework/SDK/service-call) | Opus→Sonnet | L-009-undocumented | Finds seeded undocumented choices in fixtures | G3, G5 | planned | |
| L-010 | ADR drafter (MADR format) from introducing commits | Opus→Sonnet | L-010-drafter | Draft cites only commits that exist and evidence that verifies | G5 | planned | |
| L-011 | Drift timeline: bisect first-violating commit per claim | Opus→Sonnet | L-011-timeline | Correct commit on seeded histories; G4 verifier passes | G4 | planned | |
| L-012 | Reporters: JSON, Markdown, SARIF 2.1.0 | Opus→Sonnet | L-012-reporters | SARIF validates against the schema; GitHub accepts the upload | — | planned | |
| L-013 | HTML report (self-contained, light/dark, DESIGN_TOKENS) | Opus→Sonnet | L-013-html | AA contrast both themes; works offline; phone width | — | planned | |
| L-014 | GitHub Action: full scan + PR-diff mode, PR comment, SARIF upload | Opus→Sonnet | L-014-action | Demo PR shows comment + code-scanning alert | — | planned | |
| L-015 | Seeded-fixture benchmark: ≥ 6 fixture repos, ≥ 200 records | Sonnet | L-015-bench | Precision/recall + grounding pass rate reported | G7 | planned | |
| L-016 | System test hardening + coverage ≥ 85 % on core | Sonnet | L-016-tests | Coverage report; all regression green on main | — | planned | |
| L-017 | Black-box run on RC + Sev-1/2 fixes | Haiku→Fable→Opus | rc-2026-11-01-1 | REPORT.md, no open Sev-1/2 | — | planned | |
| L-018 | Real OSS demo scan, published to `examples/` | Fable/Opus | L-018-demo | Report committed; every finding VERIFIED or *Could not verify* | G1–G5 | planned | |
| L-020 | Empty ADR (0 bytes) → skip with a note instead of MISMATCH + exit 3 (Sonnet O-1) | Opus→Sonnet | L-020-empty-adr | Empty ADR listed as skipped; scan exit 0 | G1 | planned | |
| L-021 | Normaliser false-accept: stripping `_` makes `snakecase` match `snake_case` — strip emphasis only when paired around words (Sonnet O-2) | Opus→Sonnet | L-021-normaliser | Identifier underscores preserved; emphasis still stripped; tamper tests still pass | G1 | planned | |
| L-022 | Ledger location: default to `<scanned repo>/.driftwarden/logs/grounding` when `--out` not given; add formatter exclude for docs (Opus notes) | Opus→Sonnet | L-022-ledger-path | Ledger lands in scanned repo; `ruff format` no longer touches *.md | — | planned | |
| L-019 | Final grounding run, README final, Gate 3, tag v0.1.0 | Fable | main | All S1–S9 evidenced | all | planned | |

## Grounding runs

| Date | Check | Sample | Pass rate | Failures | Log |
|---|---|---|---|---|---|
| 2026-10-23 | G1 verify_source_quote on fixture ADRs (L-002 @84b44a0) | 13 decisions | 100 % | 0 | Sonnet report, tests/test_l002_system.py |
| 2026-10-23 | G1 tamper detection (random-word mutation, 10× per decision) | 130 mutations | 100 % caught | 0 | same |

## Daily entries

### Day 0 — 2026-10-23 (Fable)
- Intake: PROJECT_BRIEF.md, DELIVERY_LOG.md, README.md, ARCHITECTURE.md written; design research delegated to Fable → DESIGN_TOKENS.md.
- Gate 1 and Gate 2 presented to Vishal together, for speed.

- Day-1 work pulled forward: L-001 and L-002 built by Opus, tested in isolation by Sonnet. Both green. Not merged — Gates 1 and 2 not yet approved.
- Defects / observations: D-001 (scan on non-git dir exits 0 on L-001 alone; fixed in L-002). New tickets L-020 (empty ADR), L-021 (normaliser false-accept), L-022 (ledger path) — scheduled for Day 2 carry-in.
- Risk: L-001 branch was cut before design tokens landed on main; Fable will rebase both branches on main before merge.
- Pushed to github.com/vshalsh/driftwarden. Gate issues #1, #2; Daily log #3; PRs #4 (L-001), #5 (L-002) labelled awaiting-gate.
