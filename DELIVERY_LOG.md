# DriftWarden — Delivery Log

The ledger. Fable owns it, and every status change here needs evidence (a commit, a test run or a grounding log). Rows are updated as work moves, not at the end.

**Status values:** `planned` · `in-build` · `in-test` · `defect` · `blocked` · `merged` · `dropped`

## Gates

| Gate | What Vishal approves | GitHub issue | Status | Approved on |
|---|---|---|---|---|
| G-1 | Scope, success criteria, grounding regime (PROJECT_BRIEF.md) | [#1](https://github.com/vshalsh/driftwarden/issues/1) | approved | 2026-10-26 (comment by vshalsh on #1) |
| G-2 | Design tokens (DESIGN_TOKENS.md) + architecture (ARCHITECTURE.md) | [#2](https://github.com/vshalsh/driftwarden/issues/2) | approved | 2026-10-26 (comment by vshalsh on #2) |
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
| 10 | 2026-11-02 | L-019 | Full grounding + benchmark run, README final, Gate 3 issue; tag v0.1.0 only after Gate 3 approved |

## Tickets

| Id | Title | Seat | Branch | Acceptance criteria | Grounding | Status | Evidence |
|---|---|---|---|---|---|---|---|
| L-000 | Intake & foundation | Fable | main | Brief, log, README, architecture, design tokens committed | — | merged | initial commits |
| L-001 | Package skeleton, `driftwarden` CLI (`scan`, `version`), config file, CI (lint + tests, py3.10–3.13) | Opus→Sonnet | L-001-skeleton | `pip install -e .` works; `driftwarden --help` and `driftwarden version` run; CI green | — | merged | PR #4 merged by Vishal; Sonnet @40ad893: 45 pass |
| L-002 | ADR discovery + parser (Nygard, MADR, free-form); Decision model with provenance; `verify_source_quote()` | Opus→Sonnet | L-002-adr-parser | Finds ADRs in `docs/adr`, `doc/architecture/decisions`, `adr/`, etc.; parses title, status, date, decision text; every record has path+lines+quote+commit; the verifier passes on 100 % of fixture records and catches tampered quotes | G1 | merged | PR #5 merged; Sonnet @84b44a0: 150 pass; G1 13/13; tamper 130/130 |
| L-003 | Repo indexer: files, languages, import graph (Py, JS/TS, Java, Go) | Opus→Sonnet | L-003-indexer | Index of a 5k-file repo in < 30 s; import edges correct on fixtures | — | merged | PR #9 -> 102b53c. Sonnet: 92 system tests, D1 root `__init__` hang, D2 `.driftwarden` index, D3 nested excludes: fixed. Codex rounds 1-2: 10 findings fixed, 3 documented (Known limits). 5k files ~1.5 s. CI green (py3.10-3.13, macOS) |
| L-004 | Manifest parsers + `verify_dependency()` (requirements/pyproject, package.json, pom/gradle, go.mod, csproj, Dockerfile, compose, Terraform, k8s) | Opus→Sonnet | L-004-manifests | Correct package lists on fixtures; verifier recomputes at any commit | G3 | merged | PR #10 -> 088bb62. Sonnet: 203 system tests, 8 defects fixed (XML entity bomb, unpinned commit, BOM, UTF-16, Gradle, npm). Codex rounds 1-3: 14 findings fixed, 4 documented. G3 tamper 2667/2667 (Opus) + 934/934 (Sonnet). CI green |
| L-005 | LLM provider layer: Anthropic, OpenAI-compatible, `offline`; JSON-schema-constrained output; cost + token log | Opus→Sonnet | L-005-llm | Swappable via config; offline mode needs no network; retries + schema validation | — | merged | PR #12 -> 2dd6045. Sonnet: 2 rounds, D1-D17 (cost-log race, key/reply redaction, regex backtracking, config key shapes); D17 documented. Codex rounds 1-2: 8 findings fixed (redirect credential forwarding, schema walk, NaN, JSON pointers, refusal usage). CI green |
| L-006 | Claim structuring: decision text → testable claims (forbid/require/only/boundary rules) | Opus→Sonnet | L-006-claims | Claims are typed; each points back to its G1 provenance; the offline rule library covers common patterns | G1 | defect | PR #13 open (branch L-006-claims). Sonnet: 14 defects fixed, re-test found R1-R18 (dedup wildcard, negation/hedge guards, perf); Codex rounds 1-3 (14 findings fixed); round-4 root-cause fix (clause-coverage, fail-closed) in progress. G1 offline 100 %, tamper 2142/2142 |
| L-007 | Judge agent: claim + evidence → verdict with citations | Opus→Sonnet | L-007-judge | Verdicts cite evidence; unverified evidence → *Could not verify* | G2 | defect | branch L-007-judge (stacked on L-006). Built; Sonnet: D-L007-2..6 (WORKTREE ignores requirements*.txt, dev deps judged production, large files skipped silently, ledger gaps, UTF-16); fixes in progress. G2 235/235, tamper 8363/8363 (Sonnet) |
| L-008 | Consistency runner (3× vote, disagreement → UNKNOWN) | Opus→Sonnet | L-008-consistency | Deterministic on the offline path; vote recorded | G6 | defect | branch L-008-consistency (stacked on L-007). Built; Sonnet: criteria met, S1-S4 (low) fixes in progress. G6: 3 seeds x 336 claim runs, 100 % of disagreements -> UNKNOWN, 0 VIOLATED leaks |
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
| L-020 | Empty ADR (0 bytes) → skip with a note instead of MISMATCH + exit 3 (Sonnet O-1) | Opus→Sonnet | L-020-empty-adr | Empty ADR listed as skipped; scan exit 0 | G1 | merged | PR #6 -> 78dcfbf. Sonnet: 36 tests; D-002 (config-before-git) and D-003 (BOM-only) fixed. CI green |
| L-021 | Normaliser false-accept: stripping `_` makes `snakecase` match `snake_case` — strip emphasis only when paired around words (Sonnet O-2) | Opus→Sonnet | L-021-normaliser | Identifier underscores preserved; emphasis still stripped; tamper tests still pass | G1 | merged | PR #7 -> ecf91e2. Sonnet: 55 tests; D-005 (`__init__`), D-006 (code spans) fixed. Tradeoff: one-word `__bold__` stays literal. G1 tamper 130/130. CI green |
| L-022 | Ledger location: default to `<scanned repo>/.driftwarden/logs/grounding` when `--out` not given; add formatter exclude for docs (Opus notes) | Opus→Sonnet | L-022-ledger-path | Ledger lands in scanned repo; `ruff format` no longer touches *.md | — | merged | PR #8 -> d793e2e. Sonnet: 27 tests; D-004 (read-only ledger dir) fixed. CI green |
| L-023 | Harden `verify_source_quote`: reject HEAD/branch/short-SHA commits and non-canonical paths (`a/b.py/`, `./a/b.py`); NUL byte must not raise (Sonnet D-L007-1, D-L007-7) | Opus->Sonnet | L-023-verify-hardening | Only full pinned SHAs and canonical paths verify; never raises; G1/G2 tamper still 100 % | G1, G2 | planned | |
| L-019 | Final grounding run, README final, Gate 3, tag v0.1.0 | Fable | main | All S1–S9 evidenced | all | planned | |

## Grounding runs

| Date | Check | Sample | Pass rate | Failures | Log |
|---|---|---|---|---|---|
| 2026-10-23 | G1 verify_source_quote on fixture ADRs (L-002 @84b44a0) | 13 decisions | 100 % | 0 | Sonnet report, tests/test_l002_system.py |
| 2026-10-23 | G1 tamper detection (random-word mutation, 10× per decision) | 130 mutations | 100 % caught | 0 | same |
| 2026-10-26 | G1 tamper detection after normaliser change (L-021) | 130 mutations | 100 % caught | 0 | PR #7 CI, tests/test_l002_system.py |
| 2026-10-26 | G3 verify_dependency tamper (L-004), author suite | 2667 mutations over 69 fixture records | 100 % caught | 0 | tests/test_g3_verify.py |
| 2026-10-26 | G3 verify_dependency tamper (L-004), Sonnet independent suite | 934 mutations over 84 records | 100 % caught | 0 | tests/test_l004_system.py |
| 2026-10-27 | G1 offline claims verify + LLM-claim tamper (L-006 @f936aae), Sonnet independent suite | 56 rule claims; 2142 mutated LLM proposals over 13 decisions | 100 % verified / 100 % caught | 0 | tests/test_l006_system.py |
| 2026-10-27 | G2 verify_evidence/gate on judge verdicts (L-007 @23a9b14), Sonnet independent suite | 235 evidence items (+85 G3) over 292 verdicts | 100 % verified | 0 | tests/test_l007_system.py |
| 2026-10-27 | G2 tamper (L-007), Sonnet own operators | 8363 mutations over 54 evidence items | 100 % caught | 0 | same |
| 2026-10-27 | G6 consistency (L-008 @93174ee), seeded flaky provider | 3 seeds x 336 claim runs (112 claims each) | disagreements -> UNKNOWN 184/184 (100 %); 0 VIOLATED leaks | 0 | tests/test_l008_system.py |

## Daily entries

### Day 0 — 2026-10-23 (Fable)
- Intake: PROJECT_BRIEF.md, DELIVERY_LOG.md, README.md, ARCHITECTURE.md written; design research delegated to Fable → DESIGN_TOKENS.md.
- Gate 1 and Gate 2 presented to Vishal together, for speed.

- Day-1 work pulled forward: L-001 and L-002 built by Opus, tested in isolation by Sonnet. Both green. Not merged — Gates 1 and 2 not yet approved.
- Defects / observations: D-001 (scan on non-git dir exits 0 on L-001 alone; fixed in L-002). New tickets L-020 (empty ADR), L-021 (normaliser false-accept), L-022 (ledger path) — scheduled for Day 2 carry-in.
- Risk: L-001 branch was cut before design tokens landed on main; Fable will rebase both branches on main before merge.
- Pushed to github.com/vshalsh/driftwarden. Gate issues #1, #2; Daily log #3; PRs #4 (L-001), #5 (L-002) labelled awaiting-gate.

### Day 3 — 2026-10-26 (Fable)
- Gates: **G-1 and G-2 approved** by vshalsh (comments on #1 and #2 at 03:37 UTC). Main was already carrying L-001 and L-002.
- Done and merged through PRs: L-003 (#9), L-004 (#10), L-020 (#6), L-021 (#7), L-022 (#8). All green on CI (py3.10–3.13 and macOS).
- Defects found by Sonnet and fixed by Opus on the same tickets: D-002 (config errors must beat the git check), D-003 (BOM-only ADR), D-004 (read-only ledger dir), D-005 (`__init__` collapsed), D-006 (code spans), indexer D1–D3, manifest D1–D8. A Codex review bot found a further 31 P2 findings across #9 and #10; 24 were fixed with regression tests and 7 recorded as "Known limits" in the module docstrings (replies are on the PR threads).
- Grounding: G1 tamper 130/130; G3 tamper 2667/2667 (author) and 934/934 (Sonnet). 962+ tests green on main.
- Carried over: L-005 and L-006 (Day 3 plan) not started. Day 3 was spent clearing Day 2 and the carry-in tickets. The plan is one day behind.
- Risks: (1) The Codex bot keeps finding rarer parsing edge cases each round; policy now is fix security/regression findings, document rare ones, and cap at three rounds per PR. (2) Commit trailers on Opus branches say "Claude Opus 5.5", not the session's Sonnet line; left as is (rewriting would need force-pushes on merged history). (3) A stray remote branch `tmp-none` (copy of main, created by mistake early in the run) could not be deleted from this session; it is safe to delete from GitHub.


### Day 4 — 2026-10-27 (Fable)
- Gates: G-1 and G-2 remain approved. Tickets merge through their PRs.
- Merged: L-005 (#12 -> 2dd6045), the Day-3 carry-over. Sonnet found 17 defects over two rounds; Codex raised 8 findings over two rounds (credential forwarding on redirects was the P1). All fixed with regression tests; one known limit documented (D17).
- In flight, not merged: L-006 (#13), L-007, L-008, stacked in that order. Each was built by Opus and tested in isolation by Sonnet. L-006 is the slow one: Sonnet's re-test (R1-R18) and four Codex rounds kept finding wrong or dropped claims in the offline rule library. The root cause is that a rule could fire while part of the clause was uncaptured, so the round-4 fix is one central clause-coverage check that fails closed instead of more per-phrase patches.
- Grounding: G1 offline claims 56/56 verified, LLM-claim tamper 2142/2142 caught; G2 235/235 and tamper 8363/8363; G6 100 % of disagreements -> UNKNOWN, 0 VIOLATED leaks (rows above).
- New ticket L-023 (verify_source_quote accepts HEAD/branch/short SHA and non-canonical paths; NUL byte raises). The judge guards its own evidence, but ADR claims (G1) are exposed. Scheduled for Day 5 carry-in.
- Carried over: L-006 (PR #13), L-007 and L-008 fixes, then L-009/L-010 (Day 5), L-023. The plan stays one day behind; no new tickets started.
- Risks: (1) The Codex bot keeps finding phrasing edge cases in the rule library; policy stays fix-the-root-cause and cap at four rounds, then document. (2) Stacked branches mean a late L-006 change forces merges into L-007 and L-008. (3) py3.10 was not available to Sonnet; CI covers it. (4) Offline-mode recall is deliberately low; the benchmark (L-015) will measure it against S2.
