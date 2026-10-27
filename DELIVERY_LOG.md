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
| L-006 | Claim structuring: decision text → testable claims (forbid/require/only/boundary rules) | Opus→Sonnet | L-006-claims | Claims are typed; each points back to its G1 provenance; the offline rule library covers common patterns | G1 | merged | PR #13 -> 8cd0dee. Sonnet: 14 defects + re-test R1-R18 + final N1-N5; Codex 5 rounds (28 findings fixed). Root-cause fix: central clause-coverage check, fail-closed. G1 offline 56/56, tamper 2142/2142. Remaining recall/precision work in L-024 |
| L-007 | Judge agent: claim + evidence → verdict with citations | Opus→Sonnet | L-007-judge | Verdicts cite evidence; unverified evidence → *Could not verify* | G2 | merged | PR #15 -> f599636. Sonnet 2 rounds (D-L007-2..9); Codex 3 rounds (19 findings fixed, incl. gate bypass on failed rule verdict, per-term cap, structural scopes). G2 282/282, tamper 3400/3400 (Opus) and 8363/8363 (Sonnet). Further hardening in L-025. Incident: a stale-index commit reverted L-006 files; caught by Codex, restored in 616c085 |
| L-008 | Consistency runner (3× vote, disagreement → UNKNOWN) | Opus→Sonnet | L-008-consistency | Deterministic on the offline path; vote recorded | G6 | merged | PR #16 -> 361df6f. Sonnet: S1-S4 fixed; tests updated for the merged L-007 gate behaviour. G6: 3 seeds x 336 claim runs, 184/184 disagreements -> UNKNOWN, 0 VIOLATED leaks. CI green, Codex clean |
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
| L-023 | Harden `verify_source_quote`: reject HEAD/branch/short-SHA commits and non-canonical paths (`a/b.py/`, `./a/b.py`); NUL byte must not raise (Sonnet D-L007-1, D-L007-7) | Opus->Sonnet | L-023-verify-hardening | Only full pinned SHAs and canonical paths verify; never raises; G1/G2 tamper still 100 % | G1, G2 | merged | PR #17 -> f42f963. Only full pinned SHAs and canonical paths verify; verifier never raises; 70 new tests; G1/G2 tamper 100 %. CI green (one merge-conflict test marker fixed), Codex clean |
| L-024 | Offline rule-library hardening after L-006: conditions, permission vs obligation, rationale whitelist (fail-closed), harmless decorations keep their claim | Opus->Sonnet | L-024-rules-hardening | 0 leaked scope/condition claims on Sonnet generator (231k sentences; main 12,616); over-drop <= 5 % (main 70.7 %); fixtures 12/12; G1 tamper 100 % | G1 | in-test | PR #18. Sonnet round 1: 9 defects fixed (0 leaks, over-drop 3.2 %). Codex round 1: 3 P2 in fix |
| L-025 | Judge hardening after Codex on L-007: from-imports, Terraform literals, bare-dir targets, `between`/call-qualified claims -> UNKNOWN, claim-field audit | Opus->Sonnet | L-025-judge-hardening | No false VIOLATED from an unevaluated qualifier; G2/G3 100 % | G2 | in-test | PR #19. G2 281/281, tamper 3400/3400 (Opus). Sonnet test and Codex round 1 (1 P2) in progress |
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
| 2026-10-27 | G1/G2 verifier strictness (L-023 @f42f963) | 70 hostile provenance cases x commit and WORKTREE; G1 130 mutations/decision; G2 3400 mutations | 100 % rejected/caught | 0 | tests/test_l023_verify.py |

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


#
#
#
 
D
a
y
 
4
 
—
 
2
0
2
6
-
1
0
-
2
7
 
(
F
a
b
l
e
)


-
 
G
a
t
e
s
:
 
G
-
1
 
a
n
d
 
G
-
2
 
r
e
m
a
i
n
 
a
p
p
r
o
v
e
d
.
 
T
i
c
k
e
t
s
 
m
e
r
g
e
 
t
h
r
o
u
g
h
 
t
h
e
i
r
 
P
R
s
.


-
 
*
*
M
e
r
g
e
d
:
*
*
 
L
-
0
0
5
 
(
#
1
2
)
,
 
L
-
0
0
6
 
(
#
1
3
)
,
 
L
-
0
0
7
 
(
#
1
5
)
,
 
L
-
0
0
8
 
(
#
1
6
)
,
 
L
-
0
2
3
 
(
#
1
7
)
.
 
T
h
i
s
 
c
o
v
e
r
s
 
t
h
e
 
D
a
y
-
3
 
c
a
r
r
y
-
o
v
e
r
 
(
L
-
0
0
5
,
 
L
-
0
0
6
)
 
a
n
d
 
t
h
e
 
w
h
o
l
e
 
D
a
y
-
4
 
p
l
a
n
 
(
L
-
0
0
7
,
 
L
-
0
0
8
)
,
 
p
l
u
s
 
L
-
0
2
3
,
 
a
 
v
e
r
i
f
i
e
r
 
h
o
l
e
 
S
o
n
n
e
t
 
f
o
u
n
d
 
w
h
i
l
e
 
t
e
s
t
i
n
g
 
L
-
0
0
7
.
 
E
a
c
h
 
w
a
s
 
b
u
i
l
t
 
b
y
 
O
p
u
s
,
 
t
e
s
t
e
d
 
i
n
 
i
s
o
l
a
t
i
o
n
 
b
y
 
S
o
n
n
e
t
,
 
a
n
d
 
r
e
v
i
e
w
e
d
 
b
y
 
t
h
e
 
C
o
d
e
x
 
b
o
t
;
 
C
I
 
g
r
e
e
n
 
(
p
y
3
.
1
0
-
3
.
1
3
,
 
m
a
c
O
S
)
 
b
e
f
o
r
e
 
e
v
e
r
y
 
m
e
r
g
e
.


-
 
*
*
I
n
 
f
l
i
g
h
t
:
*
*
 
L
-
0
2
4
 
(
#
1
8
,
 
r
u
l
e
-
l
i
b
r
a
r
y
 
h
a
r
d
e
n
i
n
g
)
 
a
n
d
 
L
-
0
2
5
 
(
#
1
9
,
 
j
u
d
g
e
 
h
a
r
d
e
n
i
n
g
)
.
 
B
o
t
h
 
a
r
e
 
b
u
i
l
t
 
a
n
d
 
S
o
n
n
e
t
-
t
e
s
t
e
d
;
 
e
a
c
h
 
h
a
s
 
a
n
 
o
p
e
n
 
C
o
d
e
x
 
r
o
u
n
d
 
b
e
i
n
g
 
f
i
x
e
d
.
 
T
h
e
y
 
a
r
e
 
t
h
e
 
f
o
l
l
o
w
-
u
p
s
 
t
o
 
t
h
e
 
C
o
d
e
x
 
a
n
d
 
S
o
n
n
e
t
 
f
i
n
d
i
n
g
s
 
t
h
a
t
 
k
e
p
t
 
a
r
r
i
v
i
n
g
 
o
n
 
L
-
0
0
6
 
a
n
d
 
L
-
0
0
7
.


-
 
*
*
D
e
f
e
c
t
s
:
*
*
 
S
o
n
n
e
t
 
f
o
u
n
d
 
1
7
 
(
L
-
0
0
5
)
,
 
1
4
 
+
 
1
8
 
+
 
3
3
 
(
L
-
0
0
6
)
,
 
7
 
+
 
2
 
(
L
-
0
0
7
)
,
 
4
 
(
L
-
0
0
8
)
,
 
9
 
(
L
-
0
2
4
)
 
i
n
 
i
t
s
 
o
w
n
 
s
u
i
t
e
s
,
 
a
l
l
 
r
o
u
t
e
d
 
b
a
c
k
 
t
o
 
O
p
u
s
 
t
h
r
o
u
g
h
 
F
a
b
l
e
.
 
C
o
d
e
x
 
r
a
i
s
e
d
 
a
b
o
u
t
 
8
0
 
P
2
/
P
1
 
f
i
n
d
i
n
g
s
 
a
c
r
o
s
s
 
t
h
e
 
P
R
s
;
 
a
l
l
 
f
i
x
e
d
 
e
x
c
e
p
t
 
d
o
c
u
m
e
n
t
e
d
 
k
n
o
w
n
 
l
i
m
i
t
s
 
(
L
-
0
0
5
 
D
1
7
:
 
e
x
a
c
t
-
s
t
r
i
n
g
 
k
e
y
 
r
e
d
a
c
t
i
o
n
 
o
n
l
y
;
 
r
u
l
e
-
l
i
b
r
a
r
y
 
l
e
x
i
c
a
l
 
l
i
m
i
t
s
 
i
n
 
t
h
e
 
`
r
u
l
e
s
.
p
y
`
 
d
o
c
s
t
r
i
n
g
)
.


-
 
*
*
G
r
o
u
n
d
i
n
g
:
*
*
 
G
1
 
o
f
f
l
i
n
e
 
5
6
/
5
6
 
a
n
d
 
t
a
m
p
e
r
 
2
1
4
2
/
2
1
4
2
;
 
G
2
 
2
8
2
/
2
8
2
 
a
n
d
 
t
a
m
p
e
r
 
3
4
0
0
/
3
4
0
0
 
(
a
u
t
h
o
r
)
 
a
n
d
 
8
3
6
3
/
8
3
6
3
 
(
S
o
n
n
e
t
)
;
 
G
6
 
1
8
4
/
1
8
4
 
d
i
s
a
g
r
e
e
m
e
n
t
s
 
-
>
 
U
N
K
N
O
W
N
,
 
0
 
V
I
O
L
A
T
E
D
 
l
e
a
k
s
;
 
v
e
r
i
f
i
e
r
 
s
t
r
i
c
t
n
e
s
s
 
(
L
-
0
2
3
)
 
1
0
0
 
%
.
 
R
o
w
s
 
a
b
o
v
e
.


-
 
*
*
D
e
s
i
g
n
 
d
e
c
i
s
i
o
n
s
 
m
a
d
e
 
t
o
d
a
y
:
*
*
 
i
n
 
L
L
M
 
m
o
d
e
 
a
 
d
e
c
i
d
e
d
 
r
u
l
e
 
v
e
r
d
i
c
t
 
s
t
a
n
d
s
 
a
n
d
 
t
h
e
 
m
o
d
e
l
'
s
 
p
r
o
p
o
s
a
l
 
i
s
 
o
n
l
y
 
a
 
n
o
t
e
;
 
a
 
f
a
i
l
e
d
 
r
u
l
e
 
g
a
t
e
 
s
t
a
y
s
 
*
C
o
u
l
d
 
n
o
t
 
v
e
r
i
f
y
*
 
(
t
h
e
 
m
o
d
e
l
 
c
a
n
n
o
t
 
o
v
e
r
r
i
d
e
 
i
t
)
;
 
a
n
y
 
c
l
a
i
m
 
q
u
a
l
i
f
i
e
r
 
t
h
e
 
j
u
d
g
e
 
c
a
n
n
o
t
 
e
v
a
l
u
a
t
e
 
g
i
v
e
s
 
U
N
K
N
O
W
N
,
 
n
e
v
e
r
 
V
I
O
L
A
T
E
D
;
 
o
f
f
l
i
n
e
 
r
u
l
e
 
c
l
a
i
m
s
 
f
a
i
l
 
c
l
o
s
e
d
 
(
a
 
q
u
a
l
i
f
i
e
r
 
t
h
e
 
r
u
l
e
s
 
c
a
n
n
o
t
 
r
e
p
r
e
s
e
n
t
 
d
r
o
p
s
 
t
h
e
 
c
l
a
i
m
)
.


-
 
*
*
P
r
o
c
e
s
s
 
i
n
c
i
d
e
n
t
s
:
*
*
 
(
1
)
 
A
 
c
o
m
m
i
t
 
o
n
 
t
h
e
 
L
-
0
0
7
 
b
r
a
n
c
h
 
s
i
l
e
n
t
l
y
 
r
e
v
e
r
t
e
d
 
m
e
r
g
e
d
 
L
-
0
0
6
 
f
i
l
e
s
 
b
e
c
a
u
s
e
 
a
g
e
n
t
 
w
o
r
k
t
r
e
e
s
 
s
h
a
r
e
 
b
r
a
n
c
h
 
r
e
f
s
 
a
n
d
 
o
n
e
 
h
a
d
 
a
 
s
t
a
l
e
 
i
n
d
e
x
.
 
T
h
e
 
C
o
d
e
x
 
b
o
t
 
c
a
u
g
h
t
 
i
t
;
 
t
h
e
 
f
i
l
e
s
 
w
e
r
e
 
r
e
s
t
o
r
e
d
 
b
y
t
e
-
f
o
r
-
b
y
t
e
 
f
r
o
m
 
m
a
i
n
 
a
n
d
 
t
h
e
 
p
r
o
c
e
s
s
 
n
o
w
 
s
t
a
g
e
s
 
f
i
l
e
s
 
b
y
 
n
a
m
e
 
o
n
l
y
.
 
(
2
)
 
M
y
 
m
e
r
g
e
 
o
f
 
m
a
i
n
 
i
n
t
o
 
L
-
0
2
3
 
c
l
e
a
r
e
d
 
a
 
k
n
o
w
n
-
d
e
f
e
c
t
 
m
a
r
k
e
r
,
 
w
h
i
c
h
 
f
a
i
l
e
d
 
C
I
 
u
n
t
i
l
 
r
e
s
t
o
r
e
d
.
 
(
3
)
 
A
 
m
a
c
O
S
-
o
n
l
y
 
t
e
s
t
 
f
a
i
l
u
r
e
 
(
n
o
n
-
U
T
F
-
8
 
f
i
l
e
 
n
a
m
e
s
)
 
w
a
s
 
f
i
x
e
d
 
b
y
 
p
r
o
b
i
n
g
 
t
h
e
 
f
i
l
e
s
y
s
t
e
m
.


-
 
*
*
C
a
r
r
i
e
d
 
o
v
e
r
:
*
*
 
L
-
0
2
4
 
a
n
d
 
L
-
0
2
5
 
m
e
r
g
e
s
;
 
L
-
0
0
9
/
L
-
0
1
0
 
(
D
a
y
-
5
 
p
l
a
n
)
 
n
o
t
 
s
t
a
r
t
e
d
.
 
T
h
e
 
p
l
a
n
 
i
s
 
n
o
w
 
*
*
t
w
o
 
d
a
y
s
 
b
e
h
i
n
d
*
*
:
 
D
a
y
s
 
3
 
a
n
d
 
4
 
w
e
r
e
 
s
p
e
n
t
 
c
l
e
a
r
i
n
g
 
r
e
v
i
e
w
 
f
i
n
d
i
n
g
s
 
o
n
 
L
-
0
0
5
 
t
o
 
L
-
0
0
8
.
 
C
a
u
s
e
:
 
e
a
c
h
 
r
e
v
i
e
w
 
r
o
u
n
d
 
e
x
p
o
s
e
d
 
a
 
r
a
r
e
r
 
p
h
r
a
s
i
n
g
 
e
d
g
e
 
c
a
s
e
 
i
n
 
t
h
e
 
o
f
f
l
i
n
e
 
r
u
l
e
 
l
i
b
r
a
r
y
,
 
a
n
d
 
I
 
c
h
o
s
e
 
p
r
e
c
i
s
i
o
n
 
(
f
i
x
 
t
h
e
 
r
o
o
t
 
c
a
u
s
e
)
 
o
v
e
r
 
s
p
e
e
d
.
 
M
i
n
o
r
 
f
o
l
l
o
w
-
u
p
s
:
 
s
t
a
l
e
 
d
o
c
s
t
r
i
n
g
 
a
n
d
 
w
a
s
t
e
d
 
m
o
d
e
l
 
c
a
l
l
s
 
i
n
 
`
c
o
n
s
i
s
t
e
n
c
y
.
p
y
`
 
w
h
e
n
 
a
 
r
u
l
e
 
g
a
t
e
 
f
a
i
l
s
;
 
D
-
L
0
0
7
-
9
 
(
a
 
s
e
r
v
i
c
e
 
i
n
 
a
 
d
i
r
e
c
t
o
r
y
 
n
a
m
e
d
 
e
x
a
c
t
l
y
 
`
d
o
c
s
/
`
 
o
r
 
`
c
i
/
`
 
i
s
 
c
l
a
s
s
e
d
 
n
o
n
-
p
r
o
d
u
c
t
i
o
n
)
 
a
c
c
e
p
t
e
d
 
a
s
 
a
 
d
e
s
i
g
n
 
t
r
a
d
e
-
o
f
f
.


-
 
*
*
R
i
s
k
s
:
*
*
 
(
1
)
 
S
c
h
e
d
u
l
e
:
 
6
 
p
l
a
n
 
d
a
y
s
 
r
e
m
a
i
n
 
f
o
r
 
8
 
p
l
a
n
 
d
a
y
s
 
o
f
 
t
i
c
k
e
t
s
;
 
D
a
y
 
5
 
s
h
o
u
l
d
 
s
t
a
r
t
 
L
-
0
0
9
 
a
n
d
 
L
-
0
1
0
 
b
u
t
 
a
l
l
o
w
 
a
 
h
a
r
d
e
n
i
n
g
 
b
u
f
f
e
r
;
 
i
f
 
i
t
 
s
l
i
p
s
 
a
g
a
i
n
 
I
 
w
i
l
l
 
r
e
c
o
m
m
e
n
d
 
c
u
t
t
i
n
g
 
L
-
0
1
8
 
(
r
e
a
l
 
O
S
S
 
d
e
m
o
)
 
o
r
 
t
r
i
m
m
i
n
g
 
L
-
0
1
4
 
s
c
o
p
e
 
a
n
d
 
w
i
l
l
 
r
a
i
s
e
 
i
t
 
o
n
 
t
h
e
 
D
a
i
l
y
 
l
o
g
.
 
(
2
)
 
O
f
f
l
i
n
e
 
r
e
c
a
l
l
 
o
n
 
f
r
e
e
-
f
o
r
m
 
A
D
R
s
 
i
s
 
d
e
l
i
b
e
r
a
t
e
l
y
 
l
o
w
;
 
t
h
e
 
b
e
n
c
h
m
a
r
k
 
(
L
-
0
1
5
)
 
w
i
l
l
 
m
e
a
s
u
r
e
 
i
t
 
a
g
a
i
n
s
t
 
S
2
 
(
p
r
e
c
i
s
i
o
n
 
>
=
 
0
.
9
0
,
 
r
e
c
a
l
l
 
>
=
 
0
.
8
5
)
.
 
(
3
)
 
m
a
c
O
S
 
C
I
 
t
a
k
e
s
 
a
b
o
u
t
 
2
7
 
m
i
n
u
t
e
s
 
p
e
r
 
r
u
n
,
 
w
h
i
c
h
 
s
l
o
w
s
 
e
v
e
r
y
 
m
e
r
g
e
;
 
c
o
n
s
i
d
e
r
 
c
a
c
h
i
n
g
 
o
r
 
t
r
i
m
m
i
n
g
 
t
h
e
 
m
a
c
O
S
 
j
o
b
 
t
o
 
a
 
s
m
o
k
e
 
s
u
b
s
e
t
 
(
n
e
e
d
s
 
y
o
u
r
 
c
a
l
l
,
 
i
t
 
c
h
a
n
g
e
s
 
C
I
)
.

