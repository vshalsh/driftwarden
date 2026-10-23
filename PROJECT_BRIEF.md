# DriftWarden — Project Brief

**Product Owner:** Vishal Sharma · **PM / gate:** Fable · **Developer + UI/UX:** Opus · **System test:** Sonnet · **Black-box test:** Haiku
**Status:** Intake (awaiting Gate 1) · **Opened:** 2026-10-23 · **Target release:** v0.1.0 on Day 10 (2026-11-02)

## 1. Goal

An open-source agent that keeps a codebase honest to its own architecture decisions.

Teams write their decisions down in ADRs, design docs and READMEs ("PostgreSQL is the only datastore", "services talk through the event bus only", "no cloud SDK outside `adapters/`"). Over time the code quietly diverges, and nobody notices until an audit, an outage or a new hire asks "why do we have two ORMs?". Linters check syntax, and code-review bots look at one diff at a time. **Nothing checks the whole repository, across its history, against what the team said it would do.**

DriftWarden does that, and **every finding it reports carries file, line and commit evidence that a plain Python verifier has confirmed.**

## 2. Users

| Persona | Wants |
|---|---|
| Principal / staff engineer, architect | "Are our ADRs still true? Which ones have rotted, and since when?" |
| Engineering manager / platform lead | A drift score per repo, trend over time, and no surprises in audits |
| Developer opening a PR | A PR comment if the change contradicts an accepted decision, with the exact lines |
| New joiner | "What did this team actually decide, and is it still true?" |

## 3. Scope (v0.1.0)

**In scope**

1. **Decision extraction.** Parse ADRs (Nygard, MADR, free-form markdown) and design docs into structured, testable *claims*. Each claim carries provenance (file, line range, quote, commit).
2. **Evidence collection.** Repo indexer covering source files, dependency manifests (Python, JS/TS, Java/Maven/Gradle, Go, .NET), Dockerfiles, docker-compose, Terraform, Kubernetes YAML and CI config. Includes import-graph extraction and git log/blame.
3. **Judgement.** For each claim the verdict is `HOLDING`, `DRIFTING`, `VIOLATED` or `UNKNOWN`. Every verdict cites evidence. An LLM proposes; deterministic checks dispose.
4. **Undocumented-decision detection.** Find architectural choices present in the code (a new datastore, queue, framework, cloud SDK or service-to-service call) that no ADR covers, and draft the missing ADR from the commits that introduced it.
5. **Drift timeline.** For each violated claim, find the commit where it first stopped holding, by bisecting history.
6. **Outputs:**
   - CLI (`driftwarden scan`)
   - JSON
   - Markdown
   - SARIF (GitHub code scanning)
   - a self-contained HTML report
   - a GitHub Action with PR-diff mode and PR comment
7. **LLM providers:** Anthropic (default), any OpenAI-compatible endpoint (including local Ollama/vLLM), plus an **offline deterministic mode** (rules only, no LLM) so CI works without keys.
8. **Benchmark harness.** Fixture repos with seeded violations, measuring precision, recall and grounding pass rate.

**Out of scope for v0.1.0:** web dashboard or server, a multi-repo org view, auto-fix PRs, IDE plugins, non-git VCS. These are candidates for v0.2.

## 4. Success criteria (checked at Gate 3)

| # | Criterion | Measured by |
|---|---|---|
| S1 | `pip install` + `driftwarden scan .` works on Linux/macOS, Python 3.10–3.13 | CI matrix |
| S2 | On the seeded-fixture benchmark: **precision ≥ 0.90, recall ≥ 0.85** for VIOLATED claims | `bench/` report |
| S3 | **100 % of findings shown as facts are VERIFIED** by the deterministic verifier; everything else is shown as *Could not verify*, never dropped silently | grounding log |
| S4 | Raw LLM citation accuracy (before the verifier filters) **≥ 90 % across ≥ 200 records** — a quality signal, not a gate on its own | grounding log |
| S5 | Offline mode runs with no network and no API key | CI job with network disabled |
| S6 | GitHub Action posts a PR comment and uploads SARIF on a demo repo | demo run link |
| S7 | Scan of a real, well-known OSS repo with ADRs completes, and the report is published in `examples/` | `examples/` |
| S8 | Haiku black-box report has no open Sev-1/Sev-2 | `tests/blackbox/REPORT.md` |
| S9 | HTML report passes WCAG AA contrast in light and dark themes | Sonnet contrast test |

## 5. Grounding regime (Fable's proposal — approve at Gate 1)

| Id | AI output | Provenance it must return | Deterministic verifier |
|---|---|---|---|
| G1 | Decision claim extracted from an ADR | `adr_path, line_start, line_end, quote, commit` | `verify_source_quote()` — `git show <commit>:<path>`, confirm the normalised quote lies inside the line range |
| G2 | Evidence cited for a verdict | `path, line_start, line_end, snippet, commit` | `verify_source_quote()` (same function, applied to code) |
| G3 | "Dependency X is used / was added" | `manifest_path, package, version_spec, commit` | `verify_dependency()` — re-parse the manifest at that commit with a non-LLM parser |
| G4 | "Decision first violated at commit C" | `commit, parent, evidence_ref` | `verify_first_violation()` — evidence present at C, absent at C's parent |
| G5 | Drafted ADR for an undocumented decision | `introducing_commits[], evidence_refs[]` | `verify_commits_exist()` + G2 on every evidence ref |
| G6 | Verdict consistency | — | Cross-record: the same claim on the same commit gives the same verdict in 3 runs; disagreement → `UNKNOWN` |
| G7 | Whole-system accuracy | — | Seeded-fixture benchmark (S2), plus a grounding pass rate across ≥ 200 records (S4) |

**Rule:** a finding whose evidence fails verification is reported under **Could not verify**, with the reason. It is never shown as a violation and never discarded silently.

## 6. Key decisions needing approval at Gate 1

1. **Name:** `driftwarden` (repo, PyPI package and CLI).
2. **Licence:** Apache-2.0 (permissive, includes a patent grant, and is friendly to enterprise adoption).
3. **Stack:** Python 3.10+, Typer CLI, Pydantic models, plain `git` subprocess calls (no GitPython), Jinja2 for the HTML report, and the Anthropic SDK plus an OpenAI-compatible client.
4. **Clean-room boundary:** generic tooling only. No UST client, manufacturing, PII-broker or Frontier concepts or code.
5. **Grounding regime G1–G7 and the thresholds in §4.**

## 7. Delivery cadence

There are ten daily runs (Day 1 = 2026-10-24 … Day 10 = 2026-11-02). Each run is a scheduled session that follows the delivery-crew process:

- Fable plans the day.
- Opus builds each ticket on its own branch.
- Sonnet tests each branch in isolation.
- Fable merges, updates `DELIVERY_LOG.md`, and posts a daily summary on the **Daily log** GitHub issue.

Gates are GitHub issues; Vishal approves by commenting **`approved`** (or `changes: …`). Runs never pass a gate without that comment. When blocked, a run does only pre-gate preparation work.
