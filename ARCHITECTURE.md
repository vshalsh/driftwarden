# DriftWarden — Architecture

> Status: proposed (Gate 2). Owner: Fable. Implemented by Opus.

## Principle: the LLM proposes, deterministic code disposes

The language model is used for the parts that need judgement: reading prose decisions, turning them into testable claims, weighing evidence, and drafting ADRs. **Every fact the model asserts is re-checked by deterministic code before anything reaches the user.** A finding that fails the check is shown as *Could not verify*. It is never shown as a violation and never dropped silently.

## Pipeline

```
           ┌──────────────┐   ┌───────────────┐   ┌────────────┐
 repo ───► │ 1 Discover   │──►│ 2 Extract     │──►│ 3 Structure│──► Claims (+G1 provenance)
 (git)     │ ADRs, docs   │   │ decisions     │   │ claims     │
           └──────────────┘   └───────────────┘   └────────────┘
                                                         │
           ┌──────────────┐   ┌───────────────┐          ▼
 repo ───► │ 4 Index      │──►│ 5 Collect     │──► Evidence (+G2/G3 provenance)
           │ files, deps, │   │ evidence per  │          │
           │ imports, IaC │   │ claim         │          ▼
           └──────────────┘   └───────────────┘   ┌────────────┐
                                                  │ 6 Judge    │──► Verdicts (cited)
                                                  │ (3× vote)  │          │
                                                  └────────────┘          ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │ 7 GROUNDING GATE — deterministic verifiers G1–G5          │
                    │   VERIFIED → findings      MISMATCH → "Could not verify" │
                    └──────────────────────────────────────────────────────────┘
                                   │                        │
             ┌─────────────────────┼────────────────┐       │
             ▼                     ▼                ▼       ▼
     8 Undocumented        9 Timeline (bisect,   10 Reporters: JSON · Markdown ·
       decisions →           G4 verified)           SARIF · HTML · PR comment
       ADR drafts (G5)
```

## Package layout

```
src/driftwarden/
  cli.py                 # Typer app: scan, version, verify, bench
  config.py              # driftwarden.toml / [tool.driftwarden] in pyproject
  models.py              # Pydantic: Provenance, Decision, Claim, Evidence, Verdict, Finding, Report
  git.py                 # thin subprocess wrapper: show, log, blame, rev-parse, diff
  discover/adr.py        # find + parse ADRs (Nygard, MADR, free-form)
  index/files.py         # file walk, language detection, ignore rules
  index/imports.py       # import-graph per language
  index/manifests/*.py   # one parser per ecosystem (non-LLM)
  claims/rules.py        # offline rule library (forbid / require / only / boundary)
  claims/structure.py    # LLM structuring with JSON-schema output
  llm/base.py            # Provider protocol
  llm/anthropic.py, llm/openai_compat.py, llm/offline.py
  judge/evidence.py      # deterministic evidence per claim, at one commit (G2/G3 provenance)
  judge/catalog.py       # technology/category table (datastore, queue, cloud SDK...)
  judge/judge.py         # verdicts with citations + grounding gate
  judge/consistency.py   # 3× vote
  undocumented/detect.py, undocumented/draft.py
  timeline/bisect.py
  grounding/verify.py    # verify_source_quote, verify_dependency, verify_first_violation, verify_commits_exist
  grounding/ledger.py    # writes logs/grounding/*.jsonl + summary
  report/json.py, report/markdown.py, report/sarif.py, report/html/ (Jinja2 + tokens.css)
action/                  # GitHub Action (composite) + PR-comment script
bench/                   # seeded fixture repos + runner
tests/                   # Sonnet's suite; tests/blackbox/REPORT.md by Haiku
```

## Core data model

```python
class Provenance:      # attached to every AI-produced statement
    path: str; line_start: int; line_end: int
    commit: str        # full SHA the quote was taken from
    quote: str         # verbatim text the model relied on

class Claim:           # one testable statement derived from a decision
    id: str            # e.g. "ADR-0007.c1"
    kind: Literal["forbid", "require", "only", "boundary", "free"]
    subject: str       # e.g. "datastore", "module:payments"
    rule: dict         # machine-checkable form, e.g. {"only": ["postgresql"]}
    source: Provenance # G1

class Evidence:
    kind: Literal["code", "dependency", "import", "infra", "commit"]
    ref: Provenance    # G2
    dependency: DependencyRef | None   # G3

class Verdict:
    claim_id: str
    status: Literal["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN"]
    evidence: list[Evidence]
    grounding: Literal["VERIFIED", "MISMATCH", "PARTIAL"]
    reasons: list[str]  # verifier messages on mismatch
```

## Two run modes

| Mode | LLM | Use |
|---|---|---|
| `offline` | none | CI without secrets. Claims come from the rule library plus front-matter hints in ADRs; judgement is purely deterministic. Lower recall, very high precision. |
| `llm` (default when a key is present) | Anthropic or OpenAI-compatible | Free-form decisions, nuanced verdicts, and ADR drafting. All output still passes the grounding gate. |

## Cost control

The LLM layer logs tokens and cost per call to `logs/llm/*.jsonl`. Evidence collection is deterministic and narrows the context so the model sees only the candidate snippets for each claim, never the whole repo. PR mode scans only claims touched by the diff.
