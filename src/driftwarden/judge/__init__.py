"""Judgement: claim + evidence -> cited verdict, behind the grounding gate.

``evidence`` collects candidate evidence per claim at one commit (deterministic);
``catalog`` is the built-in technology/category table it resolves claim terms
with; ``judge`` turns claim + evidence into a ``Verdict`` (rules offline, or
rules + model) and re-verifies every cited item (G2/G3) before it is reported.
"""

from driftwarden.judge.evidence import EvidenceSet, Snapshot, collect_evidence, load_snapshot
from driftwarden.judge.judge import (
    JUDGE_SCHEMA,
    Judge,
    build_prompt,
    gate,
    judge_claims,
    llm_verdict,
    rule_verdict,
    verify_evidence,
)

__all__ = [
    "JUDGE_SCHEMA",
    "EvidenceSet",
    "Judge",
    "Snapshot",
    "build_prompt",
    "collect_evidence",
    "gate",
    "judge_claims",
    "llm_verdict",
    "load_snapshot",
    "rule_verdict",
    "verify_evidence",
]
