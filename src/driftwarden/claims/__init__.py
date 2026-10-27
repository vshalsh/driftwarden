"""Claim structuring: decision text -> typed, testable claims with G1 provenance.

``rules`` is the offline rule library (phrase patterns + front-matter hints);
``structure`` is the dispatcher (offline = rules; llm = rules + model, merged,
de-duplicated, every claim re-checked by ``verify_source_quote``).
"""

from driftwarden.claims.rules import PATTERNS, RULES, extract_rule_claims, match_sentence
from driftwarden.claims.structure import (
    CLAIMS_SCHEMA,
    ClaimSet,
    build_prompt,
    resolve_mode,
    structure_decision,
    structure_scan,
)

__all__ = [
    "CLAIMS_SCHEMA",
    "PATTERNS",
    "RULES",
    "ClaimSet",
    "build_prompt",
    "extract_rule_claims",
    "match_sentence",
    "resolve_mode",
    "structure_decision",
    "structure_scan",
]
