"""Undocumented-decision detection (pipeline step 8).

``detect`` finds technology choices present in the code at one commit that no
ADR mentions, with G2/G3 evidence and G5 introducing commits, and re-verifies
every record before it is reported (fail closed: *Could not verify*).
"""

from driftwarden.undocumented.detect import (
    DETECTED_CATEGORIES,
    IAC_CATEGORY,
    UndocumentedScan,
    adr_mentions,
    detect_undocumented,
    technology_terms,
    verify_undocumented,
)

__all__ = [
    "DETECTED_CATEGORIES",
    "IAC_CATEGORY",
    "UndocumentedScan",
    "adr_mentions",
    "detect_undocumented",
    "technology_terms",
    "verify_undocumented",
]
