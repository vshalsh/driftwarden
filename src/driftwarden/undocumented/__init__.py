"""Undocumented-decision detection (pipeline step 8).

``detect`` finds technology choices present in the code at one commit that no
ADR mentions, with G2/G3 evidence and G5 introducing commits, and re-verifies
every record before it is reported (fail closed: *Could not verify*). ``draft``
turns a verified record into a MADR draft that must pass the G5 gate
(``verify_draft``) before it is returned.
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
from driftwarden.undocumented.draft import DraftADR, draft_adr, verify_draft

__all__ = [
    "DETECTED_CATEGORIES",
    "IAC_CATEGORY",
    "DraftADR",
    "UndocumentedScan",
    "adr_mentions",
    "detect_undocumented",
    "draft_adr",
    "technology_terms",
    "verify_draft",
    "verify_undocumented",
]
