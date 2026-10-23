"""Core data model (Pydantic v2).

Only the models needed so far are defined here. Claim, Evidence, Verdict and the
rest of ARCHITECTURE.md's model are added by later tickets.
"""

from __future__ import annotations

from datetime import date as Date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

WORKTREE = "WORKTREE"
"""Sentinel commit: the text was read from the working tree, not from a commit."""

Status = Literal["proposed", "accepted", "rejected", "deprecated", "superseded", "unknown"]
AdrFormat = Literal["nygard", "madr", "freeform"]
GroundingStatus = Literal["VERIFIED", "MISMATCH"]


class Provenance(BaseModel):
    """Where a statement came from. Attached to every AI-produced statement."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(description="Repo-relative POSIX path.")
    line_start: int = Field(description="1-based, inclusive.")
    line_end: int = Field(description="1-based, inclusive.")
    commit: str = Field(description=f"Full commit SHA, or {WORKTREE!r}.")
    quote: str = Field(description="Verbatim text the statement relies on.")
    # Odd ranges (start > end, out of bounds) are deliberately NOT rejected here:
    # they are a grounding MISMATCH the verifier must report, not a load error.


class Decision(BaseModel):
    """One architecture decision extracted from an ADR file."""

    id: str
    title: str
    status: Status
    date: Date | None = None
    context: str | None = None
    decision_text: str
    consequences: str | None = None
    source: Provenance
    format: AdrFormat
    superseded_by: str | None = None
    chosen_option: str | None = None


class GroundingResult(BaseModel):
    """Outcome of a deterministic verifier run on one provenance record."""

    check_id: str = Field(description="Grounding requirement id, e.g. 'G1'.")
    status: GroundingStatus
    reason: str
    provenance: Provenance
    subject: str | None = Field(default=None, description="What was checked, e.g. 'ADR-0007'.")
