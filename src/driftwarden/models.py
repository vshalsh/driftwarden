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
Ecosystem = Literal[
    "pypi",
    "npm",
    "maven",
    "gradle-plugin",
    "go",
    "nuget",
    "dotnet-sdk",
    "docker",
    "terraform",
    "terraform-provider",
    "terraform-module",
]


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


class DependencyRef(BaseModel):
    """One dependency declared in a manifest (G3 provenance).

    Produced by the non-LLM parsers in ``driftwarden.index.manifests`` and, when
    an LLM asserts "dependency X is used / was added", by the model. Either way
    ``verify_dependency()`` re-parses ``manifest_path`` at ``commit`` to check it.
    """

    model_config = ConfigDict(frozen=True)

    package: str = Field(description="Package / module / image name as the ecosystem names it.")
    version_spec: str | None = Field(
        default=None, description="Version constraint as declared; None when unversioned."
    )
    manifest_path: str = Field(description="Repo-relative POSIX path of the manifest.")
    line: int | None = Field(
        default=None, description="1-based line of the declaration; None if not asserted."
    )
    ecosystem: Ecosystem | None = Field(default=None, description="None = not asserted.")
    scope: str | None = Field(
        default=None, description="E.g. 'dev', 'test', 'optional:docs', 'service:web'."
    )
    commit: str | None = Field(
        default=None, description=f"Full commit SHA, or {WORKTREE!r}; None until resolved."
    )


class GroundingResult(BaseModel):
    """Outcome of a deterministic verifier run on one provenance record."""

    check_id: str = Field(description="Grounding requirement id, e.g. 'G1'.")
    status: GroundingStatus
    reason: str
    provenance: Provenance | DependencyRef
    subject: str | None = Field(default=None, description="What was checked, e.g. 'ADR-0007'.")
