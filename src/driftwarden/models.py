"""Core data model (Pydantic v2).

Only the models needed so far are defined here. Evidence, Verdict and the rest
of ARCHITECTURE.md's model are added by later tickets.
"""

from __future__ import annotations

from datetime import date as Date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

WORKTREE = "WORKTREE"
"""Sentinel commit: the text was read from the working tree, not from a commit."""

Status = Literal["proposed", "accepted", "rejected", "deprecated", "superseded", "unknown"]
AdrFormat = Literal["nygard", "madr", "freeform"]
GroundingStatus = Literal["VERIFIED", "MISMATCH"]
ClaimKind = Literal["forbid", "require", "only", "boundary", "free"]
ClaimOrigin = Literal["rule", "hint", "llm"]
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


# --------------------------------------------------------------------------- claims

# Required keys of ``Claim.rule`` per kind. Each must be a non-empty list of
# non-empty strings, except ``free.text`` which is a non-empty string. Extra keys
# (``category``, ``for``, ``action``, ``between``...) are allowed and optional.
RULE_KEYS: dict[str, tuple[str, ...]] = {
    "forbid": ("forbid",),
    "require": ("require",),
    "only": ("only",),
    "boundary": ("target",),  # plus one of "allowed_in" / "via"
    "free": ("text",),
}


def _str_list_ok(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(v, str) and v.strip() for v in value)
    )


def rule_errors(kind: str, rule: Any) -> list[str]:
    """Why ``rule`` is not a valid machine-checkable form for ``kind`` ([] when it is)."""
    if kind not in RULE_KEYS:
        return [f"unknown claim kind {kind!r}"]
    if not isinstance(rule, dict):
        return ["rule must be an object"]
    errors: list[str] = []
    if kind == "free":
        if not (isinstance(rule.get("text"), str) and rule["text"].strip()):
            errors.append("free rule needs a non-empty 'text' string")
        return errors
    for key in RULE_KEYS[kind]:
        if not _str_list_ok(rule.get(key)):
            errors.append(f"{kind} rule needs {key!r} as a non-empty list of strings")
    if kind == "boundary":
        present = [k for k in ("allowed_in", "via") if k in rule]
        if not present:
            errors.append("boundary rule needs 'allowed_in' or 'via'")
        for k in present:
            if not _str_list_ok(rule[k]):
                errors.append(f"boundary rule needs {k!r} as a non-empty list of strings")
    return errors


class Claim(BaseModel):
    """One testable statement derived from a decision (ARCHITECTURE.md).

    ``source`` is the G1 provenance: the ADR file, the line range and the
    verbatim quote the claim rests on, at the commit the ADR was read from.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description='E.g. "ADR-0007.c1".')
    kind: ClaimKind
    subject: str = Field(description='E.g. "datastore", "module:payments".')
    rule: dict[str, Any] = Field(description='Machine-checkable form, e.g. {"only": ["pg"]}.')
    source: Provenance
    decision_id: str = Field(description="Id of the Decision this claim came from.")
    origin: ClaimOrigin = Field(
        default="rule",
        description="rule = offline rule library; hint = ADR front-matter; llm = model.",
    )
    pattern: str | None = Field(default=None, description="Rule-library pattern id, if any.")

    @field_validator("subject")
    @classmethod
    def _subject_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("subject must not be empty")
        return v

    @model_validator(mode="after")
    def _rule_shape(self) -> Claim:
        errors = rule_errors(self.kind, self.rule)
        if errors:
            raise ValueError("; ".join(errors))
        return self


class UnverifiedClaim(BaseModel):
    """A proposed claim that failed G1 or is malformed. Reported under
    *Could not verify* with ``reason``; never judged, never dropped silently."""

    id: str = Field(description='E.g. "ADR-0007.u1".')
    decision_id: str
    origin: ClaimOrigin
    kind: str
    subject: str
    rule: Any = None
    source: Provenance | None = None
    reason: str
    grounding: GroundingResult | None = None
