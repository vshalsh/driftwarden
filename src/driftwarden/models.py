"""Core data model (Pydantic v2).

Only the models needed so far are defined here; Finding, Report and the rest of
ARCHITECTURE.md's model are added by later tickets.
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
    provenance: Provenance | DependencyRef | None = Field(
        default=None, description="None only for checks on bare commit ids (G5)."
    )
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


# --------------------------------------------------------------------------- evidence

EvidenceKind = Literal["code", "dependency", "import", "infra", "commit"]
EvidenceRelation = Literal[
    "forbidden",  # forbid: a forbidden technology is present
    "required",  # require: the required technology is present
    "allowed",  # only: the allowed member is present
    "alternative",  # only / require: another member of the same category is present
    "outside_boundary",  # boundary: the target is used outside the allowed paths
    "inside_boundary",  # boundary: the target is used inside the allowed paths
    "keyword",  # a source line mentioning a claim term (context for the model only)
]
VerdictStatus = Literal["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN"]
VerdictGrounding = Literal["VERIFIED", "MISMATCH", "PARTIAL"]
VerdictOrigin = Literal["rule", "llm"]


class Evidence(BaseModel):
    """One piece of evidence for (or against) a claim, with G2/G3 provenance.

    ``ref`` is the G2 provenance: the exact source lines (``quote`` = snippet) at
    ``commit``. A dependency or infra item also carries ``dependency``, the G3
    provenance that ``verify_dependency()`` re-parses.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description='Id within the claim\'s candidate set, e.g. "e3".')
    kind: EvidenceKind
    ref: Provenance
    dependency: DependencyRef | None = None
    relation: EvidenceRelation | None = None
    technology: str | None = Field(default=None, description="Catalog id or literal term.")
    production: bool = Field(
        default=True, description="False for test files and dev/test/build-scoped dependencies."
    )
    detail: str = Field(default="", description='Human summary, e.g. "imports pymongo".')


class RunVote(BaseModel):
    """One judge run inside a consistency vote (G6)."""

    run: int = Field(description="1-based run number.")
    status: VerdictStatus
    grounding: VerdictGrounding
    origin: VerdictOrigin
    proposed_status: VerdictStatus | None = None
    error: str | None = Field(
        default=None, description="LLMError of this run (the run then counts as UNKNOWN)."
    )
    reasons: list[str] = Field(default_factory=list, description="This run's gate reasons.")
    evidence: list[Evidence] = Field(
        default_factory=list, description="What this run cited (shown as data, not as fact)."
    )


ConsistencyBasis = Literal["vote", "deterministic"]


class Consistency(BaseModel):
    """The G6 record of a voted verdict: how many runs, what each said, did they agree.

    ``basis="deterministic"``: the rules decided the claim (or the judge is
    offline), so the result cannot change between runs; one run stands for all
    ``runs`` and ``executed`` is 1 (cost control, see ``judge.consistency``).
    """

    runs: int = Field(description="Runs requested.")
    executed: int = Field(description="Runs actually made.")
    basis: ConsistencyBasis
    agreement: bool
    votes: list[RunVote]


class Verdict(BaseModel):
    """The judgement on one claim (ARCHITECTURE.md).

    Invariants (enforced): a verdict whose grounding is not VERIFIED has status
    UNKNOWN and is shown as *Could not verify*, never as a violation; a HOLDING /
    DRIFTING / VIOLATED verdict from the model, and every DRIFTING / VIOLATED
    verdict, cites at least one evidence item.
    """

    claim_id: str
    status: VerdictStatus
    evidence: list[Evidence] = Field(default_factory=list)
    grounding: VerdictGrounding = "VERIFIED"
    reasons: list[str] = Field(
        default_factory=list, description="Verifier messages on mismatch (why not verified)."
    )
    rationale: str = Field(default="", description="Why this status (rule text or model).")
    origin: VerdictOrigin = "rule"
    proposed_status: VerdictStatus | None = Field(
        default=None, description="What the rules/model proposed before the grounding gate."
    )
    commit: str = Field(default="", description=f"Commit judged (full SHA or {WORKTREE!r}).")
    notes: list[str] = Field(default_factory=list)
    checks: list[GroundingResult] = Field(
        default_factory=list, description="Every G2/G3 verifier result behind this verdict."
    )
    consistency: Consistency | None = Field(
        default=None, description="G6 vote record; None for a single, unvoted judgement."
    )

    @property
    def could_not_verify(self) -> bool:
        return self.grounding != "VERIFIED"

    @property
    def display_status(self) -> str:
        return "Could not verify" if self.could_not_verify else self.status

    @model_validator(mode="after")
    def _invariants(self) -> Verdict:
        if self.grounding != "VERIFIED" and self.status != "UNKNOWN":
            raise ValueError("a verdict that is not VERIFIED must have status UNKNOWN")
        if self.status in ("DRIFTING", "VIOLATED") and not self.evidence:
            raise ValueError(f"a {self.status} verdict must cite evidence")
        if self.grounding != "VERIFIED" and not self.reasons:
            raise ValueError("a verdict that is not VERIFIED needs reasons")
        return self


# --------------------------------------------------------------------------- undocumented

UndocumentedStatus = Literal["UNDOCUMENTED", "UNKNOWN"]


class Introduction(BaseModel):
    """Where one evidence item's technology entered its file (G5 provenance).

    ``ref`` is the line(s) at ``commit`` that bring the technology into
    ``ref.path``; at every one of ``parents`` the file has no such line (or does
    not exist). ``verify_undocumented`` re-checks all of that.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(description="The evidence item this introduction is for.")
    commit: str = Field(description="Full SHA of the introducing commit.")
    parents: list[str] = Field(default_factory=list, description="Its parents (full SHAs).")
    ref: Provenance = Field(description="The introducing line(s), at ``commit``.")


class UndocumentedDecision(BaseModel):
    """A technology choice present in the code that no ADR covers (pipeline step 8).

    ``evidence`` carries G2 (and, for manifest items, G3) provenance at
    ``commit``; ``introductions`` / ``introducing_commits`` carry the G5
    provenance a drafted ADR will cite. Invariant (enforced): a record that is not
    VERIFIED has status UNKNOWN and is shown as *Could not verify* with reasons,
    never as a finding.
    """

    id: str = Field(description='E.g. "UD-cache-redis".')
    technology: str = Field(description="Catalog technology id (or Terraform provider name).")
    category: str = Field(description='Catalog category, or "iac-provider".')
    title: str = ""
    status: UndocumentedStatus = "UNDOCUMENTED"
    commit: str = Field(description="Full SHA of the commit scanned.")
    evidence: list[Evidence] = Field(default_factory=list)
    introductions: list[Introduction] = Field(default_factory=list)
    introducing_commits: list[str] = Field(
        default_factory=list, description="Distinct introducing commits, oldest first."
    )
    searched_terms: list[str] = Field(
        default_factory=list, description="Terms looked for in the ADRs (none matched)."
    )
    grounding: VerdictGrounding = "VERIFIED"
    reasons: list[str] = Field(default_factory=list, description="Why not verified.")
    checks: list[GroundingResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def could_not_verify(self) -> bool:
        return self.grounding != "VERIFIED"

    @property
    def display_status(self) -> str:
        return "Could not verify" if self.could_not_verify else "Undocumented"

    @model_validator(mode="after")
    def _invariants(self) -> UndocumentedDecision:
        if self.grounding != "VERIFIED" and self.status != "UNKNOWN":
            raise ValueError("an undocumented decision that is not VERIFIED must be UNKNOWN")
        if self.grounding != "VERIFIED" and not self.reasons:
            raise ValueError("an undocumented decision that is not VERIFIED needs reasons")
        if self.status == "UNDOCUMENTED" and not (self.evidence and self.introducing_commits):
            raise ValueError("an UNDOCUMENTED record must cite evidence and introducing commits")
        return self
