"""Consistency runner (pipeline step 6, G6): judge each claim N times, then vote.

``ConsistencyRunner(judge, runs=3).run(claim)`` collects the claim's evidence
once at the judge's commit, runs ``Judge.judge`` ``runs`` times on that same
evidence (each run a fresh, independent model call) and votes:

==============================  ==============================================
runs                            voted verdict
==============================  ==============================================
any run's gate says MISMATCH    ``UNKNOWN`` / ``MISMATCH`` (*Could not verify*)
                                with every run's verifier reasons, prefixed
                                ``run k:``; the unverified evidence stays
                                listed. Never a violation.
any run raised an LLMError      ``UNKNOWN`` (that run counts as UNKNOWN), with
                                ``run k failed: <error>`` and the
                                ``inconsistent across runs: ...`` reason.
statuses differ                 ``UNKNOWN`` with the reason
                                ``inconsistent across runs: HOLDING,VIOLATED,HOLDING``.
all runs agree                  that status. Evidence = the agreeing runs'
                                evidence (deduplicated), re-verified by the
                                same L-007 ``gate`` (G2/G3); a failure there
                                makes it *Could not verify* as usual.
==============================  ==============================================

Every voted verdict carries ``Verdict.consistency``: runs requested, runs made,
each run's status / grounding / error / citations, and whether they agreed.

Cost control (decision). The result cannot change between runs when
deterministic code decides it, so those claims are judged **once**:

* offline mode (rules only, no model), and
* llm mode when the rules reach a decided, gate-VERIFIED verdict (L-007
  precedence: the rule verdict stands whatever the model says, and an LLMError
  keeps it too). Run 1 still makes its one model call, so the model's proposal
  stays recorded in ``notes`` and the ledger as in L-007; runs 2..N are skipped.

Those verdicts get ``consistency.basis = "deterministic"``, ``executed = 1``.
``dedupe_deterministic=False`` makes every claim take all N runs (the tests use
it to show that offline runs are identical). If the rule verdict fails its gate
the judge falls back to the model, so the claim is voted like any other.

Independence. The runner never reuses a reply: each run calls
``provider.complete_json`` itself, through a per-run wrapper that labels the
cost-log purpose ``judge:<claim>#run<k>/<N>`` and records the run's LLMError.
The L-005 providers keep no response cache and send no temperature or seed, so
each call is an independent sample at the provider's default sampling.

Ledger (G6). Each voted claim (``basis="vote"``) adds one ``G6`` row via
``grounding.ledger``: VERIFIED when all runs agreed (same status and grounding,
no errors), MISMATCH otherwise, with the claim's G1 provenance as the record it
is about. ``Ledger.check_rate("G6")`` / ``ConsistencyRunner.summary()`` give the
consistency rate. Deterministic claims add no G6 row (nothing was voted), and
the re-verification of a voted verdict's evidence is not logged again (each run
already logged its own G2/G3 results).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from driftwarden.grounding.ledger import Ledger
from driftwarden.judge.evidence import EvidenceSet
from driftwarden.judge.judge import Judge, gate, rule_verdict
from driftwarden.llm.base import JsonResult, LLMError, LLMResponse, Provider
from driftwarden.llm.schema import Schema
from driftwarden.models import (
    Claim,
    Consistency,
    Evidence,
    GroundingResult,
    RunVote,
    Verdict,
)

DEFAULT_RUNS = 3


class _RunProvider:
    """The judge's provider for one run: passes every call straight through (no
    caching), labels the purpose with the run number, and records an LLMError
    before re-raising it so the judge handles it exactly as it always does."""

    def __init__(self, inner: Provider, run: int, runs: int) -> None:
        self.inner = inner
        self.name = inner.name
        self.model = inner.model
        self.offline = inner.offline
        self.run = run
        self.runs = runs
        self.calls = 0
        self.error: LLMError | None = None

    def _label(self, purpose: str | None) -> str:
        return f"{purpose or 'judge'}#run{self.run}/{self.runs}"

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> LLMResponse:
        self.calls += 1
        try:
            return self.inner.complete(
                prompt, system=system, max_tokens=max_tokens, purpose=self._label(purpose)
            )
        except LLMError as exc:
            self.error = exc
            raise

    def complete_json(
        self,
        prompt: str,
        schema: Schema,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> JsonResult:
        self.calls += 1
        try:
            return self.inner.complete_json(
                prompt, schema, system=system, max_tokens=max_tokens, purpose=self._label(purpose)
            )
        except LLMError as exc:
            self.error = exc
            raise


def _unique(items: list[Any]) -> list[Any]:
    """Order-preserving dedup of pydantic models / strings (by value)."""
    out: list[Any] = []
    seen: list[Any] = []
    for x in items:
        key = x.model_dump(mode="json") if hasattr(x, "model_dump") else x
        if key not in seen:
            seen.append(key)
            out.append(x)
    return out


def inconsistency_reason(votes: list[RunVote]) -> str:
    return "inconsistent across runs: " + ",".join(v.status for v in votes)


class ConsistencyRunner:
    """Runs ``judge`` ``runs`` times per claim at the judge's commit and votes (G6).

    ``ledger`` defaults to the judge's ledger; G6 rows go there. Not thread-safe
    (one runner per thread).
    """

    def __init__(
        self,
        judge: Judge,
        runs: int = DEFAULT_RUNS,
        *,
        ledger: Ledger | None = None,
        dedupe_deterministic: bool = True,
    ) -> None:
        if isinstance(runs, bool) or not isinstance(runs, int) or runs < 1:
            raise ValueError(f"runs must be a positive integer, got {runs!r}")
        self.judge = judge
        self.runs = runs
        self.ledger = ledger if ledger is not None else judge.ledger
        self.dedupe_deterministic = dedupe_deterministic
        self.stats: Counter[str] = Counter()

    # ------------------------------------------------------------------ one run

    def _one(self, claim: Claim, es: EvidenceSet, run: int) -> tuple[Verdict, RunVote]:
        wrapper = None
        if self.judge.mode != "offline" and self.judge.provider is not None:
            wrapper = _RunProvider(self.judge.provider, run, self.runs)
        v = self.judge.judge(claim, es, provider=wrapper)
        self.stats["runs_executed"] += 1
        error = None
        if wrapper is not None:
            self.stats["model_calls"] += wrapper.calls
            if wrapper.error is not None:
                error = f"{type(wrapper.error).__name__}: {wrapper.error}"[:500]
        vote = RunVote(
            run=run,
            status=v.status,
            grounding=v.grounding,
            origin=v.origin,
            proposed_status=v.proposed_status,
            error=error,
            reasons=list(v.reasons),
            evidence=list(v.evidence),
        )
        return v, vote

    def _is_deterministic(self, v: Verdict, rule_decided: bool) -> str | None:
        """Why run 1's result cannot change in further runs (None if it can)."""
        if self.judge.mode == "offline":
            return "offline mode: rules only, no model"
        if rule_decided and v.origin == "rule" and v.grounding == "VERIFIED":
            if v.status != "UNKNOWN":
                return "the rules decided the claim (rule verdict stands whatever the model says)"
        return None

    # ------------------------------------------------------------------ public

    def run(self, claim: Claim, es: EvidenceSet | None = None) -> Verdict:
        """The voted verdict on ``claim`` (see the module docstring)."""
        es = es or self.judge.evidence(claim)  # once: every run sees the same evidence
        rule_decided = rule_verdict(claim, es).status != "UNKNOWN"
        self.stats["claims"] += 1
        verdicts: list[Verdict] = []
        votes: list[RunVote] = []
        for k in range(1, self.runs + 1):
            v, vote = self._one(claim, es, k)
            verdicts.append(v)
            votes.append(vote)
            if k == 1 and self.dedupe_deterministic:
                why = self._is_deterministic(v, rule_decided)
                if why is not None:
                    return self._deterministic(v, vote, why)
        voted = self._vote(claim, verdicts, votes)
        self._record_g6(claim, voted)
        return voted

    def run_all(self, claims: list[Claim]) -> list[Verdict]:
        return [self.run(c) for c in claims]

    def summary(self) -> dict[str, Any]:
        voted = self.stats["voted"]
        return {
            "runs": self.runs,
            "claims": self.stats["claims"],
            "deterministic": self.stats["deterministic"],
            "voted": voted,
            "agreed": self.stats["agreed"],
            "disagreed": voted - self.stats["agreed"],
            "runs_executed": self.stats["runs_executed"],
            "model_calls": self.stats["model_calls"],
            # None, not 1.0, when nothing was voted.
            "consistency_rate": (self.stats["agreed"] / voted) if voted else None,
        }

    # ------------------------------------------------------------------ vote

    def _deterministic(self, v: Verdict, vote: RunVote, why: str) -> Verdict:
        self.stats["deterministic"] += 1
        record = Consistency(
            runs=self.runs, executed=1, basis="deterministic", agreement=True, votes=[vote]
        )
        note = f"deterministic ({why}): 1 run stands for {self.runs}; further runs skipped"
        return v.model_copy(update={"consistency": record, "notes": [*v.notes, note]})

    def _vote(self, claim: Claim, verdicts: list[Verdict], votes: list[RunVote]) -> Verdict:
        n = len(votes)
        self.stats["voted"] += 1
        errors = [vt for vt in votes if vt.error]
        agreement = not errors and len({(vt.status, vt.grounding) for vt in votes}) == 1
        if agreement:
            self.stats["agreed"] += 1
        record = Consistency(
            runs=self.runs, executed=n, basis="vote", agreement=agreement, votes=votes
        )
        first = verdicts[0]
        notes = _unique([n_ for v in verdicts for n_ in v.notes])
        base = {
            "claim_id": claim.id,
            "commit": self.judge.commit,
            "consistency": record,
        }
        inconsistent = [] if agreement else [inconsistency_reason(votes)]
        failed = [f"run {vt.run} failed: {vt.error}" for vt in errors]

        pairs = zip(verdicts, votes, strict=True)
        mismatched = [(v, vt) for v, vt in pairs if v.grounding != "VERIFIED"]
        if mismatched:
            # Any run whose citations fail the gate: Could not verify, never a violation.
            reasons = [f"run {vt.run}: {r}" for _v, vt in mismatched for r in vt.reasons]
            return Verdict(
                status="UNKNOWN",
                grounding="MISMATCH",
                evidence=_unique([e for v, _vt in mismatched for e in v.evidence]),
                reasons=[*reasons, *inconsistent, *failed],
                rationale=f"grounding MISMATCH in {len(mismatched)} of {n} run(s)",
                origin=mismatched[0][0].origin,
                proposed_status=mismatched[0][0].proposed_status,
                notes=notes,
                checks=_unique([c for v, _vt in mismatched for c in v.checks]),
                **base,
            )

        if not agreement:
            return Verdict(
                status="UNKNOWN",
                grounding="VERIFIED",
                evidence=[],
                reasons=[*inconsistent, *failed],
                rationale=inconsistent[0],
                origin=first.origin,
                proposed_status=None,
                notes=notes,
                **base,
            )

        evidence: list[Evidence] = _unique([e for v in verdicts for e in v.evidence])
        data = first.model_dump()
        data.update(
            evidence=evidence,
            checks=[],
            notes=[*notes, f"consistent across {n} runs: {first.status}"],
            **base,
        )
        # Re-verify the voted evidence with the L-007 gate (G2/G3, commit pinning).
        return gate(Verdict.model_validate(data), self.judge.root)

    def _record_g6(self, claim: Claim, voted: Verdict) -> None:
        if self.ledger is None or voted.consistency is None:
            return
        c = voted.consistency
        statuses = ",".join(vt.status for vt in c.votes)
        if c.agreement:
            reason = f"{c.executed}/{c.executed} runs agree: {statuses}"
        else:
            reason = inconsistency_reason(c.votes)
            errs = [f"run {vt.run} failed" for vt in c.votes if vt.error]
            if errs:
                reason += " (" + "; ".join(errs) + ")"
        self.ledger.append(
            GroundingResult(
                check_id="G6",
                status="VERIFIED" if c.agreement else "MISMATCH",
                reason=reason,
                provenance=claim.source,
                subject=f"{claim.id}@{self.judge.commit[:12]}",
            )
        )
