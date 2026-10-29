"""Drift timeline (pipeline step 9): for each VIOLATED claim, the commit where it first
stopped holding, found by a sampled bisection of first-parent history and re-checked
by the G4 verifier (``grounding.verify.verify_first_violation``). Offline only: the
timeline never calls an LLM.
"""

from driftwarden.timeline.bisect import (
    SnapshotCache,
    TimelineEntry,
    apply_grounding,
    build_timeline,
    first_violation,
)

__all__ = [
    "SnapshotCache",
    "TimelineEntry",
    "apply_grounding",
    "build_timeline",
    "first_violation",
]
