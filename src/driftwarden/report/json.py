"""The canonical Report JSON (L-012): what ``--format json`` and ``--json-out`` write.

Pretty-printed (2-space indent), keys sorted, UTF-8 (no ``\\u`` escapes for non-ASCII),
one trailing newline. Lists keep the Report's own stable order, so two offline scans
of the same commit differ only in ``metadata.scanned_at``. ``driftwarden report``
reads this file back with ``Report.model_validate_json``.
"""

from __future__ import annotations

import json

from driftwarden.report.model import Report


def render_json(report: Report) -> str:
    return (
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    )


__all__ = ["render_json"]
