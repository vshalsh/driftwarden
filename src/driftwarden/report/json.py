"""The canonical Report JSON (L-012): what ``--format json`` and ``--json-out`` write.

Pretty-printed (2-space indent), keys sorted, UTF-8 (no ``\\u`` escapes for non-ASCII),
one trailing newline. Lists keep the Report's own stable order, so two offline scans
of the same commit differ only in ``metadata.scanned_at``. ``driftwarden report``
reads this file back with ``Report.model_validate_json``.

``render_json`` is the lossless serialisation: it emits the Report it is given
verbatim, summary included, and does not re-gate (L-012b decision). The JSON is the
record that ``report`` re-checks and a reviewer audits, so it must keep what was saved;
a serialiser that silently rewrote verdicts would make an edited file impossible to
reproduce. Callers that want the corrected form pass ``view.regate(report)``, as
``driftwarden report`` does before every format; the scan path's Report is already
gated. The Markdown and SARIF renderers compute their counts from the view
(``view.view_stats``), so they are correct on a raw report too.
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
