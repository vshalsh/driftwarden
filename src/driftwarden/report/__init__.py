"""Reports. ``model.Report`` is the single input for every reporter.

``RENDERERS`` maps each ``--format`` name to ``render(report) -> str``; ``EXTENSIONS``
gives the file each one writes (``driftwarden.<ext>``). ``html`` is imported lazily from
``driftwarden.report.html`` (L-013); when that package is not in this build, calling it
raises :class:`RendererUnavailable` and ``renderer_available("html")`` is False.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable

from driftwarden.report.json import render_json
from driftwarden.report.markdown import render_markdown, render_pr_comment
from driftwarden.report.model import (
    ClaimResult,
    DecisionResult,
    GroundingSummary,
    Metadata,
    Report,
    Summary,
    TimelineEntry,
    UnverifiedItem,
    rule_text,
)
from driftwarden.report.sarif import render_sarif

HTML_UNAVAILABLE = "html report not available in this build"


class RendererUnavailable(RuntimeError):
    """A report format whose renderer is not part of this build."""


def _load_html() -> Callable[[Report], str]:
    try:
        module = importlib.import_module("driftwarden.report.html")
        fn = module.render_html
    except (ImportError, AttributeError) as exc:
        raise RendererUnavailable(HTML_UNAVAILABLE) from exc
    return fn


def render_html(report: Report, *, link_base: str | None = None) -> str:
    """The HTML report (L-013), imported on first use. ``link_base`` as for Markdown."""
    return _load_html()(report, link_base=link_base)


RENDERERS: dict[str, Callable[[Report], str]] = {
    "json": render_json,
    "md": render_markdown,
    "sarif": render_sarif,
    "html": render_html,
}
EXTENSIONS: dict[str, str] = {"json": "json", "md": "md", "sarif": "sarif", "html": "html"}


def renderer_available(fmt: str) -> bool:
    if fmt not in RENDERERS:
        return False
    if fmt != "html":
        return True
    try:
        _load_html()
    except RendererUnavailable:
        return False
    return True


__all__ = [
    "EXTENSIONS",
    "HTML_UNAVAILABLE",
    "RENDERERS",
    "ClaimResult",
    "DecisionResult",
    "GroundingSummary",
    "Metadata",
    "Report",
    "RendererUnavailable",
    "Summary",
    "TimelineEntry",
    "UnverifiedItem",
    "render_html",
    "render_json",
    "render_markdown",
    "render_pr_comment",
    "render_sarif",
    "renderer_available",
    "rule_text",
]
