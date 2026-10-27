"""Offline provider: no network, no API key, fully deterministic.

Offline mode is "rules only, no LLM" (ARCHITECTURE.md). Pipeline stages check
``provider.offline`` and take their deterministic path; an LLM call that still
reaches this provider raises OfflineModeError so the gap is loud, not silent.

A ``responder`` (prompt -> reply text) can be supplied for deterministic
scripted replies, e.g. fixture-driven benchmarks. Replies still go through the
same JSON parsing, schema validation, retry and cost-log path as real providers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from driftwarden.llm.base import BaseProvider, LLMRequest, LLMResponse, OfflineModeError, Usage

Responder = Callable[[LLMRequest], str]

OFFLINE_MODEL = "offline"


class OfflineProvider(BaseProvider):
    name = "offline"
    offline = True

    def __init__(
        self, *, responder: Responder | None = None, reason: str | None = None, **kwargs: Any
    ) -> None:
        super().__init__(OFFLINE_MODEL, **kwargs)
        self.responder = responder
        self.reason = reason or "offline mode"

    def __repr__(self) -> str:
        return f"OfflineProvider(reason={self.reason!r})"

    def _send(self, request: LLMRequest) -> LLMResponse:
        if self.responder is None:
            raise OfflineModeError(
                f"LLM call{f' for {request.purpose!r}' if request.purpose else ''} "
                f"attempted in {self.reason}; use the deterministic (rules) path"
            )
        text = self.responder(request)
        return LLMResponse(
            text=text, model=OFFLINE_MODEL, provider="offline", usage=Usage(), stop_reason="end"
        )
