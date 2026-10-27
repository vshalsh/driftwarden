"""Anthropic Messages API provider (plain HTTP; the ``anthropic`` SDK is not needed)."""

from __future__ import annotations

from typing import Any

from driftwarden.llm.base import (
    BaseProvider,
    LLMRequest,
    LLMResponse,
    RefusalError,
    Transport,
    TransportError,
    Usage,
    token_count,
)
from driftwarden.llm.transport import check_url, redact_url, urllib_transport

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_KEY_ENV = "ANTHROPIC_API_KEY"
API_VERSION = "2026-10-21"


class AnthropicProvider(BaseProvider):
    """Calls ``POST {base_url}/v1/messages``.

    ``structured_output=True`` also sends the schema as ``output_config.format`` so
    the API constrains decoding. It is off by default because the API accepts only a
    subset of JSON Schema; the reply is validated client-side either way.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        api_key: str,
        base_url: str | None = None,
        transport: Transport | None = None,
        timeout: float = 600.0,
        structured_output: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self.base_url = check_url(base_url or DEFAULT_BASE_URL)
        self.transport = transport or urllib_transport
        self.timeout = timeout
        self.structured_output = structured_output

    def __repr__(self) -> str:  # never show the key
        return f"AnthropicProvider(model={self.model!r}, base_url={redact_url(self.base_url)!r})"

    def build_body(self, request: LLMRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system:
            body["system"] = request.system
        if self.structured_output and request.json_schema is not None:
            body["output_config"] = {
                "format": {"type": "json_schema", "schema": request.json_schema}
            }
        return body

    def _send(self, request: LLMRequest) -> LLMResponse:
        headers = {"x-api-key": self._api_key, "anthropic-version": API_VERSION}
        data = self.transport(
            f"{self.base_url}/v1/messages", headers, self.build_body(request), self.timeout
        )
        return parse_response(data, self.model)


def parse_response(data: dict[str, Any], model: str) -> LLMResponse:
    if data.get("type") == "error":
        err = data.get("error") or {}
        raise TransportError(f"anthropic error: {err.get('type')}: {err.get('message')}")
    content = data.get("content")
    if not isinstance(content, list):
        raise TransportError("anthropic response has no content list", retryable=True)
    stop = data.get("stop_reason")
    if stop == "refusal":
        details = data.get("stop_details")
        category = details.get("category") if isinstance(details, dict) else None
        category = category if isinstance(category, str) and category.isidentifier() else None
        raise RefusalError(f"model declined the request (category={category})", category=category)
    text = "".join(
        b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
    )
    usage = data.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    return LLMResponse(
        text=text,
        model=str(data.get("model") or model),
        provider="anthropic",
        usage=Usage(
            input_tokens=token_count(usage.get("input_tokens"))
            + token_count(usage.get("cache_creation_input_tokens"))
            + token_count(usage.get("cache_read_input_tokens")),
            output_tokens=token_count(usage.get("output_tokens")),
        ),
        stop_reason=stop,
        response_id=data.get("id"),
    )
