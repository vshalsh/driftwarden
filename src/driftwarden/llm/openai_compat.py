"""Provider for any OpenAI-compatible Chat Completions endpoint.

Works with OpenAI itself and with local servers that speak the same API
(Ollama: ``http://localhost:11434/v1``, vLLM: ``http://localhost:8000/v1``,
llama.cpp server, LM Studio...). Plain HTTP; the ``openai`` SDK is not needed.
"""

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
)
from driftwarden.llm.transport import check_url, urllib_transport

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_KEY_ENV = "OPENAI_API_KEY"


class OpenAICompatProvider(BaseProvider):
    """Calls ``POST {base_url}/chat/completions``.

    ``api_key`` may be None for local servers that need no auth. ``json_mode``
    sends ``response_format: {"type": "json_object"}`` on JSON requests (widely
    supported); turn it off for servers that reject it.
    """

    name = "openai"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        transport: Transport | None = None,
        timeout: float = 600.0,
        json_mode: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        if not model:
            raise ValueError("model is required for OpenAI-compatible providers")
        self._api_key = api_key or None
        self.base_url = check_url(base_url or DEFAULT_BASE_URL)
        self.transport = transport or urllib_transport
        self.timeout = timeout
        self.json_mode = json_mode

    def __repr__(self) -> str:  # never show the key
        return f"OpenAICompatProvider(model={self.model!r}, base_url={self.base_url!r})"

    def build_body(self, request: LLMRequest) -> dict[str, Any]:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
        }
        if self.json_mode and request.json_schema is not None:
            body["response_format"] = {"type": "json_object"}
        return body

    def _send(self, request: LLMRequest) -> LLMResponse:
        headers = {"authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        data = self.transport(
            f"{self.base_url}/chat/completions", headers, self.build_body(request), self.timeout
        )
        return parse_response(data, self.model)


def parse_response(data: dict[str, Any], model: str) -> LLMResponse:
    if "error" in data and not data.get("choices"):
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else err
        raise TransportError(f"openai-compatible error: {msg}")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise TransportError("response has no choices", retryable=True)
    choice = choices[0]
    message = choice.get("message") or {}
    if message.get("refusal"):
        raise RefusalError(f"model declined the request: {str(message['refusal'])[:200]}")
    content = message.get("content")
    if isinstance(content, list):  # some servers return content parts
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    usage = data.get("usage") or {}
    return LLMResponse(
        text=content or "",
        model=str(data.get("model") or model),
        provider="openai",
        usage=Usage(
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
        ),
        stop_reason=choice.get("finish_reason"),
        response_id=data.get("id"),
    )
