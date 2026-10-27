"""Provider protocol, request/response types, errors and the shared retry loop.

The LLM proposes; deterministic code disposes. Nothing returned from this layer
is trusted: ``complete_json`` guarantees only that the reply parses and matches
the requested schema. Callers must still verify every fact it asserts.
"""

from __future__ import annotations

import itertools
import math
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from driftwarden.llm.costlog import CostLog
from driftwarden.llm.pricing import cost_usd
from driftwarden.llm.schema import (
    JsonSchemaError,
    Schema,
    check_schema,
    parse_json_reply,
    schema_dict,
    schema_text,
    validate_reply,
)

DEFAULT_MAX_TOKENS = 16000

# --------------------------------------------------------------------------- errors


class LLMError(Exception):
    """Base class for every error raised by the LLM layer."""


class ProviderConfigError(LLMError):
    """The provider cannot be built from the configuration (missing key, bad name...)."""


class OfflineModeError(LLMError):
    """An LLM call was made in offline mode. Callers must use the deterministic path."""


class TransportError(LLMError):
    """The request did not produce a usable response.

    ``retryable`` is True for rate limits, server errors, timeouts and connection
    failures; False for client errors (bad request, auth, not found).
    """

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class RefusalError(LLMError):
    """The model declined the request. Not retried.

    ``category`` is the provider's machine-readable reason, if any. ``usage`` and
    ``model`` are what the provider billed for the refused call, so the cost log
    records real token counts. The model's refusal text is never logged.
    """

    def __init__(
        self,
        message: str,
        *,
        category: str | None = None,
        usage: Usage | None = None,
        model: str | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.usage = usage
        self.model = model


class SchemaValidationError(LLMError):
    """Every attempt returned invalid JSON or JSON that does not match the schema."""

    def __init__(self, message: str, *, attempts: int, errors: list[str], last_text: str):
        super().__init__(message)
        self.attempts = attempts
        self.errors = errors
        self.last_text = last_text


# --------------------------------------------------------------------------- types


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


MAX_TOKEN_COUNT = 10**12
"""Larger reported counts are treated as garbage (and as 0), keeping cost maths finite."""

_ASCII_COUNT = re.compile(r"[0-9]{1,13}")


def token_count(value: Any) -> int:
    """A provider-reported token count, always a sane non-negative int.

    Missing, non-numeric, negative, non-finite or absurdly large (> 10**12) values
    count as 0. Strings count only when they are plain ASCII digits.
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        value = int(value)
    if isinstance(value, str):
        text = value.strip()
        if not _ASCII_COUNT.fullmatch(text):
            return 0
        value = int(text)
    if isinstance(value, int) and 0 <= value <= MAX_TOKEN_COUNT:
        return value
    return 0


class LLMRequest(BaseModel):
    """One prompt. ``json_schema`` is set by ``complete_json`` (for native JSON modes)."""

    prompt: str
    system: str | None = None
    max_tokens: int = DEFAULT_MAX_TOKENS
    json_schema: dict[str, Any] | None = None
    purpose: str | None = Field(default=None, description="Free label for the cost log.")


class LLMResponse(BaseModel):
    text: str
    model: str
    provider: str
    usage: Usage = Field(default_factory=Usage)
    stop_reason: str | None = None
    response_id: str | None = None


class JsonResult(BaseModel):
    """A schema-valid reply. ``value`` is a model instance when a Pydantic class was given."""

    model_config = {"arbitrary_types_allowed": True}

    value: Any
    text: str
    attempts: int
    response: LLMResponse


Transport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]
"""``transport(url, headers, json_body, timeout_s) -> parsed JSON response``.

Raises TransportError. The default is ``driftwarden.llm.transport.urllib_transport``;
tests pass a fake.
"""


@dataclass
class RetryPolicy:
    """Bounded retries with exponential backoff. ``sleep`` is injectable for tests."""

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    sleep: Callable[[float], None] = field(default=time.sleep)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

    def delay(self, attempt: int) -> float:
        """Seconds to wait after failed attempt number ``attempt`` (1-based)."""
        exponent = min(max(attempt - 1, 0), 64)  # 2**64 * any sane base_delay is > max_delay
        return min(self.base_delay * float(2**exponent), self.max_delay)

    def backoff(self, attempt: int) -> None:
        self.sleep(self.delay(attempt))


# --------------------------------------------------------------------------- protocol


@runtime_checkable
class Provider(Protocol):
    name: str
    model: str
    offline: bool

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> LLMResponse: ...

    def complete_json(
        self,
        prompt: str,
        schema: Schema,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> JsonResult: ...


JSON_INSTRUCTIONS = (
    "Reply with a single JSON value that validates against the JSON Schema below. "
    "Output only the JSON: no prose, no Markdown code fences.\n\nJSON Schema:\n"
)


def _json_system(system: str | None, schema_text: str) -> str:
    block = JSON_INSTRUCTIONS + schema_text
    return f"{system}\n\n{block}" if system else block


def _retry_prompt(prompt: str, errors: list[str]) -> str:
    shown = "\n".join(f"- {e}" for e in errors[:10])
    return (
        f"{prompt}\n\nYour previous reply was rejected because it was not valid against "
        f"the schema:\n{shown}\nReply again with only the corrected JSON."
    )


class BaseProvider:
    """Shared retry, schema-validation and cost-logging logic.

    Subclasses implement ``_send(request) -> LLMResponse`` (one HTTP round trip,
    raising TransportError / RefusalError).
    """

    name: str = "base"
    offline: bool = False

    def __init__(
        self,
        model: str,
        *,
        retry: RetryPolicy | None = None,
        cost_log: CostLog | None = None,
        price_per_mtok: tuple[float, float] | None = None,
    ) -> None:
        self.model = model
        self.retry = retry or RetryPolicy()
        self.cost_log = cost_log if cost_log is not None else CostLog(None)
        self.price_per_mtok = price_per_mtok

    # -- subclass hook
    def _send(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- logging
    def _log(
        self,
        request: LLMRequest,
        *,
        attempt: int,
        outcome: str,
        started: float,
        response: LLMResponse | None = None,
        error: str | None = None,
    ) -> None:
        usage = response.usage if response else Usage()
        model = response.model if response else self.model
        self.cost_log.append(
            provider=self.name,
            model=model,
            purpose=request.purpose,
            attempt=attempt,
            outcome=outcome,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost_usd=cost_usd(self.name, model, usage, self.price_per_mtok) if response else None,
            latency_ms=round((time.monotonic() - started) * 1000),
            error=error,
        )

    # -- secrets
    def _secrets(self) -> list[str]:
        """Values that must never be persisted or surfaced (API keys)."""
        key = getattr(self, "_api_key", None)
        return [key] if key else []

    def _redact(self, text: str) -> str:
        for secret in self._secrets():
            text = text.replace(secret, "[REDACTED]")
        return text

    # -- transport retries
    def _send_with_retries(
        self, request: LLMRequest, seq: Iterator[int]
    ) -> tuple[LLMResponse, float, int]:
        """One logical send with transport retries. ``seq`` numbers every attempt
        (monotonic across a whole ``complete``/``complete_json`` call)."""
        tries = 0
        while True:
            tries += 1
            n = next(seq)
            started = time.monotonic()
            try:
                response = self._send(request)
            except TransportError as exc:
                status = f"HTTP {exc.status}" if exc.status is not None else "no response"
                self._log(
                    request, attempt=n, outcome="transport_error", started=started,
                    error=f"{status}; retryable={exc.retryable}",
                )  # fmt: skip
                if not exc.retryable or tries >= self.retry.max_attempts:
                    message = self._redact(str(exc))
                    if message != str(exc):
                        raise TransportError(
                            message, status=exc.status, retryable=exc.retryable
                        ) from None
                    raise
                self.retry.backoff(tries)
                continue
            except RefusalError as exc:
                category = f"category={exc.category}" if exc.category else None
                billed = LLMResponse(
                    text="",
                    model=exc.model or self.model,
                    provider=self.name,
                    usage=exc.usage or Usage(),
                    stop_reason="refusal",
                )
                self._log(
                    request, attempt=n, outcome="refusal", started=started, response=billed,
                    error=category,
                )  # fmt: skip
                raise
            return response, started, n

    # -- public API
    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> LLMResponse:
        request = LLMRequest(
            prompt=prompt,
            system=system,
            max_tokens=max_tokens or DEFAULT_MAX_TOKENS,
            purpose=purpose,
        )
        response, started, n = self._send_with_retries(request, itertools.count(1))
        self._log(request, attempt=n, outcome="ok", started=started, response=response)
        return response

    def complete_json(
        self,
        prompt: str,
        schema: Schema,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
        purpose: str | None = None,
    ) -> JsonResult:
        """Ask for JSON matching ``schema`` (a Pydantic model class or a JSON Schema dict).

        Invalid JSON or a schema mismatch is retried (bounded by ``retry.max_attempts``,
        with backoff), feeding the validation errors back to the model. Raises
        SchemaValidationError when every attempt fails.
        """
        sdict = schema_dict(schema)
        problems = check_schema(sdict)
        if problems:
            raise ProviderConfigError(f"invalid JSON schema: {'; '.join(problems)[:300]}")
        base_request = LLMRequest(
            prompt=prompt,
            system=_json_system(system, schema_text(sdict)),
            max_tokens=max_tokens or DEFAULT_MAX_TOKENS,
            json_schema=sdict,
            purpose=purpose,
        )
        request = base_request
        errors: list[str] = []
        text = ""
        seq = itertools.count(1)
        for attempt in range(1, self.retry.max_attempts + 1):
            response, started, n = self._send_with_retries(request, seq)
            text = response.text
            try:
                data = parse_json_reply(text)
                value = validate_reply(data, schema)
            except JsonSchemaError as exc:
                errors = exc.errors
                outcome = "invalid_json" if exc.kind == "json" else "schema_error"
                # Only schema locations / error kinds: never reply values or keys.
                self._log(
                    request, attempt=n, outcome=outcome, started=started,
                    response=response, error="; ".join(exc.log_errors)[:500],
                )  # fmt: skip
                if attempt < self.retry.max_attempts:
                    self.retry.backoff(attempt)
                    request = base_request.model_copy(
                        update={"prompt": _retry_prompt(prompt, errors)}
                    )
                continue
            self._log(request, attempt=n, outcome="ok", started=started, response=response)
            return JsonResult(value=value, text=text, attempts=attempt, response=response)
        raise SchemaValidationError(
            f"{self.name}/{self.model}: no schema-valid reply after "
            f"{self.retry.max_attempts} attempt(s): {'; '.join(errors)[:300]}",
            attempts=self.retry.max_attempts,
            errors=errors,
            last_text=text,
        )
