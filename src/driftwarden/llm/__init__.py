"""LLM provider layer: Anthropic, any OpenAI-compatible endpoint, and offline mode.

Raw model output is never trusted. ``complete_json`` only guarantees the reply
parses and matches the schema; callers verify every fact it asserts.

Choosing a provider (``get_provider``):

=========  ===================================================================
mode       result
=========  ===================================================================
offline    OfflineProvider. No network, no key.
llm        The configured provider. A missing API key is a ProviderConfigError.
auto       The configured provider when it is usable (key present, or an
           ``openai`` provider with an explicit ``base_url`` such as a local
           Ollama/vLLM server); otherwise OfflineProvider, with the reason.
=========  ===================================================================
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from driftwarden.config import Config
from driftwarden.llm import anthropic as _anthropic
from driftwarden.llm import openai_compat as _openai
from driftwarden.llm.base import (
    BaseProvider,
    JsonResult,
    LLMError,
    LLMRequest,
    LLMResponse,
    OfflineModeError,
    Provider,
    ProviderConfigError,
    RefusalError,
    RetryPolicy,
    SchemaValidationError,
    Transport,
    TransportError,
    Usage,
)
from driftwarden.llm.costlog import CostLog
from driftwarden.llm.offline import OfflineProvider

__all__ = [
    "BaseProvider",
    "CostLog",
    "JsonResult",
    "LLMError",
    "LLMRequest",
    "LLMResponse",
    "OfflineModeError",
    "OfflineProvider",
    "Provider",
    "ProviderConfigError",
    "RefusalError",
    "RetryPolicy",
    "SchemaValidationError",
    "TransportError",
    "Usage",
    "get_provider",
    "key_env_name",
]

_DEFAULT_KEY_ENV = {"anthropic": _anthropic.DEFAULT_KEY_ENV, "openai": _openai.DEFAULT_KEY_ENV}


def key_env_name(config: Config) -> str:
    """Name of the environment variable holding the API key for ``config``."""
    return config.api_key_env or _DEFAULT_KEY_ENV[config.provider]


def get_provider(
    config: Config,
    root: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: Transport | None = None,
    retry: RetryPolicy | None = None,
    cost_log: CostLog | None = None,
) -> Provider:
    """Build the provider ``config`` asks for.

    ``root`` is the repository root: the cost log goes to
    ``<root>/.driftwarden/logs/llm/``. Without ``root`` (and without an explicit
    ``cost_log``) records are kept in memory only. ``env`` defaults to
    ``os.environ``; ``transport`` and ``retry`` are injectable for tests.
    """
    env = os.environ if env is None else env
    log = cost_log if cost_log is not None else CostLog(root)
    policy = retry or RetryPolicy(max_attempts=config.max_attempts)
    common = {"retry": policy, "cost_log": log}

    if config.mode == "offline":
        return OfflineProvider(reason="offline mode (mode = offline)", **common)

    key_name = key_env_name(config)
    key = env.get(key_name) or None
    price = None
    if config.input_cost_per_mtok is not None and config.output_cost_per_mtok is not None:
        price = (config.input_cost_per_mtok, config.output_cost_per_mtok)

    if config.provider == "anthropic":
        if key is None:
            return _no_key(config, key_name, common)
        return _anthropic.AnthropicProvider(
            config.model or _anthropic.DEFAULT_MODEL,
            api_key=key,
            base_url=config.base_url,
            transport=transport,
            timeout=config.timeout_s,
            price_per_mtok=price,
            **common,
        )

    if config.provider == "openai":
        # A local server (explicit base_url) may need no key at all.
        if key is None and config.base_url is None:
            return _no_key(config, key_name, common)
        if not config.model:
            raise ProviderConfigError(
                "provider 'openai' needs `model` set in the config "
                '(e.g. model = "llama3.1" for Ollama)'
            )
        return _openai.OpenAICompatProvider(
            config.model,
            api_key=key,
            base_url=config.base_url,
            transport=transport,
            timeout=config.timeout_s,
            price_per_mtok=price,
            **common,
        )

    raise ProviderConfigError(f"unknown provider: {config.provider!r}")  # pragma: no cover


def _no_key(config: Config, key_name: str, common: dict) -> Provider:
    if config.mode == "llm":
        raise ProviderConfigError(
            f"mode = llm with provider {config.provider!r} needs an API key in the "
            f"environment variable {key_name}; it is not set"
        )
    return OfflineProvider(reason=f"offline mode ({key_name} not set)", **common)
