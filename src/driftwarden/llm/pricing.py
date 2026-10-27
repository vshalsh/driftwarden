"""Per-model token prices, for the cost log only.

Prices are USD per million tokens (input, output). The built-in table covers the
Anthropic first-party API and is a snapshot (2026-10-06): set
``input_cost_per_mtok`` / ``output_cost_per_mtok`` in the config to override it, or
to price any OpenAI-compatible model. An unknown model is logged with
``cost_usd: null`` rather than a guessed figure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from driftwarden.llm.base import Usage

PRICES_AS_OF = "2026-10-06"

ANTHROPIC_PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.00, 50.00),
    "claude-fable-5": (10.00, 50.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
}


def price_for(provider: str, model: str) -> tuple[float, float] | None:
    if provider == "anthropic":
        return ANTHROPIC_PRICES.get(model)
    return None


def cost_usd(
    provider: str, model: str, usage: Usage, override: tuple[float, float] | None = None
) -> float | None:
    price = override or price_for(provider, model)
    if price is None:
        return None
    pin, pout = price
    return round((usage.input_tokens * pin + usage.output_tokens * pout) / 1_000_000, 8)
