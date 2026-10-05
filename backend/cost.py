"""Cost accounting.

Tracks token usage, latency and USD cost per model call.
Prices loaded from config/pricing.json (filled by human, never guessed).
When price is 0, cost is reported as 'price not set' instead of $0.00.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

_PRICING_PATH = Path(__file__).resolve().parent.parent / "config" / "pricing.json"

_pricing_cache: dict | None = None
_lock = threading.Lock()


def _load_pricing() -> dict:
    """Load pricing from config/pricing.json, cached after first read."""
    global _pricing_cache
    if _pricing_cache is not None:
        return _pricing_cache
    with _lock:
        if _pricing_cache is not None:
            return _pricing_cache
        with open(_PRICING_PATH) as f:
            data = json.load(f)
        _pricing_cache = data.get("models", {})
    return _pricing_cache


def reset_pricing_cache() -> None:
    """Clear the cached pricing data (useful for tests)."""
    global _pricing_cache
    _pricing_cache = None


def get_model_pricing(model_id: str) -> tuple[float, float]:
    """Return (input_per_1m, output_per_1m) for a model.

    Args:
        model_id: The model ID string.

    Returns:
        Tuple of (input_price_per_1m_tokens, output_price_per_1m_tokens).
    """
    pricing = _load_pricing()
    entry = pricing.get(model_id, {})
    return entry.get("input_per_1m", 0.0), entry.get("output_per_1m", 0.0)


def price_is_set(model_id: str) -> bool:
    """Return True if the model has non-zero pricing configured."""
    inp, out = get_model_pricing(model_id)
    return inp > 0 or out > 0


@dataclass
class CallRecord:
    """Record of a single model call."""

    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    cost_usd: float
    price_set: bool
    source: str = "content"


@dataclass
class CostLedger:
    """Accumulates cost records across a run."""

    records: list[CallRecord] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0

    def record(self, rec: CallRecord) -> None:
        """Add a call record to the ledger."""
        self.records.append(rec)
        self.total_cost_usd += rec.cost_usd
        self.total_prompt_tokens += rec.prompt_tokens
        self.total_completion_tokens += rec.completion_tokens


# Global ledger for the current process
_ledger = CostLedger()


def get_ledger() -> CostLedger:
    """Return the global cost ledger."""
    return _ledger


def reset_ledger() -> None:
    """Reset the global cost ledger (useful for tests)."""
    global _ledger
    _ledger = CostLedger()


def record_call(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: float,
    source: str = "content",
) -> CallRecord:
    """Record a model call and return its CallRecord.

    Cost is computed from pricing.json. If price is 0, cost_usd is 0
    and price_set is False — callers should display 'price not set'.

    Args:
        model: The model ID used.
        prompt_tokens: Number of input tokens.
        completion_tokens: Number of output tokens.
        latency_ms: Call latency in milliseconds.
        source: Response field the answer came from ('content',
            'reasoning_content' or 'reasoning').

    Returns:
        CallRecord with computed cost.
    """
    inp_price, out_price = get_model_pricing(model)
    has_price = inp_price > 0 or out_price > 0

    if has_price:
        cost = (prompt_tokens * inp_price / 1_000_000) + (
            completion_tokens * out_price / 1_000_000
        )
    else:
        cost = 0.0

    rec = CallRecord(
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=latency_ms,
        cost_usd=cost,
        price_set=has_price,
        source=source,
    )
    _ledger.record(rec)
    return rec


def format_cost(rec: CallRecord) -> str:
    """Format cost for display.

    Returns 'price not set' when pricing is zero, otherwise '$X.XXXXXX'.
    """
    if not rec.price_set:
        return "price not set"
    return f"${rec.cost_usd:.6f}"
