"""Cost accounting.

Tracks token usage, latency and USD cost per model call.
Prices loaded from config/pricing.json (filled by human, never guessed).
"""


def record_call(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: float,
) -> float:
    """Record a model call and return its cost in USD.

    Args:
        model: The model ID used.
        prompt_tokens: Number of input tokens.
        completion_tokens: Number of output tokens.
        latency_ms: Call latency in milliseconds.

    Returns:
        Cost in USD for this call.
    """
