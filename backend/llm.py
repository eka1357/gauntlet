"""Unified LLM client for all model calls.

All inference goes through call_model(). Responsibilities:
    - Route by role to the correct model ID from config/models.yaml
    - Return content, falling back to reasoning field if content is empty
    - Retry with exponential backoff on transient errors
    - Enforce a concurrency semaphore
    - Validate JSON responses against a pydantic schema with one repair retry
    - Record tokens, latency and cost per call
"""


async def call_model(
    role: str,
    messages: list[dict],
    schema: type | None = None,
) -> str:
    """Call a model by role, returning the response content.

    Args:
        role: One of 'ultra', 'super', 'nano', 'omni'.
        messages: OpenAI-format message list.
        schema: Optional pydantic model to validate JSON output against.

    Returns:
        The model's response content as a string.
    """
