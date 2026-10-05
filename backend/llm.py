"""Unified LLM client for all model calls.

All inference goes through call_model(). Responsibilities:
    - Route by role to the correct model ID from config/models.yaml
    - Return content, falling back to reasoning field if content is empty
    - Retry with exponential backoff on 429 and 5xx
    - Enforce a concurrency semaphore
    - Validate JSON responses against a pydantic schema with one repair retry
    - Record tokens, latency and cost per call
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import TypeVar

import yaml
from dotenv import load_dotenv
from openai import APIError, APIStatusError, APITimeoutError, AsyncOpenAI
from pydantic import BaseModel, ValidationError

from backend.cost import format_cost, record_call

load_dotenv()

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_MODELS_PATH = Path(__file__).resolve().parent.parent / "config" / "models.yaml"
_models_cache: dict | None = None


def _load_models() -> dict[str, str]:
    """Load role → model_id mapping from config/models.yaml.

    Returns:
        Dict mapping role name to model ID string.
    """
    global _models_cache
    if _models_cache is not None:
        return _models_cache
    with open(_MODELS_PATH) as f:
        data = yaml.safe_load(f)
    _models_cache = {
        role: info["model_id"] for role, info in data.get("roles", {}).items()
    }
    return _models_cache


def reset_models_cache() -> None:
    """Clear the cached models config (useful for tests)."""
    global _models_cache
    _models_cache = None


def get_model_id(role: str) -> str:
    """Return the model ID for a given role.

    Args:
        role: One of 'ultra', 'super', 'lightning', 'nano', 'vision'.

    Returns:
        The model ID string from config/models.yaml.

    Raises:
        ValueError: If the role is not found in config.
    """
    models = _load_models()
    if role not in models:
        raise ValueError(
            f"Unknown role '{role}'. Available: {list(models.keys())}"
        )
    return models[role]


# ---------------------------------------------------------------------------
# Client setup
# ---------------------------------------------------------------------------

_client: AsyncOpenAI | None = None
_semaphore: asyncio.Semaphore | None = None

# Max concurrent model calls (configurable via env)
MAX_CONCURRENCY = int(os.getenv("GAUNTLET_MAX_CONCURRENCY", "10"))

# Retry settings
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0  # seconds


def _get_client() -> AsyncOpenAI:
    """Return the shared AsyncOpenAI client, creating it on first use."""
    global _client
    if _client is not None:
        return _client

    api_key = os.getenv("NEBIUS_API_KEY")
    base_url = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1")

    if not api_key:
        raise RuntimeError(
            "NEBIUS_API_KEY not set. Copy .env.example to .env and fill it in."
        )

    # max_retries=0: call_model owns retry/backoff so it is observable and tested.
    _client = AsyncOpenAI(api_key=api_key, base_url=base_url, max_retries=0)
    return _client


def set_client(client: AsyncOpenAI) -> None:
    """Override the global client (for tests)."""
    global _client
    _client = client


def _get_semaphore() -> asyncio.Semaphore:
    """Return the shared concurrency semaphore."""
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    return _semaphore


def reset_semaphore() -> None:
    """Reset the semaphore (for tests)."""
    global _semaphore
    _semaphore = None


# ---------------------------------------------------------------------------
# Content extraction helpers
# ---------------------------------------------------------------------------

def _extract_content(choice) -> tuple[str, str]:
    """Extract text content from a chat completion choice.

    Falls back to reasoning_content or reasoning fields when
    the primary content field is empty.

    Args:
        choice: A chat completion choice object.

    Returns:
        Tuple of (text, source) where source is 'content',
        'reasoning_content', or 'reasoning'.
    """
    msg = choice.message

    # Primary: content field
    if msg.content and msg.content.strip():
        return msg.content.strip(), "content"

    # Fallback 1: reasoning_content (used by some reasoning models)
    reasoning_content = getattr(msg, "reasoning_content", None)
    if reasoning_content and reasoning_content.strip():
        return reasoning_content.strip(), "reasoning_content"

    # Fallback 2: reasoning field
    reasoning = getattr(msg, "reasoning", None)
    if reasoning and reasoning.strip():
        return reasoning.strip(), "reasoning"

    return "", "content"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _validate_json(text: str, schema: type[T]) -> T:  # noqa: UP047
    """Parse text as JSON and validate against a pydantic schema.

    Args:
        text: Raw text that should be valid JSON.
        schema: Pydantic model class to validate against.

    Returns:
        Validated pydantic model instance.

    Raises:
        ValidationError: If the JSON doesn't match the schema.
        json.JSONDecodeError: If the text isn't valid JSON.
    """
    # Strip markdown code fences if present
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Remove first line (```json or ```) and last line (```)
        if lines[-1].strip() == "```":
            lines = lines[1:-1]
        else:
            lines = lines[1:]
        cleaned = "\n".join(lines)

    data = json.loads(cleaned)
    return schema.model_validate(data)


# ---------------------------------------------------------------------------
# Main call_model function
# ---------------------------------------------------------------------------

async def call_model(  # noqa: UP047
    role: str,
    messages: list[dict],
    schema: type[T] | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str | T:
    """Call a model by role, returning the response content.

    Routes to the correct model ID via config/models.yaml.
    Retries on 429 and 5xx with exponential backoff.
    Enforces a concurrency semaphore.
    Records tokens, latency and cost.

    If schema is provided, validates the JSON response against it.
    On validation failure, retries once with a repair prompt.

    Args:
        role: One of 'ultra', 'super', 'lightning', 'nano', 'vision'.
        messages: OpenAI-format message list.
        schema: Optional pydantic model to validate JSON output against.
        max_tokens: Optional max tokens for the response.
        temperature: Optional temperature override.

    Returns:
        The model's response content as a string, or a validated
        pydantic model instance if schema is provided.

    Raises:
        RuntimeError: If all retries are exhausted.
        ValidationError: If schema validation fails after repair retry.
    """
    model_id = get_model_id(role)
    client = _get_client()
    sem = _get_semaphore()

    kwargs: dict = {
        "model": model_id,
        "messages": messages,
    }
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    if temperature is not None:
        kwargs["temperature"] = temperature

    # Retry loop with backoff
    last_error: Exception | None = None
    text = ""
    source = "content"
    prompt_tokens = 0
    completion_tokens = 0

    start_ms = time.perf_counter() * 1000

    for attempt in range(MAX_RETRIES):
        try:
            async with sem:
                response = await client.chat.completions.create(**kwargs)

            choice = response.choices[0]
            text, source = _extract_content(choice)

            usage = response.usage
            if usage:
                prompt_tokens = usage.prompt_tokens or 0
                completion_tokens = usage.completion_tokens or 0

            break  # success
        except (APIStatusError,) as e:
            status = getattr(e, "status_code", 0)
            if status in (429,) or 500 <= status < 600:
                last_error = e
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Retryable error (attempt %d/%d, status %d): %s. "
                    "Retrying in %.1fs...",
                    attempt + 1, MAX_RETRIES, status, e, delay,
                )
                await asyncio.sleep(delay)
                continue
            raise  # non-retryable status
        except (APIError, APITimeoutError) as e:
            last_error = e
            delay = RETRY_BASE_DELAY * (2 ** attempt)
            logger.warning(
                "API error (attempt %d/%d): %s. Retrying in %.1fs...",
                attempt + 1, MAX_RETRIES, e, delay,
            )
            await asyncio.sleep(delay)
            continue
    else:
        raise RuntimeError(
            f"All {MAX_RETRIES} retries exhausted for role='{role}' "
            f"model='{model_id}'. Last error: {last_error}"
        )

    elapsed_ms = (time.perf_counter() * 1000) - start_ms

    # Record cost
    rec = record_call(
        model=model_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=elapsed_ms,
        source=source,
    )

    logger.info(
        "call_model role=%s model=%s tokens=%d+%d latency=%.0fms cost=%s source=%s",
        role, model_id, prompt_tokens, completion_tokens,
        elapsed_ms, format_cost(rec), source,
    )

    # Schema validation (with one repair retry)
    if schema is not None:
        try:
            return _validate_json(text, schema)
        except (json.JSONDecodeError, ValidationError) as first_err:
            logger.warning(
                "Schema validation failed, attempting repair: %s", first_err
            )
            # Repair retry: ask the model to fix the JSON
            repair_messages = messages + [
                {"role": "assistant", "content": text},
                {
                    "role": "user",
                    "content": (
                        f"Your previous response was not valid JSON matching "
                        f"the required schema. Error: {first_err}\n\n"
                        f"Please return ONLY valid JSON matching this schema:\n"
                        f"{schema.model_json_schema()}\n\n"
                        f"No explanation, no markdown fences, just the JSON."
                    ),
                },
            ]
            repair_text = await call_model(
                role=role,
                messages=repair_messages,
                schema=None,  # Don't recurse into validation again
                max_tokens=max_tokens,
                temperature=temperature,
            )
            # This will raise if it still doesn't validate
            return _validate_json(repair_text, schema)

    return text
