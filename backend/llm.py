"""Unified LLM client for all model calls.

All inference goes through call_model(). Responsibilities:
    - Route by role to the correct model ID from config/models.yaml
    - Apply per-role request defaults from config/models.yaml
      (max_tokens, temperature, reasoning_effort, extra_body, system_prompt),
      overridable per call
    - Return content, falling back to reasoning field if content is empty
    - Retry with exponential backoff on 429 and 5xx
    - Enforce a concurrency semaphore
    - Validate JSON responses against a pydantic schema with one repair retry
    - Record tokens, latency, cost, answer source and finish reason per call
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, TypeVar

import yaml
from dotenv import load_dotenv
from openai import APIError, APIStatusError, APITimeoutError, AsyncOpenAI
from pydantic import BaseModel, ValidationError

from backend.cost import format_cost, record_call

load_dotenv()

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Request parameters a role default or a per-call override may set.
REQUEST_PARAM_KEYS = frozenset(
    {
        "max_tokens",
        "temperature",
        "reasoning_effort",
        "extra_body",
        "system_prompt",
        "timeout",
        "tools",
        "tool_choice",
    }
)
DEFAULT_TIMEOUT = 45.0


class ModelResponse(str):
    """String response that also carries tool_calls and raw message metadata.

    Acts as a standard str for content comparisons, while exposing
    `.tool_calls`, `.message`, and `.finish_reason` when tools are invoked.
    """

    tool_calls: list[Any] | None
    message: Any | None
    finish_reason: str | None

    def __new__(
        cls,
        content: str = "",
        tool_calls: list[Any] | None = None,
        message: Any | None = None,
        finish_reason: str | None = None,
    ) -> ModelResponse:
        instance = super().__new__(cls, content or "")
        instance.tool_calls = tool_calls
        instance.message = message
        instance.finish_reason = finish_reason
        return instance


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_MODELS_PATH = Path(__file__).resolve().parent.parent / "config" / "models.yaml"
_roles_cache: dict[str, dict] | None = None


def _load_roles() -> dict[str, dict]:
    """Load and validate the role table from config/models.yaml.

    Returns:
        Dict mapping role name to its config dict (model_id, request_defaults).

    Raises:
        ValueError: If a role lacks model_id or sets an unknown request default.
    """
    global _roles_cache
    if _roles_cache is not None:
        return _roles_cache
    with open(_MODELS_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    roles: dict[str, dict] = {}
    for role, info in (data.get("roles") or {}).items():
        if not info or "model_id" not in info:
            raise ValueError(f"Role '{role}' in models.yaml has no model_id")
        defaults = info.get("request_defaults") or {}
        unknown = set(defaults) - REQUEST_PARAM_KEYS
        if unknown:
            raise ValueError(
                f"Role '{role}' has unknown request_defaults keys: {sorted(unknown)}. "
                f"Allowed: {sorted(REQUEST_PARAM_KEYS)}"
            )
        roles[role] = {"model_id": info["model_id"], "request_defaults": defaults}
    _roles_cache = roles
    return _roles_cache


def reset_models_cache() -> None:
    """Clear the cached models config (useful for tests)."""
    global _roles_cache
    _roles_cache = None


def _get_role(role: str) -> dict:
    roles = _load_roles()
    if role not in roles:
        raise ValueError(f"Unknown role '{role}'. Available: {list(roles.keys())}")
    return roles[role]


def get_model_id(role: str) -> str:
    """Return the model ID for a given role.

    Args:
        role: One of 'ultra', 'super', 'lightning', 'nano', 'vision'.

    Returns:
        The model ID string from config/models.yaml.

    Raises:
        ValueError: If the role is not found in config.
    """
    return _get_role(role)["model_id"]


def get_request_defaults(role: str) -> dict[str, Any]:
    """Return a deep copy of the role's request_defaults from config/models.yaml."""
    return copy.deepcopy(_get_role(role)["request_defaults"])


def build_request(
    role: str,
    messages: list[dict],
    max_tokens: int | None = None,
    temperature: float | None = None,
    params: dict[str, Any] | None = None,
    tools: list[dict] | None = None,
    tool_choice: Any | None = None,
) -> dict[str, Any]:
    """Build chat.completions.create kwargs for a role.

    Precedence (lowest to highest): role request_defaults, the max_tokens /
    temperature arguments, then ``params``, then explicit ``tools`` /
    ``tool_choice``. A ``None`` value in ``params`` removes that key, so a
    caller can opt out of a role default. ``system_prompt`` is prepended
    as a system message (merged into an existing leading system message
    if there is one).

    Raises:
        ValueError: If ``params`` contains an unknown key.
    """
    merged = get_request_defaults(role)
    if "timeout" not in merged:
        merged["timeout"] = DEFAULT_TIMEOUT
    if max_tokens is not None:
        merged["max_tokens"] = max_tokens
    if temperature is not None:
        merged["temperature"] = temperature
    for key, value in (params or {}).items():
        if key not in REQUEST_PARAM_KEYS:
            raise ValueError(
                f"Unknown request param '{key}'. Allowed: {sorted(REQUEST_PARAM_KEYS)}"
            )
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value

    if tools is not None:
        merged["tools"] = tools
    if tool_choice is not None:
        merged["tool_choice"] = tool_choice

    msgs = list(messages)
    system_prompt = merged.pop("system_prompt", None)
    if system_prompt:
        if msgs and msgs[0].get("role") == "system":
            msgs[0] = {
                **msgs[0],
                "content": f"{system_prompt}\n\n{msgs[0].get('content', '')}",
            }
        else:
            msgs.insert(0, {"role": "system", "content": system_prompt})

    return {"model": get_model_id(role), "messages": msgs, **merged}


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
        raise RuntimeError("NEBIUS_API_KEY not set. Copy .env.example to .env and fill it in.")

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


def _reasoning_text(msg) -> str:
    """Return the first non-empty reasoning field on a message, or ''."""
    for name in ("reasoning_content", "reasoning"):
        value = getattr(msg, name, None)
        if value and value.strip():
            return value.strip()
    return ""


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


def validate_json(text: str, schema: type[T]) -> T:  # noqa: UP047
    """Parse text as JSON and validate against a pydantic schema.

    Args:
        text: Raw text that should be valid JSON (markdown fences are stripped).
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
    params: dict[str, Any] | None = None,
    tools: list[dict] | None = None,
    tool_choice: Any | None = None,
) -> str | T | ModelResponse:
    """Call a model by role, returning the response content.

    Routes to the correct model ID and request defaults via
    config/models.yaml. Retries on 429 and 5xx with exponential backoff.
    Enforces a concurrency semaphore. Records tokens, latency, cost,
    answer source and finish reason.

    If schema is provided, validates the JSON response against it.
    On validation failure, retries once with a repair prompt.

    Args:
        role: One of 'ultra', 'super', 'lightning', 'nano', 'vision'.
        messages: OpenAI-format message list.
        schema: Optional pydantic model to validate JSON output against.
        max_tokens: Optional max tokens, overrides the role default.
        temperature: Optional temperature, overrides the role default.
        params: Optional per-call overrides of request defaults
            (keys in REQUEST_PARAM_KEYS; a None value removes the default).
        tools: Optional list of OpenAI-format tool definitions.
        tool_choice: Optional tool choice setting ('auto', 'required', or specific tool).

    Returns:
        The model's response content as a string, or a validated
        pydantic model instance if schema is provided, or a
        ModelResponse instance carrying tool_calls if tools are enabled.

    Raises:
        RuntimeError: If all retries are exhausted.
        ValidationError: If schema validation fails after repair retry.
    """
    kwargs = build_request(
        role,
        messages,
        max_tokens,
        temperature,
        params,
        tools=tools,
        tool_choice=tool_choice,
    )
    model_id = kwargs["model"]
    client = _get_client()
    sem = _get_semaphore()

    # Retry loop with backoff
    last_error: Exception | None = None
    text = ""
    source = "content"
    finish_reason: str | None = None
    reasoning_present = False
    prompt_tokens = 0
    completion_tokens = 0

    start_ms = time.perf_counter() * 1000

    for attempt in range(MAX_RETRIES):
        try:
            async with sem:
                call_timeout = kwargs.get("timeout")
                if call_timeout is not None:
                    async with asyncio.timeout(call_timeout):
                        response = await client.chat.completions.create(**kwargs)
                else:
                    response = await client.chat.completions.create(**kwargs)

            choice = response.choices[0]
            text, source = _extract_content(choice)
            finish_reason = choice.finish_reason
            reasoning_present = bool(_reasoning_text(choice.message))

            usage = response.usage
            if usage:
                prompt_tokens = usage.prompt_tokens or 0
                completion_tokens = usage.completion_tokens or 0

            break  # success
        except (APIStatusError,) as e:
            status = getattr(e, "status_code", 0)
            if status in (429,) or 500 <= status < 600:
                last_error = e
                delay = RETRY_BASE_DELAY * (2**attempt)
                logger.warning(
                    "Retryable error (attempt %d/%d, status %d): %s. Retrying in %.1fs...",
                    attempt + 1,
                    MAX_RETRIES,
                    status,
                    e,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            raise  # non-retryable status
        except (APIError, APITimeoutError, TimeoutError) as e:
            last_error = e
            delay = RETRY_BASE_DELAY * (2**attempt)
            logger.warning(
                "Timeout or API error (attempt %d/%d): %s. Retrying in %.1fs...",
                attempt + 1,
                MAX_RETRIES,
                e,
                delay,
            )
            await asyncio.sleep(delay)
            continue
    else:
        raise RuntimeError(
            f"All {MAX_RETRIES} retries exhausted for role='{role}' "
            f"model='{model_id}'. Last error: {last_error}"
        )

    elapsed_ms = (time.perf_counter() * 1000) - start_ms

    if elapsed_ms > 10000:
        logger.warning(
            "Slow model call detected: role=%s model=%s latency=%.0fms (>10s)",
            role,
            model_id,
            elapsed_ms,
        )

    # Record cost
    rec = record_call(
        model=model_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=elapsed_ms,
        source=source,
        finish_reason=finish_reason,
        reasoning_present=reasoning_present,
    )

    logger.info(
        "call_model role=%s model=%s tokens=%d+%d latency=%.0fms cost=%s source=%s finish=%s",
        role,
        model_id,
        prompt_tokens,
        completion_tokens,
        elapsed_ms,
        format_cost(rec),
        source,
        finish_reason,
    )
    if finish_reason == "length":
        logger.warning(
            "call_model role=%s hit max_tokens (finish_reason=length); output may be truncated",
            role,
        )

    # Schema validation (with one repair retry)
    if schema is not None:
        try:
            return validate_json(text, schema)
        except (json.JSONDecodeError, ValidationError) as first_err:
            logger.warning("Schema validation failed, attempting repair: %s", first_err)
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
                params=params,
            )
            # This will raise if it still doesn't validate
            return validate_json(repair_text, schema)

    msg = choice.message
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls is not None or kwargs.get("tools") is not None:
        return ModelResponse(
            content=text,
            tool_calls=tool_calls,
            message=msg,
            finish_reason=finish_reason,
        )

    return text
