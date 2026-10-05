"""Tests for backend/llm.py — call_model behaviours.

A fake OpenAI-compatible server (FastAPI app serving /v1/chat/completions)
runs in-process via httpx.ASGITransport. The real AsyncOpenAI SDK talks to it
over HTTP semantics, so response parsing, extra reasoning fields and HTTP
status errors are exercised end to end. Covered:
    - Content return and empty-content fallback to reasoning fields
    - Retry with backoff on 429 / 5xx, no retry on 4xx
    - Concurrency semaphore
    - Pydantic schema validation with one repair retry
    - Cost accounting and price-not-set display
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from openai import AsyncOpenAI, BadRequestError
from pydantic import BaseModel, ValidationError

from backend import cost, llm

NANO_ID = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"


# ---------------------------------------------------------------------------
# Fake OpenAI-compatible server
# ---------------------------------------------------------------------------


class FakeServer:
    """Scripted OpenAI-compatible chat completions server."""

    def __init__(self) -> None:
        self.queue: list[tuple[int, dict]] = []
        self.requests: list[dict] = []
        self.delay_s = 0.0
        self.in_flight = 0
        self.max_in_flight = 0
        self.app = self._build_app()

    def push_completion(
        self,
        content: str | None = None,
        reasoning_content: str | None = None,
        reasoning: str | None = None,
        prompt_tokens: int = 10,
        completion_tokens: int = 5,
    ) -> None:
        """Queue a successful chat completion response."""
        message: dict = {"role": "assistant", "content": content}
        if reasoning_content is not None:
            message["reasoning_content"] = reasoning_content
        if reasoning is not None:
            message["reasoning"] = reasoning
        payload = {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": 0,
            "model": "fake",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
        self.queue.append((200, payload))

    def push_error(self, status: int, message: str = "error") -> None:
        """Queue an HTTP error response."""
        self.queue.append((status, {"error": {"message": message, "code": status}}))

    def _build_app(self) -> FastAPI:
        app = FastAPI()

        @app.post("/v1/chat/completions")
        async def completions(request: Request) -> JSONResponse:
            body = await request.json()
            self.requests.append(body)
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            try:
                if self.delay_s:
                    await asyncio.sleep(self.delay_s)
                if not self.queue:
                    # 418 is non-retryable, so an unscripted call fails loudly.
                    return JSONResponse({"error": {"message": "unscripted"}}, 418)
                status, payload = self.queue.pop(0)
                return JSONResponse(payload, status_code=status)
            finally:
                self.in_flight -= 1

        return app


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    """Point call_model at a fresh fake server with zero backoff delay."""
    fake = FakeServer()
    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake.app), base_url="http://fake"
    )
    client = AsyncOpenAI(
        api_key="test-key",
        base_url="http://fake/v1",
        http_client=http_client,
        max_retries=0,
    )
    monkeypatch.setattr(llm, "_client", client)
    monkeypatch.setattr(llm, "RETRY_BASE_DELAY", 0.0)
    return fake


@pytest.fixture
def zero_pricing(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Use a pricing file where every price is 0, independent of config."""
    path = tmp_path / "pricing.json"
    path.write_text(
        json.dumps({"models": {NANO_ID: {"input_per_1m": 0, "output_per_1m": 0}}})
    )
    monkeypatch.setattr(cost, "_PRICING_PATH", path)
    cost.reset_pricing_cache()


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset caches and ledger around each test."""
    llm.reset_models_cache()
    llm.reset_semaphore()
    cost.reset_ledger()
    cost.reset_pricing_cache()
    yield
    llm.reset_models_cache()
    llm.reset_semaphore()
    cost.reset_ledger()
    cost.reset_pricing_cache()


def _ask(text: str = "Hi") -> list[dict]:
    return [{"role": "user", "content": text}]


# ---------------------------------------------------------------------------
# Content and reasoning fallback
# ---------------------------------------------------------------------------


class TestContent:
    """call_model returns content, or a reasoning field if content is empty."""

    async def test_returns_content_and_sends_routed_model(self, server):
        server.push_completion(content="Hello world")
        result = await llm.call_model(role="nano", messages=_ask(), max_tokens=8)
        assert result == "Hello world"
        assert server.requests[0]["model"] == NANO_ID
        assert server.requests[0]["max_tokens"] == 8
        assert cost.get_ledger().records[0].source == "content"

    async def test_fallback_to_reasoning_content(self, server):
        server.push_completion(content="", reasoning_content="Thought this through")
        result = await llm.call_model(role="nano", messages=_ask())
        assert result == "Thought this through"
        assert cost.get_ledger().records[0].source == "reasoning_content"

    async def test_fallback_to_reasoning(self, server):
        server.push_completion(content=None, reasoning="Deep reasoning here")
        result = await llm.call_model(role="nano", messages=_ask())
        assert result == "Deep reasoning here"
        assert cost.get_ledger().records[0].source == "reasoning"

    async def test_content_wins_over_reasoning(self, server):
        server.push_completion(
            content="Real answer", reasoning_content="no", reasoning="no"
        )
        assert await llm.call_model(role="nano", messages=_ask()) == "Real answer"


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------


class TestRetry:
    """call_model retries on 429 and 5xx, not on other 4xx."""

    async def test_retries_on_429(self, server):
        server.push_error(429, "rate limited")
        server.push_completion(content="ok after 429")
        assert await llm.call_model(role="nano", messages=_ask()) == "ok after 429"
        assert len(server.requests) == 2

    async def test_retries_on_5xx(self, server):
        server.push_error(500, "boom")
        server.push_error(503, "unavailable")
        server.push_completion(content="ok")
        assert await llm.call_model(role="nano", messages=_ask()) == "ok"
        assert len(server.requests) == 3

    async def test_raises_after_max_retries(self, server):
        for _ in range(llm.MAX_RETRIES):
            server.push_error(503, "unavailable")
        with pytest.raises(RuntimeError, match="retries exhausted"):
            await llm.call_model(role="nano", messages=_ask())
        assert len(server.requests) == llm.MAX_RETRIES
        assert cost.get_ledger().records == []

    async def test_no_retry_on_400(self, server):
        server.push_error(400, "bad request")
        with pytest.raises(BadRequestError):
            await llm.call_model(role="nano", messages=_ask())
        assert len(server.requests) == 1


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestSemaphore:
    """call_model never exceeds MAX_CONCURRENCY in-flight requests."""

    async def test_concurrency_capped(self, server, monkeypatch):
        monkeypatch.setattr(llm, "MAX_CONCURRENCY", 2)
        llm.reset_semaphore()
        server.delay_s = 0.02
        for i in range(6):
            server.push_completion(content=f"r{i}")
        results = await asyncio.gather(
            *(llm.call_model(role="nano", messages=_ask()) for _ in range(6))
        )
        assert len(results) == 6
        assert server.max_in_flight == 2


# ---------------------------------------------------------------------------
# Schema validation with repair
# ---------------------------------------------------------------------------


class Sample(BaseModel):
    """Schema used by the validation tests."""

    name: str
    score: int


class TestSchema:
    """call_model validates JSON against a pydantic schema with one repair."""

    async def test_valid_json(self, server):
        server.push_completion(content=json.dumps({"name": "t", "score": 42}))
        result = await llm.call_model(role="nano", messages=_ask(), schema=Sample)
        assert result == Sample(name="t", score=42)
        assert len(server.requests) == 1

    async def test_strips_markdown_fences(self, server):
        server.push_completion(content='```json\n{"name": "t", "score": 7}\n```')
        result = await llm.call_model(role="nano", messages=_ask(), schema=Sample)
        assert result.score == 7

    async def test_repair_retry(self, server):
        server.push_completion(content='{"name": "t"}')  # missing score
        server.push_completion(content=json.dumps({"name": "t", "score": 99}))
        result = await llm.call_model(role="nano", messages=_ask(), schema=Sample)
        assert result.score == 99
        assert len(server.requests) == 2
        repair_msgs = server.requests[1]["messages"]
        assert repair_msgs[-2] == {"role": "assistant", "content": '{"name": "t"}'}
        assert "schema" in repair_msgs[-1]["content"]
        # Both the original and the repair call are accounted for.
        assert len(cost.get_ledger().records) == 2

    async def test_repair_only_once(self, server):
        server.push_completion(content="not json")
        server.push_completion(content="still not json")
        with pytest.raises((ValidationError, json.JSONDecodeError)):
            await llm.call_model(role="nano", messages=_ask(), schema=Sample)
        assert len(server.requests) == 2


# ---------------------------------------------------------------------------
# Cost accounting
# ---------------------------------------------------------------------------


class TestCost:
    """call_model records tokens, latency and cost per call."""

    async def test_records_tokens_and_latency(self, server, zero_pricing):
        server.push_completion(content="Hi", prompt_tokens=100, completion_tokens=50)
        await llm.call_model(role="nano", messages=_ask())
        ledger = cost.get_ledger()
        assert len(ledger.records) == 1
        rec = ledger.records[0]
        assert rec.model == NANO_ID
        assert (rec.prompt_tokens, rec.completion_tokens) == (100, 50)
        assert rec.latency_ms > 0
        assert (ledger.total_prompt_tokens, ledger.total_completion_tokens) == (100, 50)

    async def test_price_not_set(self, server, zero_pricing):
        server.push_completion(content="Hi", prompt_tokens=1000, completion_tokens=1000)
        await llm.call_model(role="nano", messages=_ask())
        rec = cost.get_ledger().records[0]
        assert not rec.price_set
        assert cost.format_cost(rec) == "price not set"
        assert "$" not in cost.format_cost(rec)

    async def test_price_set_calculates_cost(self, server, tmp_path, monkeypatch):
        path = tmp_path / "pricing.json"
        path.write_text(
            json.dumps({"models": {NANO_ID: {"input_per_1m": 1.0, "output_per_1m": 2.0}}})
        )
        monkeypatch.setattr(cost, "_PRICING_PATH", path)
        cost.reset_pricing_cache()
        server.push_completion(
            content="Hi", prompt_tokens=1_000_000, completion_tokens=500_000
        )
        await llm.call_model(role="nano", messages=_ask())
        rec = cost.get_ledger().records[0]
        assert rec.price_set
        # 1M in * $1/1M + 0.5M out * $2/1M = $2
        assert rec.cost_usd == pytest.approx(2.0)
        assert cost.format_cost(rec) == "$2.000000"


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    """get_model_id resolves roles from config/models.yaml."""

    def test_known_roles(self):
        for role in ("ultra", "super", "lightning", "nano", "vision"):
            assert llm.get_model_id(role)

    def test_unknown_role_raises(self):
        with pytest.raises(ValueError, match="Unknown role"):
            llm.get_model_id("nonexistent")
