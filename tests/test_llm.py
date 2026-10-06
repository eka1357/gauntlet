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
        self.delays: list[float] = []
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
                if not self.queue:
                    # 418 is non-retryable, so an unscripted call fails loudly.
                    return JSONResponse({"error": {"message": "unscripted"}}, 418)
                status, payload = self.queue.pop(0)
                delay = self.delays.pop(0) if self.delays else self.delay_s
                if delay:
                    await asyncio.sleep(delay)
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

    async def test_retries_on_timeout_with_delayed_response(self, server):
        """Times out if response delay exceeds timeout, then retries with backoff and succeeds."""
        # First request delays 0.08s (longer than 0.02s timeout), second succeeds immediately
        server.delays = [0.08, 0.0]
        server.push_completion(content="first-delayed")
        server.push_completion(content="second-succeeded")

        result = await llm.call_model(
            role="nano",
            messages=_ask(),
            params={"timeout": 0.02},
        )
        assert result == "second-succeeded"
        assert len(server.requests) == 2

    async def test_raises_after_all_timeouts(self, server):
        """Raises RuntimeError after max retries exhausted due to persistent timeouts."""
        server.delay_s = 0.08
        for _ in range(llm.MAX_RETRIES):
            server.push_completion(content="never-reached")

        with pytest.raises(RuntimeError, match="retries exhausted"):
            await llm.call_model(
                role="nano",
                messages=_ask(),
                params={"timeout": 0.02},
            )
        assert len(server.requests) == llm.MAX_RETRIES

    async def test_slow_call_warning_logged(self, server, caplog, monkeypatch):
        """A call slower than 10s logs a warning with role, model, and latency."""
        import logging
        server.push_completion(content="slow-ok")
        # Simulate elapsed_ms > 10000ms by mocking time.perf_counter
        calls = 0

        def fake_counter():
            nonlocal calls
            calls += 1
            return 15.0 if calls > 1 else 0.0

        monkeypatch.setattr("time.perf_counter", fake_counter)
        with caplog.at_level(logging.WARNING):
            await llm.call_model(role="nano", messages=_ask())

        assert any(
            "Slow model call detected" in r.message and "nano" in r.message
            for r in caplog.records
        )


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


# ---------------------------------------------------------------------------
# Per-role request defaults
# ---------------------------------------------------------------------------

_TEST_MODELS_YAML = """
roles:
  nano:
    model_id: "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
    request_defaults:
      max_tokens: 1024
      reasoning_effort: "none"
      extra_body:
        chat_template_kwargs:
          enable_thinking: false
  plain:
    model_id: "test/plain"
  prompted:
    model_id: "test/prompted"
    request_defaults:
      system_prompt: "Answer directly."
"""


@pytest.fixture
def models_yaml(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Point llm at a temporary models.yaml with request_defaults."""
    path = tmp_path / "models.yaml"
    path.write_text(_TEST_MODELS_YAML, encoding="utf-8")
    monkeypatch.setattr(llm, "_MODELS_PATH", path)
    llm.reset_models_cache()
    return path


class TestRequestDefaults:
    """Role request_defaults from models.yaml shape every request."""

    def test_defaults_applied(self, models_yaml):
        req = llm.build_request("nano", _ask())
        assert req["model"] == NANO_ID
        assert req["max_tokens"] == 1024
        assert req["reasoning_effort"] == "none"
        assert req["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
        assert req["timeout"] == 45.0

    def test_role_without_defaults_sends_nothing_extra(self, models_yaml):
        assert llm.build_request("plain", _ask()) == {
            "model": "test/plain",
            "messages": _ask(),
            "timeout": 45.0,
        }

    def test_precedence_and_opt_out(self, models_yaml):
        req = llm.build_request(
            "nano",
            _ask(),
            max_tokens=64,
            params={"max_tokens": 128, "reasoning_effort": None, "temperature": 0.2},
        )
        assert req["max_tokens"] == 128  # params beat the max_tokens argument
        assert req["temperature"] == 0.2
        assert "reasoning_effort" not in req  # None removes the role default
        assert "extra_body" in req

    def test_defaults_not_mutated_between_calls(self, models_yaml):
        req = llm.build_request("nano", _ask())
        req["extra_body"]["chat_template_kwargs"]["enable_thinking"] = True
        again = llm.build_request("nano", _ask())
        assert again["extra_body"]["chat_template_kwargs"]["enable_thinking"] is False

    def test_system_prompt_prepended(self, models_yaml):
        req = llm.build_request("prompted", _ask("Q"))
        assert req["messages"] == [
            {"role": "system", "content": "Answer directly."},
            {"role": "user", "content": "Q"},
        ]
        assert "system_prompt" not in req

    def test_system_prompt_merged_into_existing_system(self, models_yaml):
        msgs = [{"role": "system", "content": "You are X."}, *_ask("Q")]
        req = llm.build_request("prompted", msgs)
        assert req["messages"][0] == {
            "role": "system",
            "content": "Answer directly.\n\nYou are X.",
        }
        assert len(req["messages"]) == 2
        assert msgs[0]["content"] == "You are X."  # caller's list untouched

    def test_unknown_param_rejected(self, models_yaml):
        with pytest.raises(ValueError, match="Unknown request param"):
            llm.build_request("nano", _ask(), params={"reasoning": "off"})

    def test_unknown_config_key_rejected(self, tmp_path, monkeypatch):
        path = tmp_path / "models.yaml"
        path.write_text(
            'roles:\n  x:\n    model_id: "m"\n    request_defaults:\n      thinking: false\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(llm, "_MODELS_PATH", path)
        llm.reset_models_cache()
        with pytest.raises(ValueError, match="unknown request_defaults"):
            llm.get_model_id("x")

    async def test_defaults_reach_the_wire(self, server, models_yaml):
        server.push_completion(content='{"name": "t", "score": 1}')
        await llm.call_model(role="nano", messages=_ask())
        body = server.requests[0]
        assert body["max_tokens"] == 1024
        assert body["reasoning_effort"] == "none"
        # extra_body keys are merged into the top-level JSON body by the SDK.
        assert body["chat_template_kwargs"] == {"enable_thinking": False}

    async def test_repair_call_keeps_overrides(self, server, models_yaml):
        server.push_completion(content="not json")
        server.push_completion(content=json.dumps({"name": "t", "score": 3}))
        await llm.call_model(
            role="nano", messages=_ask(), schema=Sample, params={"max_tokens": 77}
        )
        assert [r["max_tokens"] for r in server.requests] == [77, 77]
        assert all(r["reasoning_effort"] == "none" for r in server.requests)

    async def test_records_finish_reason_and_reasoning_presence(self, server):
        server.push_completion(content="answer", reasoning="thinking...")
        await llm.call_model(role="nano", messages=_ask())
        rec = cost.get_ledger().records[0]
        assert rec.source == "content"
        assert rec.reasoning_present is True
        assert rec.finish_reason == "stop"


class TestShippedConfig:
    """The real config/models.yaml loads and every default key is allowed."""

    def test_all_roles_load(self):
        for role in ("ultra", "super", "lightning", "nano", "vision"):
            defaults = llm.get_request_defaults(role)
            assert set(defaults) <= llm.REQUEST_PARAM_KEYS

    def test_nano_uses_enable_thinking_not_reasoning_effort(self):
        # reasoning_effort="none" put Nano's answer in the reasoning field
        # (docs/experiments/reasoning_20261006T041444Z.json).
        defaults = llm.get_request_defaults("nano")
        assert "reasoning_effort" not in defaults
        assert defaults["extra_body"]["chat_template_kwargs"]["enable_thinking"] is False

    def test_lightning_and_super_disable_reasoning(self):
        for role in ("lightning", "super"):
            assert llm.get_request_defaults(role)["reasoning_effort"] == "none"


class TestPricingConfig:
    """The real config/pricing.json matches verified Token Factory rates."""

    def test_source_is_set(self):
        assert cost.get_pricing_source() == "Token Factory console Billing > Prices, eu-north1"

    def test_roles_pricing(self):
        ultra_id = llm.get_model_id("ultra")
        super_id = llm.get_model_id("super")
        lightning_id = llm.get_model_id("lightning")
        nano_id = llm.get_model_id("nano")

        assert cost.get_model_pricing(ultra_id) == (1.00, 3.00)
        assert cost.get_batch_pricing(ultra_id) == (0.50, 1.50)

        assert cost.get_model_pricing(super_id) == (0.30, 0.90)
        assert cost.get_batch_pricing(super_id) == (0.15, 0.45)

        assert cost.get_model_pricing(lightning_id) == (0.06, 0.24)
        assert cost.get_batch_pricing(lightning_id) == (0.03, 0.12)

        assert cost.get_model_pricing(nano_id) == (0.06, 0.24)
        assert cost.get_batch_pricing(nano_id) == (0.03, 0.12)

        for mid in (ultra_id, super_id, lightning_id, nano_id):
            assert cost.price_is_set(mid) is True
