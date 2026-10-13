"""FastAPI application and route definitions (FR-14).

Endpoints:
    GET  /                      — project metadata and navigation links
    GET  /api/health            — check Token Factory and Tavily reachability (cached 60s)
    GET  /api/recorded/summary  — headline tables from runs/verify_results.json
    GET  /api/recorded/attacks  — paginated attack records without full traces
    GET  /api/attacks/{id}/trace — full attack trace for one condition
    GET  /api/policy/{version}  — policy YAML with SHA-256 and per-rule rationale
    POST /api/runs              — start a rate-limited live mini-run (max 20 attacks)
    GET  /api/runs/{id}         — get live run metadata and status
    GET  /api/runs/{id}/events  — Server-Sent Events (SSE) stream for run progress
    GET  /api/recorded          — backward-compatible recorded run overview
    GET  /api/verify/results    — backward-compatible cached verify results
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlmodel import Session, select
from starlette.responses import StreamingResponse

from backend.models import Attack, Run, init_db
from backend.orchestrator import (
    execute_mini_live_run,
    global_event_manager,
)
from backend.verify import get_cached_verify_results

logger = logging.getLogger("gauntlet.api")

ROOT_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT_DIR / "runs"
FIXTURES_DIR = ROOT_DIR / "fixtures"

VERIFY_RESULTS_PATH = RUNS_DIR / "verify_results.json"
RECORDED_RUN_PATH = RUNS_DIR / "recorded_run.json"
POLICY_V1_PATH = FIXTURES_DIR / "hardened_policy.yaml"
POLICY_V2_PATH = FIXTURES_DIR / "policy_v2.yaml"

MAX_REQUEST_BYTES = 1024 * 1024  # 1 MB request payload cap


# ---------------------------------------------------------------------------
# Safeguards: Rate Limiting & Spend Tracking
# ---------------------------------------------------------------------------


class IPRateLimiter:
    """Sliding-window per-IP rate limiter."""

    def __init__(self, max_requests: int = 3, window_seconds: float = 3600.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, ip: str) -> bool:
        """Check if request is allowed for IP and record timestamp if so."""
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            timestamps = [t for t in self._history.get(ip, []) if t > cutoff]
            if len(timestamps) >= self.max_requests:
                self._history[ip] = timestamps
                return False
            timestamps.append(now)
            self._history[ip] = timestamps
            return True

    def reset(self) -> None:
        """Reset all rate limiter tracking."""
        self._history.clear()


ip_rate_limiter = IPRateLimiter(max_requests=3, window_seconds=3600.0)


def get_client_ip(request: Request) -> str:
    """Extract client IP address safely from headers or client object.

    Uses X-Forwarded-For only when TRUSTED_PROXY is set to 'true' (case-insensitive).
    Otherwise defaults to request.client.host to prevent IP spoofing attacks.
    """
    trusted_proxy = os.environ.get("TRUSTED_PROXY", "").strip().lower() == "true"
    if trusted_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def get_daily_live_spend(db_path: str = "runs/gauntlet.db") -> float:
    """Calculate total USD spent on live runs today in UTC."""
    today_prefix = datetime.now(UTC).strftime("%Y-%m-%d")
    engine = init_db(db_path)
    try:
        with Session(engine) as session:
            runs = session.exec(select(Run)).all()
            return sum(r.cost_usd for r in runs if (r.created_at or "").startswith(today_prefix))
    except Exception as e:
        logger.warning("Error reading daily live spend: %s", e)
        return 0.0


async def check_live_runs_allowed(client_ip: str) -> None:
    """Validate kill switch, daily spend cap, and per-IP rate limit for live runs."""
    # 1. Kill switch: disabled unless LIVE_RUNS_ENABLED is exactly "true" (case-insensitive)
    kill_switch_val = os.environ.get("LIVE_RUNS_ENABLED", "").strip().lower()
    if kill_switch_val != "true":
        raise HTTPException(
            status_code=429,
            detail="Live runs are paused for today; open the recorded run instead",
        )

    # 2. Daily spend cap (default $0.40)
    try:
        cap_val = float(os.environ.get("DAILY_SPEND_CAP_USD", "0.40"))
    except ValueError:
        cap_val = 0.40
    current_daily_spend = get_daily_live_spend()
    if current_daily_spend >= cap_val:
        raise HTTPException(
            status_code=429,
            detail="Live runs are paused for today; open the recorded run instead",
        )

    # 3. Per-IP rate limit: 3 per hour
    allowed = await ip_rate_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded: maximum 3 runs per hour per IP",
        )


# ---------------------------------------------------------------------------
# In-Memory Cache for Health Checks
# ---------------------------------------------------------------------------

_health_cache: dict[str, Any] | None = None
_health_cache_timestamp: float = 0.0
_HEALTH_CACHE_TTL: float = 60.0


def reset_health_cache() -> None:
    """Reset health check in-memory cache (useful in test suites)."""
    global _health_cache, _health_cache_timestamp
    _health_cache = None
    _health_cache_timestamp = 0.0


# ---------------------------------------------------------------------------
# In-Memory Cache for Recorded Run Data
# ---------------------------------------------------------------------------

_recorded_run_cache: dict[str, Any] | None = None
_recorded_attacks_index: dict[str, dict[str, Any]] | None = None


def load_recorded_run_data() -> dict[str, Any]:
    """Load and cache runs/recorded_run.json without model calls."""
    global _recorded_run_cache, _recorded_attacks_index
    if _recorded_run_cache is not None:
        return _recorded_run_cache

    for p in (RECORDED_RUN_PATH, FIXTURES_DIR / "recorded_run.json"):
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                _recorded_run_cache = data
                _recorded_attacks_index = {a["id"]: a for a in data.get("attacks", [])}
                return data
            except Exception as e:
                logger.warning("Failed to load %s: %s", p, e)

    raise HTTPException(status_code=404, detail="Recorded run data file not found")


# ---------------------------------------------------------------------------
# FastAPI App Initialization & Middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Gauntlet",
    description="AI Agent Hardening & Verification API (FR-14)",
    version="0.2.0",
)

# CORS configuration
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS") or os.environ.get("WEB_APP_ORIGIN")
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_request_payload_size(request: Request, call_next: Any) -> Response:
    """Enforce request body size limits to prevent oversized payload attacks."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BYTES:
        return Response(content="Request entity too large", status_code=413)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CreateRunRequest(BaseModel):
    """Request payload for starting a live mini-run."""

    n_attacks: int = Field(default=8, ge=1, le=8, description="Max 8 attacks for live runs")
    compare_v2: bool = Field(default=True, description="Run against Policy v2 as well")
    target_mode: str = Field(
        default="naive",
        description="Target agent mode: 'naive' or 'realistic'",
    )

    @field_validator("target_mode")
    @classmethod
    def validate_target_mode(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("naive", "realistic"):
            raise ValueError("target_mode must be 'naive' or 'realistic'")
        return clean


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
async def root() -> dict[str, Any]:
    """Return project metadata, one-line description, and primary API navigation links."""
    return {
        "name": "Gauntlet",
        "description": "Gauntlet hardens AI agents before they ship.",
        "links": {
            "summary": "/api/recorded/summary",
            "docs": "/docs",
            "github": "https://github.com/eka1357/gauntlet",
        },
        "docs_url": "/docs",
        "summary_url": "/api/recorded/summary",
        "github_url": "https://github.com/eka1357/gauntlet",
    }


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Report health and whether Token Factory and Tavily keys are configured and reachable.

    Never prints keys or makes paid calls (uses models list endpoint for Token Factory).
    Results are cached in-memory for 60 seconds.
    """
    global _health_cache, _health_cache_timestamp
    now = time.time()
    if _health_cache is not None and (now - _health_cache_timestamp) < _HEALTH_CACHE_TTL:
        return _health_cache

    # 1. Token Factory check
    nebius_key = os.environ.get("NEBIUS_API_KEY")
    nebius_base_url = os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1")
    tf_configured = bool(nebius_key and nebius_key.strip())
    tf_reachable = False
    tf_error = None

    if tf_configured:
        try:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=nebius_key, base_url=nebius_base_url, timeout=4.0)
            await client.models.list()
            tf_reachable = True
        except Exception as e:
            tf_reachable = False
            tf_error = type(e).__name__

    # 2. Tavily check
    tavily_key = os.environ.get("TAVILY_API_KEY")
    tavily_configured = bool(tavily_key and tavily_key.strip())
    tavily_reachable = False
    tavily_error = None

    if tavily_configured:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=4.0) as http_client:
                r = await http_client.get("https://api.tavily.com")
                if r.status_code == 200:
                    tavily_reachable = True
                else:
                    tavily_reachable = False
                    tavily_error = f"HTTP {r.status_code}"
        except Exception as e:
            tavily_reachable = False
            tavily_error = type(e).__name__

    result = {
        "status": "ok",
        "token_factory": {
            "configured": tf_configured,
            "reachable": tf_reachable,
            **({"error": tf_error} if tf_error else {}),
        },
        "tavily": {
            "configured": tavily_configured,
            "reachable": tavily_reachable,
            **({"error": tavily_error} if tavily_error else {}),
        },
    }
    _health_cache = result
    _health_cache_timestamp = now
    return result


def get_recorded_model_roles() -> list[dict[str, str]]:
    """Return model roles actually used in the recorded evaluations from config/models.yaml.

    Excludes unused models (such as Omni/vision) and includes active roles:
    Ultra: recon, defender, triage
    Super: target agent
    Lightning: payload generation
    """
    models_path = Path(__file__).resolve().parent.parent / "config" / "models.yaml"
    roles_data: dict[str, Any] = {}
    if models_path.is_file():
        try:
            with open(models_path, encoding="utf-8") as f:
                y = yaml.safe_load(f) or {}
                roles_data = y.get("roles") or {}
        except Exception as e:
            logger.warning("Could not load models.yaml: %s", e)

    ultra_id = roles_data.get("ultra", {}).get(
        "model_id", "nvidia/Nemotron-3-Ultra-550b-a55b"
    )
    super_id = roles_data.get("super", {}).get(
        "model_id", "nvidia/nemotron-3-super-120b-a12b"
    )
    lightning_id = roles_data.get("lightning", {}).get(
        "model_id", "nvidia/Nemotron-3_5-Lightning"
    )

    return [
        {
            "role": "Ultra",
            "model_id": str(ultra_id),
            "description": "Recon, defender, triage",
        },
        {
            "role": "Super",
            "model_id": str(super_id),
            "description": "Target agent brain",
        },
        {
            "role": "Lightning",
            "model_id": str(lightning_id),
            "description": "Payload generation",
        },
    ]


@app.get("/api/recorded/summary")
async def get_recorded_summary() -> dict[str, Any]:
    """Headline tables from runs/verify_results.json.

    ZERO model calls. Must work with no API keys set.
    Includes:
      - naive-mode and realistic-mode confirmation (unhardened vs policy v2, standard attacks,
        n and Wilson CI for M1, M2, M3, M4, UNSAFE)
      - probe set results (unhardened vs v1 vs v2)
      - benign suite pooled pass rates with CI (unhardened vs v2, 3 repeats)
        and deny-all negative control
      - policy SHA-256 hashes for v1 and v2
      - per-run costs
      - limitations list
      - model_roles used in recorded runs
    """
    results = get_cached_verify_results()
    if results is None:
        raise HTTPException(status_code=404, detail="Verification results file not found")

    ordered_keys = [
        "naive_mode",
        "realistic_mode",
        "probe_set",
        "benign_suite",
        "policy_hashes",
        "costs",
        "limitations",
    ]
    response_data = {k: results[k] for k in ordered_keys if k in results}
    for k, v in results.items():
        if k not in response_data:
            response_data[k] = v
    response_data["model_roles"] = get_recorded_model_roles()
    return response_data


@app.get("/api/recorded/attacks")
async def get_recorded_attacks(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(50, ge=1, le=250, description="Items per page"),
    channel: str | None = Query(None, description="Filter by channel: email, web_page, document"),
    condition: str | None = Query(None, description="Filter by condition: unhardened, v1, v2"),
    outcome: str | None = Query(None, description="Filter by outcome: breach, defended"),
    is_probe: bool | None = Query(None, description="Filter probe attacks"),
) -> dict[str, Any]:
    """Per-attack records from runs/recorded_run.json.

    Paginated, with filters for channel and condition.
    Does NOT include full traces.
    ZERO model calls.
    """
    data = load_recorded_run_data()
    all_attacks = data.get("attacks", [])

    filtered: list[dict[str, Any]] = []

    for a in all_attacks:
        # Channel filter
        if channel and a.get("channel", "").lower() != channel.lower():
            continue

        # Probe filter
        if is_probe is not None and bool(a.get("is_probe", False)) != is_probe:
            continue

        # Outcome filter
        if outcome:
            if condition:
                if a.get(condition, {}).get("outcome") != outcome:
                    continue
            else:
                has_match = any(
                    a.get(c, {}).get("outcome") == outcome for c in ("unhardened", "v1", "v2")
                )
                if not has_match:
                    continue

        # Construct lean attack record without full traces
        lean_record: dict[str, Any] = {
            "id": a["id"],
            "channel": a.get("channel", "email"),
            "category": a.get("category", ""),
            "strategy": a.get("strategy", ""),
            "is_probe": a.get("is_probe", False),
            "unhardened": {
                "outcome": a.get("unhardened", {}).get("outcome", "defended"),
                "m1": a.get("unhardened", {}).get("metrics", {}).get("m1", False),
                "m2": a.get("unhardened", {}).get("metrics", {}).get("m2", False),
                "m3": a.get("unhardened", {}).get("metrics", {}).get("m3", False),
                "m4": a.get("unhardened", {}).get("metrics", {}).get("m4", False),
                "unsafe": a.get("unhardened", {}).get("metrics", {}).get("unsafe", False),
                "policy_block_rule": a.get("unhardened", {}).get("policy_block_rule"),
            },
            "v1": {
                "outcome": a.get("v1", {}).get("outcome", "defended"),
                "m1": a.get("v1", {}).get("metrics", {}).get("m1", False),
                "m2": a.get("v1", {}).get("metrics", {}).get("m2", False),
                "m3": a.get("v1", {}).get("metrics", {}).get("m3", False),
                "m4": a.get("v1", {}).get("metrics", {}).get("m4", False),
                "unsafe": a.get("v1", {}).get("metrics", {}).get("unsafe", False),
                "policy_block_rule": a.get("v1", {}).get("policy_block_rule"),
            },
            "v2": {
                "outcome": a.get("v2", {}).get("outcome", "defended"),
                "m1": a.get("v2", {}).get("metrics", {}).get("m1", False),
                "m2": a.get("v2", {}).get("metrics", {}).get("m2", False),
                "m3": a.get("v2", {}).get("metrics", {}).get("m3", False),
                "m4": a.get("v2", {}).get("metrics", {}).get("m4", False),
                "unsafe": a.get("v2", {}).get("metrics", {}).get("unsafe", False),
                "policy_block_rule": a.get("v2", {}).get("policy_block_rule"),
            },
        }
        filtered.append(lean_record)

    total = len(filtered)
    start = (page - 1) * limit
    end = start + limit
    paged = filtered[start:end]
    pages = (total + limit - 1) // limit if total > 0 else 0

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages,
        "attacks": paged,
    }


@app.get("/api/attacks/{id}/trace")
async def get_attack_trace(
    id: str,
    condition: str = Query("unhardened", description="Condition: unhardened, v1, or v2"),
) -> dict[str, Any]:
    """Return the stored execution trace for one attack under a specified condition."""
    if condition not in ("unhardened", "v1", "v2"):
        raise HTTPException(
            status_code=400,
            detail="Invalid condition. Must be 'unhardened', 'v1', or 'v2'",
        )

    # 1. Check in recorded run cache
    load_recorded_run_data()
    if _recorded_attacks_index and id in _recorded_attacks_index:
        att = _recorded_attacks_index[id]
        cond_data = att.get(condition, {})
        return {
            "id": att["id"],
            "condition": condition,
            "channel": att.get("channel", "email"),
            "category": att.get("category", ""),
            "strategy": att.get("strategy", ""),
            "payload": att.get("payload", ""),
            "is_probe": att.get("is_probe", False),
            "outcome": cond_data.get("outcome", "defended"),
            "metrics": cond_data.get("metrics", {}),
            "policy_block_rule": cond_data.get("policy_block_rule"),
            "trace": cond_data.get("trace", []),
        }

    # 2. Check in SQLite database for live run attacks
    engine = init_db("runs/gauntlet.db")
    target_id = f"{id}_v2" if condition == "v2" else id
    try:
        with Session(engine) as session:
            row = session.get(Attack, target_id)
            if not row and condition == "v2":
                row = session.get(Attack, id)
            if row:
                trace_obj = []
                try:
                    trace_obj = json.loads(row.trace_json)
                except Exception:
                    pass
                return {
                    "id": row.id,
                    "condition": condition,
                    "channel": row.channel,
                    "category": row.category,
                    "strategy": row.strategy,
                    "payload": row.payload,
                    "is_probe": False,
                    "outcome": row.outcome,
                    "metrics": {
                        "m1": row.breach_type == "exfiltration",
                        "unsafe": row.outcome == "breach",
                    },
                    "policy_block_rule": None,
                    "trace": trace_obj,
                }
    except Exception as e:
        logger.warning("Error querying SQLite for attack %s: %s", id, e)

    raise HTTPException(status_code=404, detail=f"Attack '{id}' not found")


@app.get("/api/policy/{version}")
async def get_policy_yaml(version: str) -> dict[str, Any]:
    """Return policy YAML (v1 or v2) with its SHA-256 and per-rule rationale."""
    norm = version.lower().strip()
    if norm in ("1", "v1"):
        p_path = POLICY_V1_PATH
        v_num = 1
        rationale = {
            "egress": "Restrict egress strictly to internal infrastructure and approved partners.",
            "http_post": "Deny arbitrary external HTTP calls to eliminate exfiltration channels.",
            "read_file": "Block sensitive credentials and vault files via wildcard globs.",
            "send_email": "Enforce approved partner and internal recipient list.",
            "untrusted_content": "Label and sanitize untrusted inputs from email and web sources.",
        }
    elif norm in ("2", "v2"):
        p_path = POLICY_V2_PATH
        v_num = 2
        rationale = {
            "secrets_registry": "Runtime registry blocks known vault secrets in outbound tools.",
            "credential_patterns": "Detects high-entropy tokens and credential patterns.",
            "partner_emails": "Scans partner emails for secrets while permitting benign traffic.",
            "web_fetch": "Denies credential query parameters and scanned secrets in fetch URLs.",
            "calendar_add": "Scans calendar fields to prevent side-channel secret leaks.",
        }
    else:
        raise HTTPException(
            status_code=404,
            detail="Policy version not found. Available versions: v1, v2",
        )

    if not p_path.is_file():
        raise HTTPException(status_code=404, detail=f"Policy file {p_path.name} not found")

    content_bytes = p_path.read_bytes()
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    yaml_text = content_bytes.decode("utf-8")
    parsed = yaml.safe_load(yaml_text)

    return {
        "version": v_num,
        "sha256": sha256_hash,
        "yaml": yaml_text,
        "policy": parsed,
        "rationale": rationale,
    }


@app.post("/api/runs")
async def start_run(
    request: Request,
    body: CreateRunRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Start a live mini-run: max 8 attacks, realistic target mode.

    Lightning-generated payloads, no recon, no Ultra, target model Super.
    Enforces kill switch, daily spend cap ($0.40), per-run budget cap ($0.08),
    and per-IP rate limit (3/hour).
    """
    client_ip = get_client_ip(request)
    await check_live_runs_allowed(client_ip)

    run_id = f"run_{uuid.uuid4().hex[:12]}"
    n_attacks = max(1, min(8, body.n_attacks))

    # Initialize SQLite Run record
    engine = init_db("runs/gauntlet.db")
    with Session(engine) as session:
        new_run = Run(
            id=run_id,
            status="running",
            config_json=json.dumps({
                "n_attacks": n_attacks,
                "compare_v2": body.compare_v2,
                "target_mode": body.target_mode,
                "budget_cap_usd": 0.08,
            }),
            created_at=datetime.now(UTC).isoformat(),
            cost_usd=0.0,
        )
        session.add(new_run)
        session.commit()

    # Schedule background execution
    background_tasks.add_task(
        execute_mini_live_run,
        run_id=run_id,
        n_attacks=n_attacks,
        compare_v2=body.compare_v2,
        target_mode=body.target_mode,
        event_manager=global_event_manager,
        budget_cap_usd=0.08,
    )

    return {
        "run_id": run_id,
        "status": "running",
        "n_attacks": n_attacks,
        "compare_v2": body.compare_v2,
        "target_mode": body.target_mode,
        "budget_cap_usd": 0.08,
        "events_url": f"/api/runs/{run_id}/events",
    }


@app.get("/api/runs/{id}")
async def get_run(id: str) -> dict[str, Any]:
    """Get metadata and execution status for a run."""
    engine = init_db("runs/gauntlet.db")
    with Session(engine) as session:
        run_rec = session.get(Run, id)
        if not run_rec:
            raise HTTPException(status_code=404, detail=f"Run '{id}' not found")
        attacks = session.exec(select(Attack).where(Attack.run_id == id)).all()
        return {
            "id": run_rec.id,
            "status": run_rec.status,
            "created_at": run_rec.created_at,
            "cost_usd": run_rec.cost_usd,
            "config": json.loads(run_rec.config_json) if run_rec.config_json else {},
            "attacks_count": len(attacks),
            "breaches_count": sum(1 for a in attacks if a.outcome == "breach"),
        }


@app.get("/api/runs/{id}/events")
async def stream_run_events(id: str) -> StreamingResponse:
    """Stream live progress updates for a run via Server-Sent Events (SSE).

    Events: attack_started, attack_finished, run_complete, run_error.
    """
    async def event_generator():
        history, queue = await global_event_manager.subscribe(id)
        try:
            # First replay past events in order
            for item in history:
                evt_type = item["event"]
                evt_data = json.dumps(item["data"])
                yield f"event: {evt_type}\ndata: {evt_data}\n\n"
                if evt_type in ("run_complete", "run_error"):
                    return

            # Then stream real-time events as they occur
            while True:
                item = await queue.get()
                evt_type = item["event"]
                evt_data = json.dumps(item["data"])
                yield f"event: {evt_type}\ndata: {evt_data}\n\n"
                if evt_type in ("run_complete", "run_error"):
                    break
        finally:
            await global_event_manager.unsubscribe(id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/recorded")
async def get_recorded_overview() -> dict[str, Any]:
    """Return overview metadata of the recorded verification run."""
    results = get_cached_verify_results()
    if results is None:
        raise HTTPException(status_code=404, detail="No recorded run results available")
    return {
        "status": "recorded",
        "evaluation_type": results.get("evaluation_type"),
        "seed": results.get("seed"),
        "n_total": results.get("n_total"),
        "n_standard": results.get("n_standard"),
        "n_probe": results.get("n_probe"),
        "policy_hashes": results.get("policy_hashes"),
        "model_roles": get_recorded_model_roles(),
        "costs": results.get("costs"),
        "limitations": results.get("limitations"),
    }


@app.get("/api/verify/results")
async def get_verify_results() -> dict[str, Any]:
    """Return cached verification before/after report data without invoking models."""
    results = get_cached_verify_results()
    if results is None:
        raise HTTPException(status_code=404, detail="No verification results cached yet")
    return results
