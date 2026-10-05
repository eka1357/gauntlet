"""FastAPI application and route definitions.

Endpoints:
    POST /api/runs          — start a new hardening run
    GET  /api/runs/{id}     — get run status and summary
    GET  /api/runs/{id}/events — SSE stream for live updates
    POST /api/runs/{id}/harden — trigger defender + verify
    GET  /api/runs/{id}/report — final hardening report
    GET  /api/attacks/{id}/trace — full attack trace
    GET  /api/recorded      — return the stored recorded run
    GET  /api/health/models — check model availability
"""

from fastapi import FastAPI

app = FastAPI(
    title="Gauntlet",
    description="AI agent hardening API",
    version="0.1.0",
)


@app.get("/api/health")
async def health() -> dict:
    """Basic health check."""
    return {"status": "ok"}
