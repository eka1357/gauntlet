# Gauntlet

Gauntlet attacks your AI agent until it breaks, fixes it, and proves the fix.

## Safety

Gauntlet only tests agents you own, in a sandbox with fake tools and data.
Payloads are prompt-injection text. No real exploit code, no real credentials,
no outbound network from the sandbox.

## Quick Start

```bash
cp .env.example .env
# Fill in NEBIUS_API_KEY, TAVILY_API_KEY
make install
make dev
```

## Configuration & Safeguards

- `NEBIUS_API_KEY`: API key for Nebius Token Factory inference.
- `NEBIUS_BASE_URL`: Base URL (default `https://api.tokenfactory.nebius.com/v1`).
- `TAVILY_API_KEY`: API key for Tavily search.
- `LIVE_RUNS_ENABLED`: Live runs are disabled by default. Must be set exactly to `"true"` (case-insensitive) to enable live runs (`POST /api/runs`). Any other value or omission pauses live runs with a 429 response pointing users to the recorded run.
- `TRUSTED_PROXY`: When set to `"true"`, client IP resolution trusts the `X-Forwarded-For` header. Defaults to `"false"` to prevent header spoofing attacks from bypassing IP rate limiters.
- `DAILY_SPEND_CAP_USD`: Maximum daily expenditure across live runs in USD (default `$0.40`).
- **Live Run Safeguards**: Live runs enforce a hard per-run cap of `$0.08`, a maximum of 8 attacks per run (validated by API schema and UI slider), and a per-IP rate limit of 3 runs per hour.

## License

MIT
