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

## License

MIT
