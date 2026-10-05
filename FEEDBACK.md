# FEEDBACK.md — keep this updated as you build

Devpost scores feedback on completeness, viability and impact. Be specific and name the tool.

## Nebius Token Factory
- Used for: all inference via the OpenAI-compatible endpoint (`openai` Python SDK, `AsyncOpenAI`).
- Zero to hello world (minutes, what slowed me): first live call worked on the first try once the exact, case-sensitive model IDs were in `config/models.yaml`. All 4 roles answered in 5.9s total (2026-10-05).
- Worked well: standard OpenAI usage block (prompt/completion tokens) returned for every model; no auth or base-URL surprises.
- Needs work (with exact error, model ID, date): model IDs are inconsistently cased (`nvidia/Nemotron-3-Ultra-550b-a55b` vs `nvidia/nemotron-3-super-120b-a12b`), easy to get wrong.
- Pricing / limits surprises: prices not yet filled in `config/pricing.json`; cost currently reports "price not set".
- Would I build with it again, and why:

## Nebius Serverless (Jobs / Endpoints)
- Used for / attempted:
- Docs gaps:
- What I would change:

## NVIDIA Nemotron models
| Model | Used for | Strengths | Problems |
|---|---|---|---|
| Nemotron 3 Ultra (`nvidia/Nemotron-3-Ultra-550b-a55b`) | recon, defender, clustering, report | clean answer in `content` ("ready", 17 tokens) | slowest: 3743 ms for a one-word reply |
| Nemotron 3 Super (`nvidia/nemotron-3-super-120b-a12b`) | target agent brain, strategic attacks | clean answer in `content` ("ready", 19 tokens), 689 ms | none seen yet |
| Nemotron 3.5 Lightning (`nvidia/Nemotron-3_5-Lightning`) | bulk payload generation | fastest: 410 ms | puts its thinking trace inline in `content` ("Here's a thinking process: ..."); hit max_tokens=32 before answering |
| Nemotron 3 Nano (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`) | fallback for Lightning | 1035 ms | `content` empty; answer came from the `reasoning` field, and that was still thinking when it hit max_tokens=32 |
| Nemotron 3 Nano Omni | | | |

Notes on reasoning-field output, JSON adherence, latency under concurrency:
- 2026-10-05 `scripts/hello.py`, prompt "Reply with the single word: ready", max_tokens=32:
  - Ultra, Super: `content`.
  - Nano: `reasoning` field (content empty).
  - Lightning: `content`, but the content is reasoning text.
- Implication: small token budgets on Lightning/Nano spend everything on thinking. Bulk generation will need a larger max_tokens or reasoning turned off; must be verified before Prompt 3.

## Tavily
- Used for:
- Quality of results:

## Overall
- Would I recommend this stack for agent security tooling:

## Build log

### Prompt 1: model client and config (2026-10-05)
- Time: about 12 min of active agent work, about 45 min wall clock (the session was interrupted by an agent server restart for about 34 min).
- Errors while building:
  - 3 retry tests failed at first: building `openai.APIStatusError` needs an `httpx.Response` with a request attached. Tests were later rewritten to use a fake FastAPI server through the real SDK.
  - The OpenAI SDK's default `max_retries=2` would have stacked silently under `call_model`'s own backoff. Now set to `max_retries=0`.
  - ruff import-order errors (fixed with isort `known-first-party`).
  - `make` is not installed on this Windows machine, so the lint and test commands were run directly.
- Live run errors: none. All 4 roles returned 200.
- Reasoning-field output: Nano (`reasoning` field). Lightning puts its reasoning inline in `content`.
