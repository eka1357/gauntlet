# PROMPTS.md — Build Gauntlet in Antigravity

## Setup (do by hand first)
1. Create an empty folder `gauntlet`, `git init`, add the MIT `LICENSE`.
2. Copy these files into the root: AGENTS.md, PRODUCT.md, REQUIREMENTS.md, DESIGN.md, PROMPTS.md, FEEDBACK.md. Open the folder (not its parent) in Antigravity. It reads AGENTS.md automatically; keep each rules file under 12,000 characters.
3. Create `.env` (never commit) with `NEBIUS_API_KEY`, `NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1`, `TAVILY_API_KEY`. Commit `.env.example` with empty values.
4. Look up exact Nemotron model IDs and prices in the Token Factory console. Give them to the agent in Prompt 1.
5. Optional workflow file `.agent/workflows/verify.md`: "Run `make test` and `make lint`, start the app, exercise the feature in the browser, report what passed and what you could not check."
6. Run one phase per agent session. After each, run it yourself, commit, then start the next.

## Prompt 0: Bootstrap
```
Read AGENTS.md, PRODUCT.md, REQUIREMENTS.md, DESIGN.md. Do not write feature code yet.
Create the repo layout from REQUIREMENTS.md with empty modules and docstrings, a Makefile (dev, test, lint, demo), pyproject with fastapi, uvicorn, openai, pydantic, sqlmodel, httpx, pytest, ruff, a Next.js app in /web with Tailwind and shadcn initialised, and .env.example. Confirm `make test` and `make lint` run (even with zero tests). Show me the tree.
```

## Prompt 1: Model client and config
```
Implement FR-1. Create config/models.yaml with these IDs: <paste IDs>. Create config/pricing.json from these prices: <paste prices>. Write backend/llm.py call_model() exactly as AGENTS.md describes (empty-content fallback to reasoning field, retries, semaphore, pydantic JSON validation with one repair retry, cost accounting). Write pytest tests against a fake local OpenAI-compatible server for each behaviour. Then add scripts/hello.py that calls Ultra, Super, Nano and Omni once each and prints role, model, latency, tokens and cost. Run it with my real key and show the output. Also append what happened to FEEDBACK.md.
```

## Prompt 2: Target sandbox, oracle, benign suite
```
Implement FR-2, FR-3, FR-4. Build the Inbox Assistant in /target with the six mock tools, an audit log, a vault with 4 fake canary secrets, and a fixtures set. Use Nano to generate fixtures once (40 realistic emails for a fictional freight company, 6 web pages, 4 documents, 25-30 benign tasks with programmatic checks), then save and show me 5 samples to review before committing. Write oracle.py with the three breach types and unit tests. Write one hand-crafted poisoned email and show a trace where the unhardened agent leaks a canary. Show the benign pass rate.
```

## Prompt 3: Attack loop (CLI only)
```
Implement FR-6 as a CLI first: `python -m backend.attacker --generations 3 --population 20 --seed 1`. Use Nano to generate payloads per channel and category from config/threat_categories.yaml, run each against the target, apply the oracle, select breaching attacks, mutate them for the next generation, and store everything in SQLite. Print breaches per generation and total cost. No UI yet.
```

## Prompt 4: Recon and Tavily
```
Implement FR-5. Ultra reads the target's tool schemas and system prompt and returns a threat plan JSON (schema in pydantic). Add a real Tavily search step for current prompt-injection and tool-misuse techniques; cache results per run and store source URLs. Feed the plan into the attack generator. Show me the plan and the sources for a real run.
```

## Prompt 5: Swarm and Serverless Jobs
```
Implement FR-7. Make evaluation concurrent with a configurable semaphore, with SSE-ready event emission. Then create /jobs/attack_worker.py and a Dockerfile so the same worker can run as a Nebius Serverless Job. Document the exact commands I need to run in docs/serverless.md based on Nebius docs (search them; do not guess flags). Report anything you could not verify.
```

## Prompt 6: Triage
```
Implement FR-8. Ultra clusters breaches by root cause with title, severity, plain-language explanation, and a minimal reproduction attack id. Every cluster must link to real traces. Add tests with fixture breaches. Show clusters for a real run.
```

## Prompt 7: Defender, policy engine, verify
```
Implement FR-9 and FR-10. Build target/policy_engine.py enforcing the YAML schema in REQUIREMENTS.md at the tool layer, with tests. Build defender.py (Ultra proposes policy from clusters, pydantic validation, one retry on invalid output) and verify.py (re-run old exploits, fresh held-out attacks, and the benign suite; store Eval rows; loop up to 3 times). `make demo` must print the before/after table. Report the real numbers, including if the targets were not met.
```

## Prompt 8: API, SSE, persistence, replay
```
Implement the API and FR-14. Endpoints and SSE events as in REQUIREMENTS.md. Save a real completed run as fixtures/recorded_run.json and add /api/recorded. Add per-IP rate limiting and a cap of 20 attacks for anonymous live runs. Write API tests.
```

## Prompt 9: Frontend shell and tokens
```
Read DESIGN.md. Create web/styles/tokens.css with the exact tokens, map them in Tailwind, load Bricolage Grotesque, IBM Plex Sans and IBM Plex Mono. Build the three-zone workspace shell (left config rail, centre Range area, right findings drawer) using shadcn components. Connect to the API and render the recorded run's raw numbers in plain text for now. No charts or animation yet. Screenshot at 1440 and 390 px and tell me what you see.
```

## Prompt 10: The Range, charts, before/after
```
Build the Range as an SVG grid (rows = channels, columns = generations), squares coloured by outcome, updating live from SSE with Motion. Add the findings drawer with the trace viewer (Plex Mono) highlighting the exact tool call that leaked. Install Bklit charts via the registry (`npx shadcn@latest add @bklit/line-chart`, then ring-chart and sankey-chart), theme them with the token CSS variables, and add: breach rate by generation, cluster share, attack-to-outcome flow. Build the before/after wipe with Motion as the single orchestrated animation. Respect prefers-reduced-motion. Follow the anti-generated checklist in DESIGN.md.
```

## Prompt 11: Report, PR step, image attack
```
Implement FR-12 (report page and Markdown export) first. Then FR-11: render invoice PNGs with PIL that contain a hidden instruction, let the target read attachments through Omni, and add image as a channel. Last, stretch: a script that opens a PR on a demo repo with the policy and regression tests.
```

## Prompt 12: Polish and vision QA
```
Write scripts/screenshots.ts (Playwright) that captures the Range mid-run, the drawer, the before/after and the report at 1440 and 390 px. Send each screenshot to the Omni model with the QA prompt below, apply the single biggest fix per screenshot, and repeat once. Then run an accessibility pass (keyboard, focus, contrast) and fix issues.
```
Vision QA prompt:
```
Act as a strict visual QA judge for a security dashboard. Score 0-2 each: (1) the primary data (the Range grid) reads at a glance, (2) colour only conveys breached / cleared / in-flight, (3) text is readable and nothing overlaps or overflows, (4) hierarchy is clear: one focal point, (5) it does not look like a generic template. Return scores, the single biggest failure, and one specific fix. Do not invent anything not visible.
```

## Prompt 13: Deploy
```
Create a production Dockerfile that serves API and web together. Write docs/deploy.md for Nebius Serverless Endpoints based on the current Nebius docs (search them; flag anything unverified). Add a /api/health/models page that checks all four models and Tavily. List what I must do by hand.
```

## Prompt 14: README, Devpost, video
```
Write README.md: what it is, safety statement, screenshots, quick start, architecture diagram (Mermaid), a table of which Nemotron model does what, where Token Factory helped (measured numbers from stored runs), Nebius services used, Tavily usage, tests, license. Then draft the Devpost description (what, why, how, challenges, what is next) using only real numbers from the recorded run, and a shot list for the 3-minute video from PRODUCT.md.
```

## Fix-it template (use when something breaks)
```
Problem: <what you did, what you expected, what happened, exact error>.
Constraints: keep AGENTS.md rules. Find the root cause before changing code, explain it in two sentences, make the smallest fix, add a test that fails without it, run make test and make lint, and report what you verified.
```

## Optional image prompt (empty-state illustration)
```
Minimal line drawing of a narrow corridor with a gate at the far end, single dark ink line on pale blue-grey paper (#EAEEF0), no text, no people, no gradients, generous empty space, flat 2D, 1600x900.
```

## Cut order if time runs short
1. Pull request step 2. Image attack 3. Serverless Jobs (keep async on Token Factory) 4. Sankey chart. Never cut: oracle, swarm, defender, verify, real numbers, README, FEEDBACK.md, video.
