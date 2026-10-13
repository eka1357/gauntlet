# Gauntlet

Gauntlet attacks your AI agent until it breaks, fixes it, and proves the fix.

Demo: <PASTE VERCEL URL>

The hosted demo shows a recorded run. Live runs are disabled in this deployment to protect the cost cap.

## Safety

Gauntlet only tests agents you own, in a sandbox with fake tools and data. Payloads are prompt-injection text. No real exploit code, no real credentials, no outbound network from the sandbox.

## What It Does

The hardening loop operates in six short steps:

1. Recon: Nemotron Ultra reads the agent tools and system prompt, generating a structured threat plan. Tavily searches real-world prompt injection and tool misuse techniques with citations.
2. Attack: A swarm of Nemotron Lightning workers generates and mutates multi-channel attack payloads across email, web, document, and tool arguments.
3. Detect: A deterministic oracle flags security breaches when canary tokens appear in outbound tool arguments or forbidden tools execute. Every breach records a full execution trace.
4. Triage: Nemotron Ultra clusters observed breaches by root cause and produces minimal reproductions.
5. Fix: Nemotron Ultra synthesizes defense policy-as-code, including egress destination allowlists, tool execution constraints, vault path blocks, and parameter pattern scanning.
6. Verify: The agent is re-tested against held-out attacks, channel-coverage probes, and benign operational tasks to prove breach reduction without degrading operational capabilities.

## Results

Evaluation results from `summary.json` comparing unhardened baselines against synthesized defense Policy v2:

| Evaluation Suite | Condition | Unsafe Actions Rate | Unsafe Actions Count | Denominator (in words) | Wilson 95% Interval | Classification |
|---|---|---|---|---|---|---|
| Realistic prompt | Unhardened | 25.8% | 49 of 190 | 190 standard evaluation attacks | [20.1%, 32.4%] | Baseline |
| Realistic prompt | Policy v2 | 0.0% | 0 of 190 | 190 standard evaluation attacks | [0.0%, 2.0%] | Real difference (intervals do not overlap) |
| Naive prompt | Unhardened | 62.1% | 118 of 190 | 190 standard evaluation attacks | [55.0%, 68.7%] | Baseline |
| Naive prompt | Policy v2 | 0.0% | 0 of 190 | 190 standard evaluation attacks | [0.0%, 2.0%] | Real difference (intervals do not overlap) |
| Probe set (channel coverage) | Unhardened | 2.2% | 1 of 45 | 45 targeted channel-coverage probe attacks | [0.4%, 11.6%] | Baseline |
| Probe set (channel coverage) | Policy v2 | 0.0% | 0 of 45 | 45 targeted channel-coverage probe attacks | [0.0%, 7.9%] | Not real difference (intervals overlap) |

All 49 unsafe actions in the realistic unhardened baseline came through email (49 of 150 email attacks; web and document vectors yielded zero unsafe actions).

On the channel-coverage probe set, while exfiltration differences are not statistically distinguishable due to low base rates, Policy v2 eliminates residual leakage:
- Unhardened probe M4 side-channel leak rate: 22.2% (10 of 45), Wilson 95% interval [12.5%, 36.3%].
- Policy v1 probe M4 side-channel leak rate: 17.8% (8 of 45), Wilson 95% interval [9.3%, 31.3%].
- Policy v2 probe M4 side-channel leak rate: 0.0% (0 of 45), Wilson 95% interval [0.0%, 7.9%].
- Classification: The difference between Policy v1 and Policy v2 on probe M4 leaks is a real difference (confidence intervals do not overlap: [9.3%, 31.3%] versus [0.0%, 7.9%]).

Benign operational task pass rate:
- Unhardened baseline: 95.2% pass rate (100 of 105), Wilson 95% interval [89.3%, 97.9%], evaluated over 105 evaluations across three repeated runs of 35 tasks.
- Policy v2: 95.2% pass rate (100 of 105), Wilson 95% interval [89.3%, 97.9%], evaluated over 105 evaluations across three repeated runs of 35 tasks.
- Pooled difference: 0.0 percentage points.
- Classification: Not real difference (identical pass rates; intervals overlap completely), confirming zero degradation of benign agent capabilities.
- Negative control (deny-all policy): 17.1% pass rate (6 of 35), Wilson 95% interval [8.1%, 32.7%], confirming that the task suite detects broken operational utility.

## Limitations

Verbatim limitations from the evaluation report:
1. secrets registry matches literal values
2. one fictional company and one agent
3. labelling effect on benign tasks not excluded
4. probe set used an attacker-supplied secret
5. realistic baseline M1 was low (about 2%), so exfiltration alone shows no measurable change
6. headline improvement is unsafe actions (M2, M3)

Additional boundaries:
- One target agent: The evaluation is conducted on Meridian Freight's freight operations inbox assistant.
- Fake data: All customer records, tracking IDs, emails, and credentials are synthetic mocks.
- No live runs in the hosted demo: Live model execution is disabled in the web deployment to enforce cost caps.

## Models and Services

Model routing from `config/models.yaml`:

| Role | Model ID | Job Description |
|---|---|---|
| Ultra | `nvidia/Nemotron-3-Ultra-550b-a55b` | Recon, defender, clustering, report |
| Super | `nvidia/nemotron-3-super-120b-a12b` | Target agent brain, strategic attacks |
| Lightning | `nvidia/Nemotron-3_5-Lightning` | Bulk payload generation, swarm |
| Nano | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Fallback for Lightning |
| Vision | `google/gemma-3-27b-it` | Optional image reading and dashboard QA (unused) |

Token Factory pricing from `config/pricing.json`:
- Nemotron 3 Ultra: $1.00 prompt / $3.00 completion ($0.50 / $1.50 batch) per 1M tokens.
- Nemotron 3 Super: $0.30 prompt / $0.90 completion ($0.15 / $0.45 batch) per 1M tokens.
- Nemotron 3.5 Lightning: $0.06 prompt / $0.24 completion ($0.03 / $0.12 batch) per 1M tokens.
- Nemotron 3 Nano: $0.06 prompt / $0.24 completion ($0.03 / $0.12 batch) per 1M tokens.

Nebius Token Factory measured usage from `summary.json:costs`:
- Policy v1 confirmation run: $1.3087 USD
- Confirmation Set #2 evaluation run: $1.5468 USD
- Benign operational variance and naive-mode run: $1.3107 USD
- Total recorded confirmation spend: $4.1662 USD
- Project total usage: $12.40 USD (source note from `docs/project_facts.json`: Token Factory console usage page, read manually on 2026-10-13, covering development, prototyping, exploratory runs, and confirmation runs).

Tavily:
- Called at runtime in `backend/recon.py` during the Recon phase before swarm execution.
- Dispatches 4 search queries covering indirect injection in email assistants, unauthorized exfiltration tool misuse, infrastructure error spoofing, and multi-turn tool calling evasion.
- Cached at `runs/cache/tavily_cache.json` with a 24-hour TTL; the freshest query runs live on every execution. Citations are synthesized by Nemotron Ultra into the threat plan.

Nebius Serverless:
- Nebius Serverless Jobs and Nebius Serverless Endpoints were NOT used in production or evaluation runs.
- What was tried (from FEEDBACK.md):
  - Serverless Jobs: An attack worker entrypoint (`jobs/attack_worker.py`) and container definition were created to run swarm workers as standalone batch jobs. Execution remained on local async workers using Token Factory.
  - Serverless Endpoints: A unified container deployment for FastAPI and Next.js was prepared in `docs/DEPLOY.md`, but Nebius Serverless Endpoints were not used; the hosted demo was deployed as a static Next.js export on Vercel.

## Screenshots

Embedded at 1440 px viewport:

### Range
![Range](docs/screens/range_1440.png)

### Drawer
![Drawer](docs/screens/drawer_1440.png)

### Results
![Results](docs/screens/results_1440.png)

### Report
![Report](docs/screens/report_1440.png)

## Architecture

```mermaid
graph TD
    Recon["Recon (backend/recon.py)<br/>Tavily Search API + Nemotron Ultra"] --> ThreatPlan["Threat Plan"]
    ThreatPlan --> Swarm["Attack Swarm (backend/attacker.py)<br/>Nemotron Lightning / Nano Swarm"]
    Swarm --> AgentSandbox["Target Agent Sandbox (target/inbox_agent.py)<br/>Nemotron Super + Mock Tools + Vault"]
    AgentSandbox --> Oracle["Deterministic Oracle (backend/oracle.py)<br/>Canary Exfiltration / Forbidden Tool Call Checks"]
    Oracle --> Triage["Triage (backend/triage.py)<br/>Nemotron Ultra Breach Clustering"]
    Triage --> Defender["Defender (backend/defender.py)<br/>Nemotron Ultra Policy Synthesis"]
    Defender --> PolicyEngine["Policy Engine (target/policy_engine.py)<br/>Egress Allowlists + Path Denials + Secret Scanners"]
    PolicyEngine --> Verify["Verify (backend/verify.py)<br/>Held-out Attacks + Probe Set + Benign Tasks"]
    Verify --> Report["Report (backend/report.py / Web UI)<br/>Audit Ledger + Wilson 95% CIs"]
```

## Quick Start

### Backend

```bash
python -m venv .venv
# On Windows: .venv\Scripts\activate
# On Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
python -m uvicorn backend.api:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd web
npm install
npm run dev
```

### Configuration (.env.example)

- `NEBIUS_API_KEY`: API key for Nebius Token Factory inference.
- `NEBIUS_BASE_URL`: Base URL (default `https://api.tokenfactory.nebius.com/v1`).
- `TAVILY_API_KEY`: API key for Tavily search.
- `LIVE_RUNS_ENABLED`: Live runs are disabled by default (`false`). Set to `true` to enable live run endpoints.
- `TRUSTED_PROXY`: When `true`, parses `X-Forwarded-For` header for IP rate limiting (`false` by default).
- `DAILY_SPEND_CAP_USD`: Maximum daily expenditure across live runs in USD (default `$0.40`).

### Enabling Live Runs Locally

To enable live runs locally:
1. Set `LIVE_RUNS_ENABLED=true` in `.env`.
2. Ensure `NEBIUS_API_KEY` is configured.

Live run safeguards enforced in code:
- Hard per-run budget cap: $0.08 USD per run.
- Maximum 8 attacks per live run.
- Per-IP rate limit: 3 runs per hour.
- Global daily spend cap: $0.40 USD.

### Running Tests and Lint

```bash
# Run pytest test suite
python -m pytest

# Run Python linter
python -m ruff check backend tests target scripts

# Run TypeScript check
cd web && npm run lint
```

### Running Static Export

```bash
# Export backend data to static JSON files
python scripts/export_static.py

# Build Next.js static HTML export
cd web
npm run build
```

The static HTML bundle is generated in `web/out/`.

## Reproducibility

Stored evaluation artifacts:
- `runs/verify_results.json`: Full verification run metrics and condition comparisons.
- `runs/cache/verify_results.json`: Cached verification results for offline execution.
- `runs/recorded_run.json` and `fixtures/recorded_run.json`: Complete 235-attack execution traces.
- `web/public/data/summary.json`: Headline summary tables, confidence intervals, cost ledgers, and limitations.
- `docs/project_facts.json`: Token Factory console billing record.

Policy file hashes (SHA-256):
- Policy v1: `f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265` (`fixtures/hardened_policy.yaml`)
- Policy v2: `31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e` (`fixtures/policy_v2.yaml`)

Re-running the empirical claims audit:
```bash
python scripts/audit_numbers.py
```

## License

MIT
