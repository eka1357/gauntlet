# Gauntlet Deployment Guide (Static Mode)

This guide documents how to export static evaluation artifacts, build the Gauntlet web application without a backend dependency, and deploy the recorded evaluation experience.

---

## 1. Overview

Gauntlet supports a **zero-backend static mode**. In this mode:
- All recorded evaluation results, attack grids, policy definitions, Wilson confidence intervals, and execution traces are served directly as static JSON from `/data/*.json`.
- Zero live model calls are made.
- The web application runs completely standalone on any web server, CDN, or static file host.
- Live runs are permanently disabled (`LIVE_RUNS_ENABLED=false`) to protect API quotas and honor daily spend limits.

---

## 2. Step 1: Export Static Data

Run the static export script from the repository root to generate all required JSON assets from recorded fixtures:

```bash
py scripts/export_static.py
```

This script runs entirely in-process (zero model calls, zero external network egress) and populates `web/public/data/` with:
- `summary.json` — Headline evaluation metrics, Wilson CIs, costs, and limitations.
- `project_facts.json` — Verified Token Factory total usage ($12.40).
- `model_roles.json` — Verified model mapping (Ultra, Super, Lightning).
- `policy_v1.json` & `policy_v2.json` — Policy YAML definitions with verified SHA-256 hashes and per-rule rationales.
- `benign.json` — 3-repeat benign suite evaluation and negative control results.
- `report.json` — Complete before/after evaluation report payload.
- `health.json` — Static health state (`live_runs_enabled: false`, `static_mode: true`).
- `attacks.json` & `attacks_*.json` — Paginated attack records matching UI query patterns.
- `traces/*.json` — Stored execution traces for all 235 attacks across unhardened, v1, and v2 conditions (705 files total).

> **Verification:** The export script verifies that no API keys or environment secrets leak into any static file.

---

## 3. Step 2: Build the Frontend in Static Mode

Navigate to the `web/` directory and run the Next.js production build with `NEXT_PUBLIC_STATIC_DATA=true`.

### Linux / macOS / Bash:
```bash
cd web
NEXT_PUBLIC_STATIC_DATA=true npm run build
```

### Windows (PowerShell):
```powershell
cd web
$env:NEXT_PUBLIC_STATIC_DATA="true"
npm run build
```

### Windows (CMD):
```cmd
cd web
set NEXT_PUBLIC_STATIC_DATA=true
npm run build
```

When `NEXT_PUBLIC_STATIC_DATA` is `"true"`, `web/lib/api.ts` automatically routes all data requests to `/data/*.json` and disables live run dispatchers.

---

## 4. What to Upload

Depending on your hosting strategy:

### Option A: Next.js Node / Container Server
Upload:
- The compiled `.next/` build folder.
- The `web/public/` folder (including `web/public/data/`).
- `package.json` and production dependencies (`node_modules`).
- Set environment:
  ```env
  NEXT_PUBLIC_STATIC_DATA=true
  LIVE_RUNS_ENABLED=false
  NODE_ENV=production
  PORT=3000
  ```
- Start command: `npm run start`

### Option B: Pure Static Hosting (HTML/CSS/JS export)
If `next.config.ts` specifies `output: "export"`:
- Run `npm run build` to generate `web/out/`.
- Upload the entire contents of `web/out/` (which includes static pages, chunks, and the `/data/` folder).

---

## 5. Host-Specific Deployment Notes

> [!WARNING]
> **UNVERIFIED**: All instructions below for specific third-party hosting platforms are theoretical configuration templates and have **not** been verified on live infrastructure. Deployers must test their own configurations.

### Nebius Serverless / Container Registry (UNVERIFIED)
1. Build the production Docker image using `Dockerfile`.
2. Ensure container environment specifies `LIVE_RUNS_ENABLED=false` and `NEXT_PUBLIC_STATIC_DATA=true`.
3. Deploy container image to Nebius Serverless container service.
4. *(Status: Unverified)*

### Vercel (UNVERIFIED)
1. Link repository with Root Directory set to `web`.
2. In Project Settings > Environment Variables, add:
   - `NEXT_PUBLIC_STATIC_DATA` = `true`
   - `LIVE_RUNS_ENABLED` = `false`
3. Pre-build command: `cd .. && py scripts/export_static.py && cd web` (requires Python build environment) or commit the pre-built `web/public/data/` files to Git.
4. *(Status: Unverified)*

### Cloudflare Pages / Netlify (UNVERIFIED)
1. Build command: `npm run build` with `NEXT_PUBLIC_STATIC_DATA=true`.
2. Output directory: `.next` or `out`.
3. Commit `web/public/data/` to git prior to deployment.
4. *(Status: Unverified)*

---

## 6. Budget & Security Safeguards

- **`LIVE_RUNS_ENABLED=false`**: Never set `LIVE_RUNS_ENABLED=true` in public deployments.
- In static mode, the `/live` route displays an explanatory banner:
  > *"Live runs are off in this deployment. Recorded results are shown instead. Live model execution is disabled to preserve the daily cost cap and protect budget limits."*
  with a direct link back to the 235-attack recorded Range.
- The start button is disabled to guarantee zero failed requests and zero unintended model spend.
