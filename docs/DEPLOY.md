# Gauntlet Deployment Guide (Static Mode)

This guide documents the verified path to export static evaluation artifacts, build the Gauntlet web application without a backend dependency, and deploy the recorded evaluation experience from `web/out`.

---

## 1. Overview

Gauntlet supports a **zero-backend static mode**. In this mode:
- All recorded evaluation results, attack grids, policy definitions, Wilson confidence intervals, and execution traces are served directly as static JSON from `/data/*.json`.
- Zero live model calls are made.
- The web application runs completely standalone from pure HTML, CSS, JavaScript, and static JSON files.
- Live runs are permanently disabled (`LIVE_RUNS_ENABLED=false`) to protect API quotas and honor daily spend limits.

---

## 2. The One Verified Deployment Path

The following 3-step sequence is the single verified path to build and deploy Gauntlet:

### Step 1: Export Static Data
From the repository root, run the static export script:
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

### Step 2: Build the Frontend Static Export
In the `web/` directory, run the Next.js production build with `NEXT_PUBLIC_STATIC_DATA=true`:

**Linux / macOS / Bash:**
```bash
cd web
NEXT_PUBLIC_STATIC_DATA=true npm run build
```

**Windows (PowerShell):**
```powershell
cd web
$env:NEXT_PUBLIC_STATIC_DATA="true"
npm run build
```

**Windows (CMD):**
```cmd
cd web
set NEXT_PUBLIC_STATIC_DATA=true
npm run build
```

When `NEXT_PUBLIC_STATIC_DATA=true`, `web/next.config.ts` sets `output: "export"`, `trailingSlash: true`, and `images: { unoptimized: true }`. Next.js writes a fully static site to `web/out/`.

### Step 3: Deploy `web/out`
Deploy the contents of the `web/out/` directory to any static file server, static hosting provider, object storage bucket, or CDN.

To test locally with a plain static server (with NO Next server and NO backend running):
```bash
py -m http.server 3000 --directory web/out
```
Then open `http://localhost:3000` in your browser. All routes (`/`, `/results`, `/policy`, `/report`, `/live`) and direct deep links resolve cleanly from the exported HTML files.

---

## 3. Host-Specific Deployment Notes (UNVERIFIED)

> [!WARNING]
> **UNVERIFIED**: All instructions below for specific third-party hosting platforms are theoretical configuration templates and have **not** been verified on live infrastructure. Deployers must test their own configurations.

### Vercel (UNVERIFIED)
1. Link repository with Root Directory set to `web`.
2. Output Directory: `out` (or leave default for Next.js static export).
3. Environment variables: `NEXT_PUBLIC_STATIC_DATA=true`.
4. Ensure `web/public/data/` is generated before build, or commit static data files to the repository.
5. *(Status: UNVERIFIED)*

### Cloudflare Pages / Netlify (UNVERIFIED)
1. Build command: `npm run build`
2. Build output directory: `out`
3. Environment variable: `NEXT_PUBLIC_STATIC_DATA=true`
4. Pre-deploy requirement: Ensure `web/public/data/` files are present in source repository.
5. *(Status: UNVERIFIED)*

### Nebius Serverless / Container Registry (UNVERIFIED)
1. Build static assets into an Nginx or lightweight HTTP server container image from `web/out`.
2. Deploy container image to Nebius Serverless container service.
3. *(Status: UNVERIFIED)*

---

## 4. Budget & Security Safeguards

- **`LIVE_RUNS_ENABLED=false`**: Never set `LIVE_RUNS_ENABLED=true` in public deployments.
- In static mode, the `/live` route displays an explanatory banner:
  > *"Live runs are off in this deployment. Recorded results are shown instead. Live model execution is disabled to preserve the daily cost cap and protect budget limits."*
  with a direct link back to the 235-attack recorded Range.
- The start button is disabled to guarantee zero failed requests and zero unintended model spend.
