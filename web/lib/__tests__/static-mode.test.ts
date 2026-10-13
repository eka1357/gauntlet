import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import React from "react";
import ReactDOMServer from "react-dom/server";

// Force static mode in environment
process.env.NEXT_PUBLIC_STATIC_DATA = "true";

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

// Setup module resolver and tsx compiler hook for rendering tests in Node
import Module from "node:module";

const originalResolveFilename = (Module as unknown as { _resolveFilename: any })._resolveFilename;
(Module as unknown as { _resolveFilename: any })._resolveFilename = function (
  request: string,
  parent: unknown,
  isMain: boolean,
  options: unknown
) {
  if (request.startsWith("@/")) {
    const root = fs.existsSync(path.resolve(process.cwd(), "lib"))
      ? process.cwd()
      : path.resolve(process.cwd(), "web");
    request = path.join(root, request.slice(2));
  }
  return originalResolveFilename.call(this, request, parent, isMain, options);
};

// Compile ts and tsx files on the fly via typescript compiler
const ts = require("typescript");
const tsxLoader = function (mod: any, filename: string) {
  const content = fs.readFileSync(filename, "utf8");
  const transpiled = ts.transpileModule(content, {
    compilerOptions: {
      jsx: ts.JsxEmit.ReactJSX,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
    },
  });
  mod._compile(transpiled.outputText, filename);
};

require.extensions[".tsx"] = tsxLoader;
require.extensions[".ts"] = tsxLoader;

import {
  getRecordedSummary,
  getProjectFacts,
  getPolicy,
  getRecordedAttacks,
  getAttackTrace,
  getHealth,
  createRun,
  ApiError,
} from "../api.ts";

describe("Static Data Mode: API unreachable and offline execution", () => {
  const originalFetch = global.fetch;
  let apiCallAttempts: string[] = [];
  let staticDataRequests: string[] = [];

  const publicDataDir = fs.existsSync(path.resolve(process.cwd(), "public/data"))
    ? path.resolve(process.cwd(), "public/data")
    : path.resolve(process.cwd(), "web/public/data");

  before(() => {
    // Mock global fetch: fail immediately if any /api URL is accessed
    global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(input);

      if (urlStr.includes("/api/") || urlStr.includes(":8000")) {
        apiCallAttempts.push(urlStr);
        throw new Error(`FAIL: Network call attempted to live API in static mode: ${urlStr}`);
      }

      // Handle static data files
      if (urlStr.includes("/data/")) {
        staticDataRequests.push(urlStr);
        const match = urlStr.match(/\/data\/(.+)$/);
        const relPath = match ? match[1].split("?")[0] : "";
        const diskPath = path.join(publicDataDir, relPath);

        if (!fs.existsSync(diskPath)) {
          return new Response(`Not Found: ${diskPath}`, { status: 404, statusText: "Not Found" });
        }

        const raw = fs.readFileSync(diskPath, "utf-8");
        return new Response(raw, {
          status: 200,
          statusText: "OK",
          headers: { "Content-Type": "application/json" },
        });
      }

      throw new Error(`Unexpected fetch target in static mode: ${urlStr}`);
    }) as unknown as typeof fetch;
  });

  after(() => {
    global.fetch = originalFetch;
  });

  test("getRecordedSummary loads from /data/summary.json without contacting live API", async () => {
    const summary = await getRecordedSummary();
    assert.ok(summary);
    assert.equal(summary.naive_mode.n, 190);
    assert.equal(summary.realistic_mode.n, 190);
    assert.ok(summary.costs);
    assert.equal(summary.costs.total_usd, 4.1662);
    assert.equal(apiCallAttempts.length, 0, "No API requests must be made");
  });

  test("getProjectFacts loads from /data/project_facts.json without API calls", async () => {
    const facts = await getProjectFacts();
    assert.ok(facts);
    assert.equal(facts.total_project_usage_usd, 12.40);
    assert.equal(facts.formatted_project_usage, "$12.40");
    assert.equal(apiCallAttempts.length, 0);
  });

  test("getPolicy v1 and v2 load from static policy files with verified SHA-256", async () => {
    const p1 = await getPolicy("v1");
    assert.equal(p1.version, 1);
    assert.equal(p1.sha256, "f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265");

    const p2 = await getPolicy("v2");
    assert.equal(p2.version, 2);
    assert.equal(p2.sha256, "31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e");
    assert.equal(apiCallAttempts.length, 0);
  });

  test("getRecordedAttacks fulfills paginated requests in static mode", async () => {
    // Workspace pagination: limit=250
    const res250 = await getRecordedAttacks({ limit: 250 });
    assert.equal(res250.total, 235);
    assert.equal(res250.attacks.length, 235);

    // Policy page pagination: page 1 and page 2 with limit 150
    const p1 = await getRecordedAttacks({ page: 1, limit: 150 });
    assert.equal(p1.attacks.length, 150);

    const p2 = await getRecordedAttacks({ page: 2, limit: 150 });
    assert.equal(p2.attacks.length, 85);

    // Default pagination: page 1 with limit 50
    const p50 = await getRecordedAttacks({ page: 1, limit: 50 });
    assert.equal(p50.attacks.length, 50);

    assert.equal(apiCallAttempts.length, 0);
  });

  test("getAttackTrace loads execution traces offline", async () => {
    const tUnh = await getAttackTrace("conf2_std_email_001", "unhardened");
    assert.equal(tUnh.id, "conf2_std_email_001");
    assert.equal(tUnh.condition, "unhardened");
    assert.ok(Array.isArray(tUnh.trace));

    const tV2 = await getAttackTrace("conf2_std_email_001", "v2");
    assert.equal(tV2.id, "conf2_std_email_001");
    assert.equal(tV2.condition, "v2");
    assert.ok(Array.isArray(tV2.trace));
    assert.equal(apiCallAttempts.length, 0);
  });

  test("getHealth returns static mode health state without API calls", async () => {
    const health = await getHealth();
    assert.equal(health.status, "ok");
    assert.equal(health.live_runs_enabled, false);
    assert.equal(health.static_mode, true);
    assert.equal(apiCallAttempts.length, 0);
  });

  test("createRun rejects immediately in static mode with 400 ApiError", async () => {
    await assert.rejects(
      async () => {
        await createRun({ n_attacks: 4 });
      },
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal((err as ApiError).status, 400);
        assert.match((err as ApiError).message, /Live runs are off in this deployment/i);
        return true;
      }
    );
    assert.equal(apiCallAttempts.length, 0);
  });
});

describe("Page rendering in static mode with API unreachable", () => {
  const root = fs.existsSync(path.resolve(process.cwd(), "components"))
    ? process.cwd()
    : path.resolve(process.cwd(), "web");

  test("renders Workspace view cleanly in static mode", () => {
    const { WorkspaceView } = require(path.join(root, "components/Range/WorkspaceView.tsx"));
    const html = ReactDOMServer.renderToString(React.createElement(WorkspaceView));
    assert.ok(html.length > 0);
  });

  test("renders Results page cleanly in static mode", () => {
    const ResultsPage = require(path.join(root, "app/results/page.tsx")).default;
    const html = ReactDOMServer.renderToString(React.createElement(ResultsPage));
    assert.ok(html.length > 0);
  });

  test("renders Policy page cleanly in static mode", () => {
    const PolicyPage = require(path.join(root, "app/policy/page.tsx")).default;
    const html = ReactDOMServer.renderToString(React.createElement(PolicyPage));
    assert.ok(html.length > 0);
  });

  test("renders Report page cleanly in static mode", () => {
    const ReportPage = require(path.join(root, "app/report/page.tsx")).default;
    const html = ReactDOMServer.renderToString(React.createElement(ReportPage));
    assert.ok(html.length > 0);
  });

  test("renders Live page with clear disabled panel and cost cap explanation", () => {
    const LivePage = require(path.join(root, "app/live/page.tsx")).default;
    const html = ReactDOMServer.renderToString(React.createElement(LivePage));
    assert.ok(html.length > 0);
    // Assert required panel text is present
    assert.ok(
      html.includes("Live runs are off in this deployment. Recorded results are shown instead."),
      "Must display panel title"
    );
    assert.ok(
      html.includes("Live model execution is disabled to preserve the daily cost cap and protect budget limits."),
      "Must explain cost cap in one sentence"
    );
    assert.ok(
      html.includes("Explore the recorded Range on the Workspace"),
      "Must link to recorded Range"
    );
    assert.ok(
      html.includes("Live runs disabled"),
      "Start button must indicate live runs disabled"
    );
  });
});
