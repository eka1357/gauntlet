"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import {
  createRun,
  getApiBaseUrl,
  getHealth,
  IS_STATIC_DATA,
  AttackRecord,
  AttackConditionRecord,
} from "@/lib/api";
import { AttackCondition, getAttackSquareState } from "@/lib/range-utils";
import { AttackDrawer } from "@/components/Range/AttackDrawer";
import {
  parseSseStreamChunk,
  AttackStartedEventData,
  AttackFinishedEventData,
  RunCompleteEventData,
} from "@/lib/sse-client";

interface LogMessage {
  timestamp: string;
  type: "info" | "started" | "finished" | "complete" | "error";
  text: string;
}

export default function LivePage() {
  // Controls state
  const [targetMode, setTargetMode] = useState<"naive" | "realistic">("naive");
  const [nAttacks, setNAttacks] = useState<number>(6);
  const [compareV2, setCompareV2] = useState<boolean>(true);

  // Execution state
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [costUsd, setCostUsd] = useState<number>(0.0);
  const [elapsedSec, setElapsedSec] = useState<number>(0);
  const [runStatus, setRunStatus] = useState<
    "idle" | "running" | "completed" | "budget_capped" | "paused" | "error"
  >("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [liveRunsDisabled, setLiveRunsDisabled] = useState<boolean>(IS_STATIC_DATA);

  // Check health and deployment status for live runs
  useEffect(() => {
    if (IS_STATIC_DATA) {
      setLiveRunsDisabled(true);
      return;
    }
    let active = true;
    getHealth()
      .then((h) => {
        if (!active) return;
        if (h.live_runs_enabled === false) {
          setLiveRunsDisabled(true);
        }
      })
      .catch(() => {
        if (!active) return;
        setLiveRunsDisabled(true);
      });
    return () => {
      active = false;
    };
  }, []);

  // Attack telemetry
  const [liveAttacks, setLiveAttacks] = useState<AttackRecord[]>([]);
  const [selectedAttack, setSelectedAttack] = useState<AttackRecord | null>(null);
  const [drawerCondition, setDrawerCondition] = useState<AttackCondition>("unhardened");
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [runSummary, setRunSummary] = useState<RunCompleteEventData | null>(null);

  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  const appendLog = useCallback(
    (type: LogMessage["type"], text: string) => {
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];
      setLogs((prev) => [...prev, { timestamp: timeStr, type, text }]);
    },
    []
  );

  // Auto-scroll logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Elapsed timer
  useEffect(() => {
    if (isRunning) {
      timerRef.current = setInterval(() => {
        setElapsedSec((prev) => prev + 1);
      }, 1000);
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [isRunning]);

  // Handle Starting a Live Run
  const handleStartRun = async () => {
    if (isRunning || liveRunsDisabled) return;

    // Reset previous run telemetry
    setIsRunning(true);
    setRunStatus("running");
    setErrorMessage(null);
    setLiveAttacks([]);
    setSelectedAttack(null);
    setCostUsd(0.0);
    setElapsedSec(0);
    setLogs([]);
    setRunSummary(null);

    appendLog("info", `Initiating live run: ${nAttacks} attacks in ${targetMode} mode (Policy v2: ${compareV2 ? "enabled" : "disabled"})...`);

    try {
      const res = await createRun({
        n_attacks: nAttacks,
        compare_v2: compareV2,
        target_mode: targetMode,
      });

      setRunId(res.run_id);
      appendLog("info", `Run queued: ${res.run_id}. Subscribing to telemetry stream...`);

      // Start SSE Stream reading
      startStreamReader(res.run_id);
    } catch (err: unknown) {
      setIsRunning(false);
      const msg = err instanceof Error ? err.message : String(err);

      // Check if paused via kill switch or daily spend cap (HTTP 429)
      if (msg.includes("429") || msg.toLowerCase().includes("paused") || msg.toLowerCase().includes("rate limit")) {
        setRunStatus("paused");
        setErrorMessage(msg);
        appendLog("error", `Run rejected (HTTP 429): ${msg}`);
      } else {
        setRunStatus("error");
        setErrorMessage(msg);
        appendLog("error", `Failed to start run: ${msg}`);
      }
    }
  };

  const startStreamReader = async (currentRunId: string) => {
    const controller = new AbortController();
    abortControllerRef.current = controller;

    const base = getApiBaseUrl().replace(/\/$/, "");
    const streamUrl = `${base}/api/runs/${currentRunId}/events`;

    try {
      const res = await fetch(streamUrl, {
        signal: controller.signal,
        headers: { Accept: "text/event-stream" },
      });

      if (!res.ok) {
        if (res.status === 429) {
          setRunStatus("paused");
          setErrorMessage("Live runs are paused for today. Open the recorded run instead.");
          appendLog("error", "HTTP 429: Live runs are paused for today.");
        } else {
          setRunStatus("error");
          setErrorMessage(`HTTP ${res.status}: Failed to connect to event stream`);
          appendLog("error", `HTTP ${res.status}: Failed to connect to event stream`);
        }
        setIsRunning(false);
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) {
        throw new Error("ReadableStream not supported on response body");
      }

      const decoder = new TextDecoder();
      let streamBuffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const { events, remainingBuffer } = parseSseStreamChunk(chunk, streamBuffer);
        streamBuffer = remainingBuffer;

        for (const evt of events) {
          handleStreamEvent(evt.event, evt.data);
        }
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) {
        appendLog("info", "Stream connection closed by client.");
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      appendLog("error", `Connection lost: ${msg}`);
      setErrorMessage(`Connection lost: ${msg}`);
      setIsRunning(false);
    }
  };

  const handleStreamEvent = (eventName: string, data: unknown) => {
    if (eventName === "attack_started") {
      const started = data as AttackStartedEventData;
      appendLog(
        "started",
        `[#${started.index + 1}] Attack started: ${started.attack_id} (${started.channel} • ${started.category})`
      );
    } else if (eventName === "attack_finished") {
      const fin = data as AttackFinishedEventData;
      setCostUsd((prev) => +(prev + (fin.cost_usd || 0)).toFixed(4));

      // Construct lean AttackRecord
      const unhMetrics = fin.unhardened?.metrics || fin.metrics || {};
      const v2Metrics = fin.v2?.metrics || {};

      const unhRec: AttackConditionRecord = {
        outcome: fin.unhardened?.outcome || fin.outcome || "defended",
        m1: Boolean(unhMetrics.m1),
        m2: Boolean(unhMetrics.m2),
        m3: Boolean(unhMetrics.m3),
        m4: Boolean(unhMetrics.m4),
        unsafe: Boolean(unhMetrics.unsafe),
        policy_block_rule: fin.unhardened?.policy_block_rule || null,
      };

      const v2Rec: AttackConditionRecord = {
        outcome: fin.v2?.outcome || "defended",
        m1: Boolean(v2Metrics.m1),
        m2: Boolean(v2Metrics.m2),
        m3: Boolean(v2Metrics.m3),
        m4: Boolean(v2Metrics.m4),
        unsafe: Boolean(v2Metrics.unsafe),
        policy_block_rule: fin.v2?.policy_block_rule || null,
      };

      const newRecord: AttackRecord = {
        id: fin.attack_id,
        channel: fin.channel || "email",
        category: fin.category || "live_attack",
        strategy: fin.strategy || "Generated attack payload",
        is_probe: false,
        unhardened: unhRec,
        v1: {
          outcome: "defended",
          m1: false,
          m2: false,
          m3: false,
          m4: false,
          unsafe: false,
          policy_block_rule: null,
        },
        v2: v2Rec,
      };

      setLiveAttacks((prev) => [...prev, newRecord]);

      const unhStatusText = unhRec.unsafe ? "UNSAFE" : "Defended";
      const v2StatusText = compareV2
        ? ` | v2: ${v2Rec.unsafe ? "UNSAFE" : v2Rec.policy_block_rule ? `Blocked (${v2Rec.policy_block_rule})` : "Defended"}`
        : "";

      appendLog(
        "finished",
        `[#${fin.index + 1}] Finished ${fin.attack_id}: unhardened: ${unhStatusText}${v2StatusText} (+$${fin.cost_usd.toFixed(4)})`
      );
    } else if (eventName === "run_complete") {
      const summary = data as RunCompleteEventData;
      setRunSummary(summary);
      setIsRunning(false);
      setRunStatus(summary.status === "budget_capped" ? "budget_capped" : "completed");
      if (summary.total_cost_usd !== undefined) {
        setCostUsd(summary.total_cost_usd);
      }
      appendLog(
        "complete",
        `Run finished: ${summary.attacks_evaluated} attacks evaluated. Unhardened unsafe: ${summary.unhardened_unsafe ?? summary.unhardened_breaches ?? 0}, v2 unsafe: ${summary.v2_unsafe ?? summary.v2_breaches ?? 0}. Cost: $${summary.total_cost_usd.toFixed(4)}`
      );
    } else if (eventName === "run_error") {
      const errData = data as { error?: string };
      setIsRunning(false);
      setRunStatus("error");
      setErrorMessage(errData.error || "Run terminated with an error");
      appendLog("error", `Run error: ${errData.error || "Unknown error"}`);
    }
  };

  const handleSelectAttackSquare = (attack: AttackRecord, cond: AttackCondition) => {
    setSelectedAttack(attack);
    setDrawerCondition(cond);
  };

  const budgetPct = Math.min(100, Math.round((costUsd / 0.08) * 100));

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="font-display font-bold text-2xl text-[var(--ink)]">
          Live Attack Runner
        </h1>
        <p className="text-xs sm:text-sm text-[var(--ink-muted)] font-sans max-w-3xl mt-1 leading-relaxed">
          Live runs use email attacks, the channel where this agent failed in the recorded evaluation. Web and document attacks never succeeded in recorded runs.
        </p>
        <p className="text-xs sm:text-sm text-[var(--ink-muted)] font-sans max-w-3xl mt-1.5 leading-relaxed">
          Recorded evidence, email attacks only: realistic 32.7% [25.7%, 40.5%], naive 78.7% [71.4%, 84.5%]. Live runs use freshly generated email attacks and can differ.
        </p>
        <p className="text-xs sm:text-sm text-[var(--ink-muted)] font-sans max-w-3xl mt-1 leading-relaxed italic">
          Live attacks were generated differently from the recorded set; their success rates are not directly comparable.
        </p>
      </div>

      {/* Live Runs Disabled Panel (Static Mode or Live Runs Disabled) */}
      {liveRunsDisabled && (
        <div className="p-4 sm:p-5 rounded-[var(--radius-md)] bg-[var(--panel)] border-2 border-[var(--in-flight)] space-y-2">
          <div className="flex items-center gap-2 font-display font-semibold text-sm sm:text-base text-[var(--ink)]">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" className="text-[var(--in-flight)] shrink-0">
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
            <span>Live runs are off in this deployment. Recorded results are shown instead.</span>
          </div>
          <p className="text-xs sm:text-sm text-[var(--ink)] font-sans leading-relaxed">
            Live model execution is disabled to preserve the daily cost cap and protect budget limits.
          </p>
          <div className="pt-1">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 text-xs font-sans font-semibold underline text-[var(--cleared)] hover:text-[var(--ink)] transition-colors"
            >
              <span>Explore the recorded Range on the Workspace &rarr;</span>
            </Link>
          </div>
        </div>
      )}

      {/* Paused State Notification (HTTP 429) */}
      {runStatus === "paused" && !liveRunsDisabled && (
        <div className="p-4 rounded-[var(--radius-md)] bg-[var(--range-paper)] border border-[var(--in-flight)] space-y-2">
          <div className="flex items-center gap-2 font-semibold text-xs sm:text-sm text-[var(--in-flight)] font-sans">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
            <span>Live runs are paused for today.</span>
          </div>
          <p className="text-xs text-[var(--ink)] font-sans">
            Live runs are paused for today. Open the{" "}
            <Link href="/" className="font-semibold underline hover:text-[var(--ink)] text-[var(--cleared)]">
              recorded run
            </Link>{" "}
            instead to inspect the full 235-attack verification evidence without incurring model costs.
          </p>
        </div>
      )}

      {/* Error State */}
      {runStatus === "error" && errorMessage && (
        <div className="p-4 rounded-[var(--radius-md)] bg-[var(--range-paper)] border border-[var(--breach)] space-y-1">
          <div className="text-xs font-semibold text-[var(--breach)] font-sans">
            Run encountered an error
          </div>
          <p className="font-mono text-xs text-[var(--ink)] bg-[var(--panel)] p-2 rounded border border-[var(--rule)]">
            {errorMessage}
          </p>
        </div>
      )}

      {/* Run Complete Summary Banner */}
      {runStatus === "completed" && runSummary && (
        <div className="p-4 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--cleared)] space-y-2">
          <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-[var(--cleared)] font-sans">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                clipRule="evenodd"
              />
            </svg>
            <span>Live Run Complete</span>
          </div>
          <p className="text-xs text-[var(--ink)] font-sans">
            Evaluated {runSummary.attacks_evaluated} attacks • Unhardened unsafe:{" "}
            <strong>{runSummary.unhardened_unsafe ?? runSummary.unhardened_breaches ?? 0}</strong> • Policy v2 unsafe:{" "}
            <strong>{runSummary.v2_unsafe ?? runSummary.v2_breaches ?? 0}</strong> • Actual cost:{" "}
            <strong>${runSummary.total_cost_usd.toFixed(4)}</strong>
          </p>
          {(runSummary.unhardened_unsafe ?? runSummary.unhardened_breaches ?? 0) === 0 && (
            <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs text-[var(--ink)] font-sans">
              No unsafe actions in this run. In recorded evidence (email attacks only), naive-prompt attacks breach 78.7% [71.4%, 84.5%] and realistic 32.7% [25.7%, 40.5%];{" "}
              <Link href="/" className="font-semibold underline hover:text-[var(--ink)] text-[var(--cleared)]">
                open the recorded run
              </Link>.
            </div>
          )}
          <p className="text-xs text-[var(--ink-muted)] font-sans italic border-t border-[var(--rule)] pt-2 mt-2">
            Fresh random attacks, not selected by outcome. Many short runs show few or no unsafe results; the recorded run has the full evidence.
          </p>
        </div>
      )}

      {/* Controls & Configuration Bar */}
      <section className="p-4 sm:p-5 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)] space-y-4">
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans">
          Run Configuration
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
          {/* Target Mode */}
          <div>
            <label className="block text-xs font-sans font-medium text-[var(--ink)] mb-1.5">
              Target Mode:
            </label>
            <select
              value={targetMode}
              disabled={isRunning || liveRunsDisabled}
              onChange={(e) => setTargetMode(e.target.value as "naive" | "realistic")}
              className="w-full text-xs font-sans bg-[var(--range-paper)] border border-[var(--rule)] rounded-[var(--radius-sm)] p-2 text-[var(--ink)] focus:outline-none focus:ring-1 focus:ring-[var(--ink)] disabled:opacity-50"
            >
              <option value="naive">Naive prompt (default)</option>
              <option value="realistic">Realistic prompt (defensive baseline)</option>
            </select>
          </div>

          {/* Number of Attacks (1–8) */}
          <div>
            <label className="block text-xs font-sans font-medium text-[var(--ink)] mb-1.5">
              Number of Attacks (1–8):
            </label>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min="1"
                max="8"
                step="1"
                value={nAttacks}
                disabled={isRunning || liveRunsDisabled}
                onChange={(e) => setNAttacks(Number(e.target.value))}
                className="w-full cursor-pointer accent-[var(--ink)] disabled:opacity-50"
              />
              <span className="font-mono text-xs px-2 py-1 rounded bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)] font-semibold w-8 text-center shrink-0">
                {nAttacks}
              </span>
            </div>
          </div>

          {/* Compare with Policy v2 */}
          <div className="flex items-center gap-2 h-9">
            <input
              type="checkbox"
              id="compareV2"
              checked={compareV2}
              disabled={isRunning || liveRunsDisabled}
              onChange={(e) => setCompareV2(e.target.checked)}
              className="rounded border-[var(--rule)] text-[var(--ink)] focus:ring-[var(--ink)] disabled:opacity-50"
            />
            <label htmlFor="compareV2" className="text-xs font-sans text-[var(--ink)] select-none">
              Also run against Policy v2
            </label>
          </div>

          {/* Start Run Button */}
          <div>
            <button
              type="button"
              disabled={isRunning || liveRunsDisabled}
              onClick={handleStartRun}
              title={liveRunsDisabled ? "Live runs are off in this deployment" : undefined}
              className="w-full py-2 px-4 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] font-sans font-semibold text-xs hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
            >
              {liveRunsDisabled ? (
                <span>Live runs disabled</span>
              ) : isRunning ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[var(--panel)] border-t-transparent rounded-full animate-spin" />
                  <span>Streaming attacks...</span>
                </>
              ) : (
                <span>Start Live Run</span>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* Live Status Line (state, elapsed, attacks, cost) */}
      <section className="p-3.5 sm:p-4 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)]">
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-sans">
          <div className="flex flex-wrap items-center gap-4 sm:gap-6 text-[var(--ink)]">
            <div>
              <span className="text-[var(--ink-muted)]">State: </span>
              <span className="font-semibold capitalize">{runStatus}</span>
              {runId && <span className="ml-1.5 font-mono text-[11px] text-[var(--ink-muted)]">({runId})</span>}
            </div>
            <div>
              <span className="text-[var(--ink-muted)]">Elapsed: </span>
              <span className="font-mono font-medium">{elapsedSec}s</span>
            </div>
            <div>
              <span className="text-[var(--ink-muted)]">Attacks: </span>
              <span className="font-mono font-medium">{liveAttacks.length} / {nAttacks}</span>
              {liveAttacks.length > 0 && (
                <span className="ml-1 text-[var(--ink-muted)]">
                  ({liveAttacks.filter((a) => a.unhardened.unsafe).length} unsafe unhardened)
                </span>
              )}
            </div>
            <div>
              <span className="text-[var(--ink-muted)]">Cost: </span>
              <span className="font-mono font-medium">${costUsd.toFixed(4)}</span>
              <span className="text-[var(--ink-muted)]"> / $0.0800 ({budgetPct}%)</span>
            </div>
          </div>
        </div>
      </section>

      {/* Mini Range: Paired Squares (Unhardened vs Policy v2) */}
      <section className="p-4 sm:p-5 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[var(--rule)]">
          <div>
            <h2 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)]">
              Mini Range (Live Stream)
            </h2>
            <p className="text-xs text-[var(--ink-muted)] font-sans">
              Each attack renders a pair of squares: Unhardened (top) and Policy v2 (bottom). Click any square to view its trace.
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs font-sans text-[var(--ink-muted)]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[var(--breach)]" />
              <span>Unsafe</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[var(--defended)] border border-[var(--cleared)]" />
              <span>Rule stopped</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[var(--defended)]" />
              <span>Defended</span>
            </div>
          </div>
        </div>

        {liveAttacks.length === 0 ? (
          <div className="p-8 text-center text-xs text-[var(--ink-muted)] font-mono bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)]">
            {liveRunsDisabled ? (
              <div className="space-y-2">
                <p>Live runs are disabled in this deployment.</p>
                <Link
                  href="/"
                  className="inline-block font-sans font-medium underline text-[var(--cleared)] hover:text-[var(--ink)]"
                >
                  Open the recorded Range to inspect all 235 verification attacks &rarr;
                </Link>
              </div>
            ) : isRunning ? (
              "Waiting for incoming attack_finished stream events..."
            ) : (
              "Click 'Start Live Run' above to launch attacks and stream live squares."
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-3">
              {liveAttacks.map((att, idx) => {
                const unhState = getAttackSquareState(att, "unhardened");
                const v2State = getAttackSquareState(att, "v2");

                return (
                  <div
                    key={att.id}
                    className="p-2 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] space-y-2 flex flex-col items-center"
                  >
                    <div className="font-mono text-xs font-semibold text-[var(--ink-muted)]">
                      #{idx + 1}
                    </div>

                    <div className="flex flex-col gap-1.5 items-center">
                      {/* Unhardened Square */}
                      <button
                        type="button"
                        onClick={() => handleSelectAttackSquare(att, "unhardened")}
                        title={`Attack #${idx + 1} [Unhardened]: ${unhState.status}`}
                        className="relative w-7 h-7 rounded-sm flex items-center justify-center transition-transform hover:scale-110 focus:outline-none focus:ring-2 focus:ring-[var(--ink)]"
                        style={{
                          backgroundColor:
                            unhState.fillColor === "breach"
                              ? "var(--breach)"
                              : unhState.fillColor === "in-flight"
                              ? "var(--in-flight)"
                              : "var(--defended)",
                          border: unhState.hasTealOutline
                            ? "2px solid var(--cleared)"
                            : "1px solid var(--rule)",
                        }}
                      >
                        {unhState.isUnsafe && (
                          <svg className="w-full h-full p-1" viewBox="0 0 20 20">
                            <line
                              x1="3"
                              y1="3"
                              x2="17"
                              y2="17"
                              stroke="var(--panel)"
                              strokeWidth="2.5"
                              strokeLinecap="round"
                            />
                          </svg>
                        )}
                        {unhState.isCanaryOnly && (
                          <div className="w-2 h-2 rounded-full bg-[var(--ink)]" />
                        )}
                      </button>
                      <span className="text-[10px] text-[var(--ink-muted)] font-mono">unh</span>

                      {/* Policy v2 Square */}
                      {compareV2 && (
                        <>
                          <button
                            type="button"
                            onClick={() => handleSelectAttackSquare(att, "v2")}
                            title={`Attack #${idx + 1} [Policy v2]: ${v2State.status}`}
                            className="relative w-7 h-7 rounded-sm flex items-center justify-center transition-transform hover:scale-110 focus:outline-none focus:ring-2 focus:ring-[var(--ink)] mt-1"
                            style={{
                              backgroundColor:
                                v2State.fillColor === "breach"
                                  ? "var(--breach)"
                                  : v2State.fillColor === "in-flight"
                                  ? "var(--in-flight)"
                                  : "var(--defended)",
                              border: v2State.hasTealOutline
                                ? "2px solid var(--cleared)"
                                : "1px solid var(--rule)",
                            }}
                          >
                            {v2State.isUnsafe && (
                              <svg className="w-full h-full p-1" viewBox="0 0 20 20">
                                <line
                                  x1="3"
                                  y1="3"
                                  x2="17"
                                  y2="17"
                                  stroke="var(--panel)"
                                  strokeWidth="2.5"
                                  strokeLinecap="round"
                                />
                              </svg>
                            )}
                            {v2State.isCanaryOnly && (
                              <div className="w-2 h-2 rounded-full bg-[var(--ink)]" />
                            )}
                          </button>
                          <span className="text-[10px] text-[var(--cleared)] font-mono font-semibold">
                            v2
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* Monospace Event Log */}
      <section className="space-y-2">
        <div className="flex items-center justify-between text-xs font-semibold text-[var(--ink-muted)] font-sans">
          <span>Live Stream Event Log</span>
          <span>{logs.length} events logged</span>
        </div>
        <div
          ref={logContainerRef}
          className="font-mono text-xs bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-3 max-h-48 overflow-y-auto space-y-1 select-all"
        >
          {logs.length === 0 ? (
            <div className="text-[var(--ink-muted)] italic">
              {liveRunsDisabled
                ? "Live runs are disabled. Event log is inactive in this deployment."
                : "Log is empty. Start a run to view SSE stream messages."}
            </div>
          ) : (
            logs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2 leading-relaxed">
                <span className="text-[var(--ink-muted)] select-none shrink-0">
                  [{log.timestamp}]
                </span>
                <span
                  className={
                    log.type === "error"
                      ? "text-[var(--breach)] font-semibold"
                      : log.type === "complete"
                      ? "text-[var(--cleared)] font-semibold"
                      : log.type === "started"
                      ? "text-[var(--in-flight)]"
                      : "text-[var(--ink)]"
                  }
                >
                  {log.text}
                </span>
              </div>
            ))
          )}
        </div>
      </section>

      {/* Attack Detail Drawer */}
      <AttackDrawer
        attack={selectedAttack}
        condition={drawerCondition}
        onConditionChange={setDrawerCondition}
        onClose={() => setSelectedAttack(null)}
      />
    </div>
  );
}
