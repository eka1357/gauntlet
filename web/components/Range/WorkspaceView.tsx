"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import {
  AttackRecord,
  getRecordedAttacks,
  getRecordedSummary,
  RecordedSummary,
  ApiError,
} from "@/lib/api";
import {
  AttackCondition,
  computeWilsonCi,
  getAttackSquareState,
} from "@/lib/range-utils";
import { RangeGrid } from "./RangeGrid";
import { RangeCounter } from "./RangeCounter";
import { RangeFilters } from "./RangeFilters";
import { LeftRailFacts } from "./LeftRailFacts";
import { AttackDrawer } from "./AttackDrawer";

export function WorkspaceView() {
  const [attacks, setAttacks] = useState<AttackRecord[]>([]);
  const [summary, setSummary] = useState<RecordedSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  // Interaction State
  const [condition, setCondition] = useState<AttackCondition>("unhardened");
  const [selectedAttack, setSelectedAttack] = useState<AttackRecord | null>(null);
  const [isWiping, setIsWiping] = useState(false);
  const [factsExpanded, setFactsExpanded] = useState(true);

  // Filter State
  const [channelFilter, setChannelFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [onlyUnsafeUnhardened, setOnlyUnsafeUnhardenedChange] = useState(false);

  // Fetch all attacks and summary once, client-side
  useEffect(() => {
    let active = true;

    Promise.all([
      getRecordedAttacks({ limit: 250 }),
      getRecordedSummary(),
    ])
      .then(([attacksRes, summaryRes]) => {
        if (!active) return;
        setAttacks(attacksRes.attacks);
        setSummary(summaryRes);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setError(
          err instanceof ApiError
            ? err
            : new ApiError(String(err), 0, "Ensure backend is running with 'py -m uvicorn backend.api:app --port 8000'.")
        );
        setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  // Dismissible Framing Block state
  const [framingDismissed, setFramingDismissed] = useState<boolean>(() => {
    try {
      if (typeof window !== "undefined") {
        return localStorage.getItem("gauntlet_framing_dismissed") === "true";
      }
    } catch {
      // Ignore storage errors
    }
    return false;
  });

  const handleDismissFraming = () => {
    setFramingDismissed(true);
    try {
      localStorage.setItem("gauntlet_framing_dismissed", "true");
    } catch {
      // Ignore storage errors
    }
  };

  // Condition switch handler with orchestrated before/after wipe
  const handleConditionChange = (nextCondition: AttackCondition) => {
    if (condition === "unhardened" && nextCondition === "v2") {
      setIsWiping(true);
      setCondition("v2");
      setTimeout(() => {
        setIsWiping(false);
      }, 950);
    } else {
      setIsWiping(false);
      setCondition(nextCondition);
    }
  };

  // Derive unique categories for filter dropdown
  const availableCategories = useMemo(() => {
    const set = new Set<string>();
    attacks.forEach((a) => set.add(a.category));
    return Array.from(set).sort();
  }, [attacks]);

  // Apply filters to attacks
  const filteredAttacks = useMemo(() => {
    return attacks.filter((a) => {
      // Channel filter
      if (channelFilter === "probes") {
        if (!a.is_probe) return false;
      } else if (channelFilter !== "all") {
        if (a.is_probe || a.channel !== channelFilter) return false;
      }

      // Category filter
      if (categoryFilter !== "all" && a.category !== categoryFilter) {
        return false;
      }

      // Only unsafe when unhardened
      if (onlyUnsafeUnhardened) {
        const wasUnsafe = getAttackSquareState(a, "unhardened").isUnsafe;
        if (!wasUnsafe) return false;
      }

      return true;
    });
  }, [attacks, channelFilter, categoryFilter, onlyUnsafeUnhardened]);

  // Compute live counter stats from visible squares (splitting standard vs probes)
  const {
    standardUnsafeCount,
    totalStandard,
    standardWilsonCi,
    probeUnsafeCount,
    totalProbes,
    probeAmberCount,
    probeWilsonCi,
    redCount,
    amberCount,
    greyCount,
    tealOutlineCount,
    attribution,
  } = useMemo(() => {
    let stdUnsafe = 0;
    let stdTotal = 0;
    let prbUnsafe = 0;
    let prbTotal = 0;
    let prbAmber = 0;

    let red = 0;
    let amber = 0;
    let grey = 0;
    let teal = 0;

    filteredAttacks.forEach((a) => {
      const state = getAttackSquareState(a, condition);
      if (a.is_probe) {
        prbTotal++;
        if (state.isUnsafe) prbUnsafe++;
        if (state.isCanaryOnly) prbAmber++;
      } else {
        stdTotal++;
        if (state.isUnsafe) stdUnsafe++;
      }

      if (state.isUnsafe) {
        red++;
      } else if (state.isCanaryOnly) {
        amber++;
      } else {
        grey++;
      }
      if (state.hasTealOutline) {
        teal++;
      }
    });

    const stdCi = computeWilsonCi(stdUnsafe, stdTotal);
    const prbCi = computeWilsonCi(prbUnsafe, prbTotal);

    // Hardening attribution for standard attacks
    const unhardenedUnsafeStd = filteredAttacks.filter(
      (a) => !a.is_probe && getAttackSquareState(a, "unhardened").isUnsafe
    );
    const n = unhardenedUnsafeStd.length;
    let x = 0;
    let y = 0;
    unhardenedUnsafeStd.forEach((a) => {
      const st = getAttackSquareState(a, condition);
      if (st.policyRule) {
        x++;
      } else if (!st.isUnsafe) {
        y++;
      }
    });

    return {
      standardUnsafeCount: stdUnsafe,
      totalStandard: stdTotal,
      standardWilsonCi: stdCi,
      probeUnsafeCount: prbUnsafe,
      totalProbes: prbTotal,
      probeAmberCount: prbAmber,
      probeWilsonCi: prbCi,
      redCount: red,
      amberCount: amber,
      greyCount: grey,
      tealOutlineCount: teal,
      attribution: {
        nUnsafeUnhardened: n,
        xStoppedByRule: x,
        yDidNotRecur: y,
      },
    };
  }, [filteredAttacks, condition]);

  const standardCount = useMemo(() => attacks.filter((a) => !a.is_probe).length, [attacks]);
  const probeCount = useMemo(() => attacks.filter((a) => a.is_probe).length, [attacks]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <div className="w-6 h-6 border-2 border-[var(--ink)] border-t-transparent rounded-full animate-spin" />
        <span className="font-mono text-xs text-[var(--ink-muted)]">
          Loading recorded evaluation telemetry...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto my-12 p-6 bg-[var(--panel)] border border-[var(--breach)] rounded-[var(--radius-md)] space-y-4">
        <div className="flex items-center gap-2 text-[var(--breach)] font-semibold text-sm">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path
              fillRule="evenodd"
              d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
              clipRule="evenodd"
            />
          </svg>
          API Error: Failed to load evaluation data
        </div>
        <p className="font-mono text-xs text-[var(--ink)] bg-[var(--range-paper)] p-3 rounded border border-[var(--rule)]">
          {error.message}
        </p>
        {error.actionGuide && (
          <p className="text-xs text-[var(--ink-muted)] font-sans">
            <strong>Remediation:</strong> {error.actionGuide}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Framing Block: plain-language overview, max 3 sentences, render-time numbers, dismissible */}
      {!framingDismissed && summary && (
        <section
          aria-label="Evaluation Overview"
          className="p-3.5 sm:p-4 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)] text-xs sm:text-sm font-sans leading-relaxed text-[var(--ink)]"
        >
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1.5 pr-2">
              <p>
                You are inspecting an automated inbox assistant tested against {summary.n_total} adversarial prompt-injection attacks.
                Before hardening, {summary.realistic_mode.unhardened.unsafe.count} attacks produced unsafe actions, compared to {summary.realistic_mode.policy_v2.unsafe.count} under synthesized Policy v2.
                The same attacks are replayed across three conditions to verify deterministic enforcement without LLM judges.
              </p>
              <div className="pt-0.5">
                <Link
                  href="/report#section-2"
                  prefetch={false}
                  className="font-medium text-[var(--ink)] underline hover:opacity-80 text-xs inline-flex items-center gap-1"
                >
                  How was this measured?
                </Link>
              </div>
            </div>
            <button
              type="button"
              onClick={handleDismissFraming}
              className="p-1.5 -mr-1 -mt-1 rounded-[var(--radius-sm)] text-[var(--ink-muted)] hover:text-[var(--ink)] hover:bg-[var(--range-paper)] focus-visible:outline-2 focus-visible:outline-[var(--ink)] shrink-0"
              aria-label="Dismiss evaluation overview"
            >
              <svg width="16" height="16" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M5 5 L15 15 M15 5 L5 15" />
              </svg>
            </button>
          </div>
        </section>
      )}

      {/* Top Filter and Condition Switch Toolbar */}
      <RangeFilters
        condition={condition}
        onConditionChange={handleConditionChange}
        channelFilter={channelFilter}
        onChannelFilterChange={setChannelFilter}
        categoryFilter={categoryFilter}
        onCategoryFilterChange={setCategoryFilter}
        onlyUnsafeUnhardened={onlyUnsafeUnhardened}
        onOnlyUnsafeUnhardenedChange={setOnlyUnsafeUnhardenedChange}
        availableCategories={availableCategories}
      />

      {/* Main Workspace Layout: The Range is the Hero (most width) with Counter directly next to it */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start min-w-0 max-w-full">
        {/* The Range Hero: Takes 8 of 12 columns */}
        <section className="lg:col-span-8 xl:col-span-8 2xl:col-span-9 min-w-0 max-w-full" aria-label="The Range interactive attack grid">
          {filteredAttacks.length === 0 ? (
            <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-8 text-center space-y-3">
              <div className="text-sm font-semibold text-[var(--ink)] font-sans">
                No attacks match the selected filters
              </div>
              <p className="text-xs text-[var(--ink-muted)] max-w-sm mx-auto font-sans">
                No attack records satisfied the current channel, category, and unhardened-unsafe criteria.
              </p>
              <button
                type="button"
                onClick={() => {
                  setChannelFilter("all");
                  setCategoryFilter("all");
                  setOnlyUnsafeUnhardenedChange(false);
                }}
                className="px-3.5 py-1.5 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] text-xs font-semibold hover:opacity-90 font-sans"
              >
                Reset all filters
              </button>
            </div>
          ) : (
            <RangeGrid
              attacks={filteredAttacks}
              condition={condition}
              selectedAttackId={selectedAttack?.id ?? null}
              onSelectAttack={setSelectedAttack}
              isWiping={isWiping}
            />
          )}
        </section>

        {/* Counter: Right next to the grid in 4 of 12 columns */}
        <section className="lg:col-span-4 xl:col-span-4 2xl:col-span-3 min-w-0 max-w-full" aria-label="Unsafe-action rate telemetry counter and legend">
          <RangeCounter
            condition={condition}
            standardUnsafeCount={standardUnsafeCount}
            totalStandard={totalStandard}
            standardWilsonCi={standardWilsonCi}
            probeUnsafeCount={probeUnsafeCount}
            totalProbes={totalProbes}
            probeAmberCount={probeAmberCount}
            probeWilsonCi={probeWilsonCi}
            redCount={redCount}
            amberCount={amberCount}
            greyCount={greyCount}
            tealOutlineCount={tealOutlineCount}
            attribution={attribution}
            isWiping={isWiping}
          />
        </section>
      </div>

      {/* Collapsible Run Facts Panel placed below The Range hero */}
      <section className="border border-[var(--rule)] rounded-[var(--radius-md)] bg-[var(--panel)] overflow-hidden" aria-label="Run facts and configuration">
        <button
          type="button"
          onClick={() => setFactsExpanded((prev) => !prev)}
          className="w-full flex items-center justify-between p-4 text-xs font-medium text-[var(--ink)] hover:bg-[var(--range-paper)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ink)]"
          aria-expanded={factsExpanded}
        >
          <div className="flex items-center gap-2 font-sans">
            <span className="font-semibold text-xs text-[var(--ink)]">Run facts & configuration</span>
            <span className="text-[var(--ink-muted)] text-xs hidden sm:inline">
              (target agent, active model roles, and policy SHA-256 hashes)
            </span>
          </div>
          <span className="font-mono text-xs text-[var(--ink-muted)]">
            {factsExpanded ? "Collapse ▲" : "Expand ▼"}
          </span>
        </button>
        {factsExpanded && (
          <div className="p-4 sm:p-5 border-t border-[var(--rule)] bg-[var(--panel)]">
            <LeftRailFacts
              totalAttacks={attacks.length}
              standardCount={standardCount}
              probeCount={probeCount}
              policyHashes={summary?.policy_hashes ?? null}
              modelRoles={summary?.model_roles ?? null}
              horizontal={true}
            />
          </div>
        )}
      </section>

      {/* Attack Detail Drawer */}
      <AttackDrawer
        attack={selectedAttack}
        condition={condition}
        onConditionChange={setCondition}
        onClose={() => setSelectedAttack(null)}
      />
    </div>
  );
}
