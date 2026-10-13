"use client";

import React, { useEffect, useState, useMemo } from "react";
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
        const wasUnsafe = Boolean(
          a.unhardened.unsafe ||
            a.unhardened.m1 ||
            a.unhardened.m2 ||
            a.unhardened.m3
        );
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

  // 1. Loading State
  if (loading) {
    return (
      <div className="max-w-4xl mx-auto py-16 text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--rule)] text-xs text-[var(--ink-muted)]">
          <span className="w-2 h-2 rounded-full bg-[var(--in-flight)] animate-pulse" aria-hidden="true" />
          <span>Loading attack telemetry...</span>
        </div>
        <p className="text-xs text-[var(--ink-muted)] font-mono">
          Fetching 235 recorded attacks from /api/recorded/attacks
        </p>
      </div>
    );
  }

  // 2. Error State
  if (error) {
    return (
      <div className="max-w-2xl mx-auto my-8 p-6 rounded-[var(--radius-md)] bg-[var(--panel)] border-2 border-[var(--breach)] space-y-4">
        <div className="flex items-start gap-3">
          <span className="w-3 h-3 rounded-full bg-[var(--breach)] shrink-0 mt-1" aria-hidden="true" />
          <div>
            <h2 className="font-display font-semibold text-lg text-[var(--ink)]">
              Cannot connect to Gauntlet API
            </h2>
            <p className="text-xs text-[var(--breach)] font-mono mt-1 break-words">
              {error.message}
            </p>
          </div>
        </div>
        <div className="p-3 bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)] text-xs text-[var(--ink-muted)]">
          {error.actionGuide ||
            "Start the FastAPI server: py -m uvicorn backend.api:app --port 8000, then refresh."}
        </div>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] text-xs font-semibold hover:opacity-90 focus-visible:outline-2"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const standardCount = attacks.filter((a) => !a.is_probe).length;
  const probeCount = attacks.filter((a) => a.is_probe).length;

  return (
    <div className="max-w-7xl mx-auto space-y-6 pb-12">
      {/* Top Controls: Filters and 3-State Condition Switch */}
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

      {/* Main Workspace Layout: Left Rail + Center Range + Counter */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Rail Facts */}
        <aside className="lg:col-span-3 space-y-4" aria-label="Run facts">
          <LeftRailFacts
            totalAttacks={attacks.length}
            standardCount={standardCount}
            probeCount={probeCount}
            policyHashes={summary?.policy_hashes ?? null}
          />
        </aside>

        {/* Center: The Range Grid */}
        <section className="lg:col-span-6" aria-label="The Range interactive attack grid">
          {filteredAttacks.length === 0 ? (
            <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-8 text-center space-y-3">
              <div className="text-sm font-semibold text-[var(--ink)]">
                No attacks match the selected filters
              </div>
              <p className="text-xs text-[var(--ink-muted)] max-w-sm mx-auto">
                No attack records satisfied the current channel, category, and unhardened-unsafe criteria.
              </p>
              <button
                type="button"
                onClick={() => {
                  setChannelFilter("all");
                  setCategoryFilter("all");
                  setOnlyUnsafeUnhardenedChange(false);
                }}
                className="px-3.5 py-1.5 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] text-xs font-semibold hover:opacity-90"
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

        {/* Right: Breach Counter & Legend */}
        <section className="lg:col-span-3" aria-label="Breach rate telemetry counter and legend">
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
