"use client";

import React, { useEffect, useState, useRef } from "react";
import { AttackCondition } from "@/lib/range-utils";

interface RangeCounterProps {
  condition: AttackCondition;
  // Standard attacks (basis for main counter)
  standardUnsafeCount: number;
  totalStandard: number;
  standardWilsonCi: [number, number];
  // Probes (basis for secondary counter)
  probeUnsafeCount: number;
  totalProbes: number;
  probeAmberCount: number;
  probeWilsonCi: [number, number];
  // Visual counts for visible grid
  redCount: number;
  amberCount: number;
  greyCount: number;
  tealOutlineCount: number;
  // Attribution from real data
  attribution: {
    nUnsafeUnhardened: number;
    xStoppedByRule: number;
    yDidNotRecur: number;
  };
  isWiping?: boolean;
}

export function RangeCounter({
  condition,
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
  isWiping = false,
}: RangeCounterProps) {
  // Animated values for the before/after wipe (interpolating standard attack breach figures)
  const targetRate = totalStandard > 0 ? (standardUnsafeCount / totalStandard) * 100 : 0;
  const [animatedValues, setAnimatedValues] = useState<{ rate: number; count: number } | null>(null);
  const prevValuesRef = useRef({ rate: targetRate, count: standardUnsafeCount });

  useEffect(() => {
    if (!isWiping) {
      prevValuesRef.current = { rate: targetRate, count: standardUnsafeCount };
      return;
    }

    const startRate = prevValuesRef.current.rate;
    const endRate = targetRate;
    const startCount = prevValuesRef.current.count;
    const endCount = standardUnsafeCount;
    const duration = 900;
    const startTime = performance.now();

    let animationFrameId: number;

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      // ease-out cubic
      const ease = 1 - Math.pow(1 - progress, 3);

      setAnimatedValues({
        rate: startRate + (endRate - startRate) * ease,
        count: Math.round(startCount + (endCount - startCount) * ease),
      });

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(tick);
      } else {
        setAnimatedValues(null);
        prevValuesRef.current = { rate: endRate, count: endCount };
      }
    };

    animationFrameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animationFrameId);
  }, [isWiping, targetRate, standardUnsafeCount]);

  const displayRate = animatedValues ? animatedValues.rate : targetRate;
  const displayCount = animatedValues ? animatedValues.count : standardUnsafeCount;

  const stdLowPct = (standardWilsonCi[0] * 100).toFixed(1);
  const stdHighPct = (standardWilsonCi[1] * 100).toFixed(1);

  const probeRate = totalProbes > 0 ? (probeUnsafeCount / totalProbes) * 100 : 0;
  const probeLowPct = (probeWilsonCi[0] * 100).toFixed(1);
  const probeHighPct = (probeWilsonCi[1] * 100).toFixed(1);

  return (
    <div className="space-y-4">
      {/* 1. Main Range Counter: Standard Attacks Only (n=190 basis matching /results) */}
      <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-2">
            <span className="font-semibold uppercase tracking-wider text-[11px]">
              Breach Rate (Standard Attacks)
            </span>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)]">
              {condition === "unhardened"
                ? "Unhardened baseline"
                : condition === "v1"
                ? "Policy v1"
                : "Policy v2 (Active)"}
            </span>
          </div>

          {/* Large Breach Rate Counter in Bricolage Grotesque */}
          <div className="my-2">
            <div className="font-display font-bold text-5xl sm:text-6xl text-[var(--ink)] tracking-tight">
              {displayRate.toFixed(1)}%
            </div>
            <div className="font-mono text-xs text-[var(--ink)] mt-1.5 font-medium">
              {displayCount} of {totalStandard} standard attacks breached
            </div>
            <div className="font-mono text-[11px] text-[var(--ink-muted)] mt-0.5">
              95% Wilson CI: [{stdLowPct}%, {stdHighPct}%]
            </div>
          </div>
        </div>

        {/* 2. Secondary Counter: 45 Channel-Coverage Probes */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)]">
          <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-1.5">
            Channel-coverage probes (attacker was given the secret)
          </div>
          <div className="flex items-baseline justify-between">
            <div className="font-display font-bold text-2xl text-[var(--ink)]">
              {probeRate.toFixed(1)}%
            </div>
            <div className="text-right">
              <div className="font-mono text-xs text-[var(--ink)]">
                {probeUnsafeCount} of {totalProbes} breached
              </div>
              <div className="font-mono text-[10px] text-[var(--ink-muted)]">
                95% CI: [{probeLowPct}%, {probeHighPct}%] • {probeAmberCount} canary leaks
              </div>
            </div>
          </div>
        </div>

        {/* 3. Attribution from real data */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)]">
          <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-1">
            Hardening Attribution
          </div>
          <p className="text-xs text-[var(--ink)] leading-snug font-sans">
            {condition === "unhardened" ? (
              <span>
                <strong>{attribution.nUnsafeUnhardened}</strong> standard attacks breached under unhardened baseline (prior to policy synthesis).
              </span>
            ) : (
              <span>
                Of <strong>{attribution.nUnsafeUnhardened}</strong> unsafe when unhardened:{" "}
                <strong>{attribution.xStoppedByRule}</strong> stopped by a named policy rule,{" "}
                <strong>{attribution.yDidNotRecur}</strong> did not recur (agent behaviour varies between runs).
              </span>
            )}
          </p>
        </div>

        {/* 4. Legend with explicit shapes for colour independence */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)] space-y-2 text-xs">
          <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
            Square Legend (Colour-Independent Shapes)
          </div>

          {/* UNSAFE: Red with diagonal slash */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--breach)" />
                <line x1="2.5" y1="2.5" x2="11.5" y2="11.5" stroke="var(--panel)" strokeWidth="1.6" strokeLinecap="round" />
              </svg>
              <span className="text-[var(--ink)] font-medium">
                UNSAFE (M1 ∨ M2 ∨ M3) <span className="text-[var(--ink-muted)] font-normal">• diagonal slash</span>
              </span>
            </div>
            <span className="font-mono font-semibold text-[var(--breach)]">{redCount}</span>
          </div>

          {/* Amber: Dot in center */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--in-flight)" />
                <circle cx="7" cy="7" r="2.3" fill="var(--ink)" />
              </svg>
              <span className="text-[var(--ink)] font-medium">
                Canary-only leak (M4) <span className="text-[var(--ink-muted)] font-normal">• center dot</span>
              </span>
            </div>
            <span className="font-mono font-semibold text-[var(--in-flight)]">{amberCount}</span>
          </div>

          {/* Defended: Plain grey */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--defended)" />
              </svg>
              <span className="text-[var(--ink)] font-medium">
                Defended <span className="text-[var(--ink-muted)] font-normal">• plain</span>
              </span>
            </div>
            <span className="font-mono text-[var(--ink)]">{greyCount}</span>
          </div>

          {/* Teal outline */}
          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center gap-2.5">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect x="1" y="1" width="12" height="12" rx="2" fill="var(--defended)" stroke="var(--cleared)" strokeWidth="2" />
              </svg>
              <span className="text-[var(--ink)] font-medium">
                Stopped by policy rule <span className="text-[var(--ink-muted)] font-normal">• teal outline</span>
              </span>
            </div>
            <span className="font-mono font-semibold text-[var(--cleared)]">{tealOutlineCount}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
