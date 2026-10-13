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

  const totalSquares = totalStandard + totalProbes;
  const totalDefended = greyCount;

  return (
    <div className="space-y-4">
      {/* 1. Main Range Counter: Standard Attacks Only (n=190 basis matching /results) */}
      <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-2 font-sans">
            <span className="font-semibold text-xs text-[var(--ink)]">
              Unsafe-action rate (standard attacks)
            </span>
            <span className="font-sans text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)] font-medium">
              {condition === "unhardened"
                ? "Unhardened baseline"
                : condition === "v1"
                ? "Policy v1"
                : "Policy v2 (Active)"}
            </span>
          </div>

          {/* Large Unsafe-Action Rate Counter in Bricolage Grotesque */}
          <div className="my-2">
            <div className="font-display font-bold text-5xl sm:text-6xl text-[var(--ink)] tracking-tight">
              {displayRate.toFixed(1)}%
            </div>
            {/* Readable text at least 14px directly under large number */}
            <div className="font-sans text-[14px] sm:text-base text-[var(--ink)] mt-1.5 font-medium">
              {displayCount} of {totalStandard} standard attacks, 95% upper bound {stdHighPct}%
            </div>
            <div className="font-sans text-xs text-[var(--ink-muted)] mt-1">
              95% Wilson CI: [{stdLowPct}%, {stdHighPct}%]
            </div>
          </div>
        </div>

        {/* 2. Secondary Counter: 45 Channel-Coverage Probes */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)]">
          <div className="text-xs font-semibold text-[var(--ink)] font-sans mb-1.5 leading-snug">
            Channel-coverage probes (attacker was given the secret)
          </div>
          <div className="flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1 sm:gap-2">
            <div className="font-display font-bold text-2xl text-[var(--ink)]">
              {probeRate.toFixed(1)}%
            </div>
            <div className="sm:text-right">
              <div className="font-sans text-xs text-[var(--ink)] font-medium">
                {probeUnsafeCount} of {totalProbes} unsafe actions
              </div>
              <div className="font-sans text-xs text-[var(--ink-muted)] mt-0.5 leading-snug">
                95% CI: [{probeLowPct}%, {probeHighPct}%], {probeAmberCount} canary leaks
              </div>
            </div>
          </div>
        </div>

        {/* 3. Attribution from real data */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)]">
          <div className="text-xs font-semibold text-[var(--ink)] font-sans mb-1">
            Hardening attribution
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

        {/* 4. Legend with explicit shapes for colour independence & clear basis */}
        <div className="mt-4 pt-3.5 border-t border-[var(--rule)] space-y-2.5 text-xs">
          <div>
            <div className="text-xs font-semibold text-[var(--ink)] font-sans">
              Square legend
            </div>
            <div className="text-xs text-[var(--ink-muted)] font-sans">
              Basis: of {totalSquares} squares ({totalStandard} standard, {totalProbes} probes)
            </div>
          </div>

          {/* Unsafe: Red with diagonal slash */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--breach)" />
                <line x1="2.5" y1="2.5" x2="11.5" y2="11.5" stroke="var(--panel)" strokeWidth="1.6" strokeLinecap="round" />
              </svg>
              <span className="text-[var(--ink)] font-medium font-sans leading-snug">
                Red with diagonal slash: unsafe action (M1, M2, or M3)
              </span>
            </div>
            <span className="font-mono font-semibold text-[var(--breach)] shrink-0">{redCount}</span>
          </div>

          {/* Amber: Dot in center */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--in-flight)" />
                <circle cx="7" cy="7" r="2.3" fill="var(--ink)" />
              </svg>
              <span className="text-[var(--ink)] font-medium font-sans leading-snug">
                Amber with center dot: canary-only leak (M4)
              </span>
            </div>
            <span className="font-mono font-semibold text-[var(--in-flight-text)] shrink-0">{amberCount}</span>
          </div>

          {/* Defended: Plain grey (subset: stopped by a named policy rule) */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-2.5 min-w-0">
              <svg width="14" height="14" viewBox="0 0 14 14" className="shrink-0 mt-0.5" aria-hidden="true">
                <rect width="14" height="14" rx="2" fill="var(--defended)" />
              </svg>
              <div className="min-w-0">
                <div className="text-[var(--ink)] font-medium font-sans">
                  Plain grey: defended attack
                </div>
                {tealOutlineCount > 0 && (
                  <div className="flex items-center gap-1.5 text-xs text-[var(--ink-muted)] mt-1 font-sans">
                    <svg width="12" height="12" viewBox="0 0 12 12" className="shrink-0" aria-hidden="true">
                      <rect x="1" y="1" width="10" height="10" rx="2" fill="var(--defended)" stroke="var(--cleared)" strokeWidth="1.8" />
                    </svg>
                    <span>Teal outline: stopped by a named policy rule ({tealOutlineCount})</span>
                  </div>
                )}
              </div>
            </div>
            <span className="font-mono font-semibold text-[var(--ink)] shrink-0">{totalDefended}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
