"use client";

import React, { useEffect, useState } from "react";
import { AttackCondition } from "@/lib/range-utils";

interface RangeCounterProps {
  condition: AttackCondition;
  unsafeCount: number;
  totalVisible: number;
  wilsonCi: [number, number]; // [0..1, 0..1]
  redCount: number;
  amberCount: number;
  greyCount: number;
  tealOutlineCount: number;
  isWiping?: boolean;
}

export function RangeCounter({
  condition,
  unsafeCount,
  totalVisible,
  wilsonCi,
  redCount,
  amberCount,
  greyCount,
  tealOutlineCount,
  isWiping = false,
}: RangeCounterProps) {
  // Animated values for the before/after wipe
  const targetRate = totalVisible > 0 ? (unsafeCount / totalVisible) * 100 : 0;
  const [animatedValues, setAnimatedValues] = useState<{ rate: number; count: number } | null>(null);
  const prevValuesRef = React.useRef({ rate: targetRate, count: unsafeCount });

  useEffect(() => {
    if (!isWiping) {
      prevValuesRef.current = { rate: targetRate, count: unsafeCount };
      return;
    }

    const startRate = prevValuesRef.current.rate;
    const endRate = targetRate;
    const startCount = prevValuesRef.current.count;
    const endCount = unsafeCount;
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
  }, [isWiping, targetRate, unsafeCount]);

  const displayRate = animatedValues ? animatedValues.rate : targetRate;
  const displayCount = animatedValues ? animatedValues.count : unsafeCount;

  const lowPct = (wilsonCi[0] * 100).toFixed(1);
  const highPct = (wilsonCi[1] * 100).toFixed(1);

  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-2">
          <span className="font-semibold uppercase tracking-wider text-[11px]">Breach Rate</span>
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)]">
            {condition === "unhardened"
              ? "Unhardened baseline"
              : condition === "v1"
              ? "Policy v1"
              : "Policy v2 (Active)"}
          </span>
        </div>

        {/* Large Breach Rate Counter */}
        <div className="my-2">
          <div className="font-display font-bold text-5xl sm:text-6xl text-[var(--ink)] tracking-tight">
            {displayRate.toFixed(1)}%
          </div>
          <div className="font-mono text-xs text-[var(--ink)] mt-1.5 font-medium">
            {displayCount} of {totalVisible} attacks breached
          </div>
          <div className="font-mono text-[11px] text-[var(--ink-muted)] mt-0.5">
            95% Wilson CI: [{lowPct}%, {highPct}%]
          </div>
        </div>
      </div>

      {/* Legend with exact counts per colour */}
      <div className="mt-5 pt-4 border-t border-[var(--rule)] space-y-2 text-xs">
        <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
          Visible Square Legend
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-[var(--radius-sm)] bg-[var(--breach)] shrink-0"
              aria-hidden="true"
            />
            <span className="text-[var(--ink)] font-medium">UNSAFE (M1 ∨ M2 ∨ M3)</span>
          </div>
          <span className="font-mono font-semibold text-[var(--breach)]">{redCount}</span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-[var(--radius-sm)] bg-[var(--in-flight)] shrink-0"
              aria-hidden="true"
            />
            <span className="text-[var(--ink)] font-medium">Canary-only leak (M4)</span>
          </div>
          <span className="font-mono font-semibold text-[var(--in-flight)]">{amberCount}</span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-[var(--radius-sm)] bg-[#94A3B8] shrink-0"
              aria-hidden="true"
            />
            <span className="text-[var(--ink)] font-medium">Defended</span>
          </div>
          <span className="font-mono text-[var(--ink)]">{greyCount}</span>
        </div>

        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-[var(--radius-sm)] bg-[#94A3B8] border-2 border-[var(--cleared)] shrink-0"
              aria-hidden="true"
            />
            <span className="text-[var(--ink)] font-medium">Stopped by policy rule</span>
          </div>
          <span className="font-mono font-semibold text-[var(--cleared)]">{tealOutlineCount}</span>
        </div>
      </div>
    </div>
  );
}
