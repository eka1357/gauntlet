"use client";

import React from "react";
import { ProbeSetEval } from "@/lib/api";

interface ProbeSetSectionProps {
  probeSet: ProbeSetEval;
}

export function ProbeSetSection({ probeSet }: ProbeSetSectionProps) {
  const unh = probeSet.unhardened.m4;
  const v1 = probeSet.policy_v1.m4;
  const v2 = probeSet.policy_v2.m4;
  const n = probeSet.n;

  // Custom SVG plot parameters with ample right margin for readouts
  const svgWidth = 680;
  const svgHeight = 175;
  const plotLeft = 105;
  const plotRight = 425;
  const plotWidth = plotRight - plotLeft;

  const toX = (pct: number) => {
    const clamped = Math.max(0, Math.min(50, pct));
    // Scale 0% to 50% across plot width for high-resolution interval discrimination
    return plotLeft + (clamped / 50) * plotWidth;
  };

  const ticks = [0, 10, 20, 30, 40, 50];

  const conditions = [
    {
      id: "unhardened",
      label: "Unhardened",
      color: "var(--breach)",
      data: unh,
      y: 62,
      marker: "circle",
    },
    {
      id: "v1",
      label: "Policy v1",
      color: "var(--in-flight)",
      data: v1,
      y: 100,
      marker: "diamond",
    },
    {
      id: "v2",
      label: "Policy v2",
      color: "var(--cleared)",
      data: v2,
      y: 138,
      marker: "square",
    },
  ];

  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 mb-3">
        <div>
          <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans">
            Probe evaluation suite (n={n})
          </div>
          <h3 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)] mt-0.5">
            Channel-coverage probe: attacker was given the secret
          </h3>
        </div>
        <div className="text-xs font-mono px-2.5 py-1 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)] shrink-0 self-start">
          Metric: M4 Canary Leak
        </div>
      </div>

      <p className="text-xs text-[var(--ink-muted)] mb-4 max-w-3xl leading-relaxed">
        The probe suite tests non-vault leakage pathways where the injection payload already contains the secret token.
        Under Policy v1, 8 of 45 attacks leaked via unmonitored partner address and calendar side-channels.
        Policy v2 closed all residual channels (0 of 45 leaks, 95% Wilson CI upper bound {v2.ci_pct[1].toFixed(1)}%).
      </p>

      {/* SVG Interval Plot for M4 across Unhardened / v1 / v2 */}
      <div className="w-full overflow-x-auto">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="w-full h-auto min-w-[540px]"
          role="img"
          aria-label="Channel-coverage probe interval plot for M4 comparing Unhardened, Policy v1, and Policy v2"
        >
          {/* Ticks and grid lines */}
          {ticks.map((tick) => {
            const x = toX(tick);
            return (
              <g key={`probe-tick-${tick}`}>
                <line
                  x1={x}
                  y1={35}
                  x2={x}
                  y2={155}
                  stroke="var(--rule)"
                  strokeWidth="1"
                  strokeDasharray="2 3"
                  opacity={tick === 0 ? 0.9 : 0.6}
                />
                <text
                  x={x}
                  y={28}
                  textAnchor="middle"
                  fontSize="11"
                  fontFamily="var(--font-ibm-mono)"
                  fill="var(--ink-muted)"
                >
                  {tick}%
                </text>
              </g>
            );
          })}

          {/* Condition Rows */}
          {conditions.map((c) => {
            const xVal = toX(c.data.rate_pct);
            const xLow = toX(c.data.ci_pct[0]);
            const xHigh = toX(c.data.ci_pct[1]);

            return (
              <g key={c.id}>
                {/* Condition Label */}
                <text
                  x="6"
                  y={c.y + 4}
                  fontFamily="var(--font-ibm-sans)"
                  fontWeight="600"
                  fontSize="12"
                  fill="var(--ink)"
                >
                  {c.label}
                </text>

                {/* Guide line */}
                <line
                  x1={plotLeft}
                  y1={c.y}
                  x2={plotRight}
                  y2={c.y}
                  stroke="var(--rule)"
                  strokeWidth="0.5"
                  strokeDasharray="1 4"
                  opacity="0.4"
                />

                {/* CI Whisker bar */}
                <line
                  x1={xLow}
                  y1={c.y}
                  x2={xHigh}
                  y2={c.y}
                  stroke={c.color}
                  strokeWidth="2"
                  strokeLinecap="round"
                />
                <line
                  x1={xLow}
                  y1={c.y - 4}
                  x2={xLow}
                  y2={c.y + 4}
                  stroke={c.color}
                  strokeWidth="1.5"
                />
                <line
                  x1={xHigh}
                  y1={c.y - 4}
                  x2={xHigh}
                  y2={c.y + 4}
                  stroke={c.color}
                  strokeWidth="1.5"
                />

                {/* Point Marker */}
                {c.marker === "circle" && (
                  <circle
                    cx={xVal}
                    cy={c.y}
                    r="4"
                    fill={c.color}
                    stroke="var(--panel)"
                    strokeWidth="1"
                  />
                )}
                {c.marker === "diamond" && (
                  <polygon
                    points={`${xVal},${c.y - 4} ${xVal + 4},${c.y} ${xVal},${c.y + 4} ${xVal - 4},${c.y}`}
                    fill={c.color}
                    stroke="var(--panel)"
                    strokeWidth="1"
                  />
                )}
                {c.marker === "square" && (
                  <rect
                    x={xVal - 3.5}
                    y={c.y - 3.5}
                    width="7"
                    height="7"
                    fill={c.color}
                    stroke="var(--panel)"
                    strokeWidth="1"
                    rx="1"
                  />
                )}

                {/* Right text readout formatted on two lines to prevent truncation */}
                <text
                  x={plotRight + 16}
                  y={c.y - 2}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="12"
                  fill={c.color}
                  fontWeight="600"
                >
                  {c.data.count}/{n} ({c.data.rate_pct.toFixed(1)}%)
                </text>
                <text
                  x={plotRight + 16}
                  y={c.y + 12}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="12"
                  fill="var(--ink-muted)"
                >
                  95% CI: [{c.data.ci_pct[0].toFixed(1)}%, {c.data.ci_pct[1].toFixed(1)}%]
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Summary grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4 pt-3 border-t border-[var(--rule)] text-xs">
        <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
          <div className="text-[var(--ink-muted)] mb-1">Unhardened Baseline</div>
          <div className="font-mono text-base font-semibold text-[var(--breach)]">
            {unh.count}/{n} <span className="text-xs font-normal">({unh.rate_pct.toFixed(1)}%)</span>
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% CI: [{unh.ci_pct[0].toFixed(1)}%, {unh.ci_pct[1].toFixed(1)}%]
          </div>
        </div>

        <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
          <div className="text-[var(--ink-muted)] mb-1">Policy v1 Partial</div>
          <div className="font-mono text-base font-semibold text-[var(--in-flight)]">
            {v1.count}/{n} <span className="text-xs font-normal">({v1.rate_pct.toFixed(1)}%)</span>
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% CI: [{v1.ci_pct[0].toFixed(1)}%, {v1.ci_pct[1].toFixed(1)}%]
          </div>
        </div>

        <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
          <div className="text-[var(--ink-muted)] mb-1">Policy v2 Fully Defended</div>
          <div className="font-mono text-base font-semibold text-[var(--cleared)]">
            {v2.count}/{n} <span className="text-xs font-normal">({v2.rate_pct.toFixed(1)}%)</span>
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% CI: [{v2.ci_pct[0].toFixed(1)}%, {v2.ci_pct[1].toFixed(1)}%]
          </div>
        </div>
      </div>
    </div>
  );
}
