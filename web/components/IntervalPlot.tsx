"use client";

import React from "react";
import { ModeMetrics } from "@/lib/api";

interface IntervalPlotProps {
  title: string;
  subtitle: string;
  unhardened: ModeMetrics;
  policyV2: ModeMetrics;
}

interface MetricRowData {
  key: keyof Pick<ModeMetrics, "m1" | "m2" | "m3" | "m4" | "unsafe">;
  label: string;
  name: string;
}

const METRICS: MetricRowData[] = [
  { key: "m1", label: "M1", name: "Exfiltration" },
  { key: "m2", label: "M2", name: "Forbidden tool" },
  { key: "m3", label: "M3", name: "System compromise" },
  { key: "m4", label: "M4", name: "Canary leak" },
  { key: "unsafe", label: "UNSAFE", name: "Any unsafe action" },
];

export function IntervalPlot({
  title,
  subtitle,
  unhardened,
  policyV2,
}: IntervalPlotProps) {
  // SVG coordinate dimensions
  const svgWidth = 620;
  const svgHeight = 330;
  const plotLeft = 110;
  const plotRight = 480;
  const plotWidth = plotRight - plotLeft; // 370px for 0% - 100%
  const rowStart = 70;
  const rowStep = 48;

  const toX = (pct: number) => {
    const clamped = Math.max(0, Math.min(100, pct));
    return plotLeft + (clamped / 100) * plotWidth;
  };

  const ticks = [0, 25, 50, 75, 100];

  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col">
      <div className="mb-4">
        <h3 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)]">
          {title}
        </h3>
        <p className="text-xs text-[var(--ink-muted)] mt-0.5">{subtitle}</p>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 text-xs mb-3 pb-2 border-b border-[var(--rule)]">
        <div className="flex items-center gap-1.5">
          <span
            className="w-2.5 h-2.5 rounded-full bg-[var(--breach)] shrink-0"
            aria-hidden="true"
          />
          <span className="font-medium text-[var(--ink)]">Unhardened baseline</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="w-2.5 h-2.5 rounded-[var(--radius-sm)] bg-[var(--cleared)] shrink-0"
            aria-hidden="true"
          />
          <span className="font-medium text-[var(--ink)]">Policy v2</span>
        </div>
        <div className="text-xs text-[var(--ink-muted)] font-sans ml-auto">
          Whisker bars: 95% Wilson CI
        </div>
      </div>

      {/* Custom SVG Interval Plot */}
      <div className="w-full overflow-x-auto">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="w-full h-auto min-w-[500px]"
          role="img"
          aria-label={`${title} interval plot showing Wilson confidence intervals for Unhardened vs Policy v2`}
        >
          {/* Grid lines and X-axis ticks */}
          {ticks.map((tick) => {
            const x = toX(tick);
            return (
              <g key={`tick-${tick}`}>
                <line
                  x1={x}
                  y1={rowStart - 20}
                  x2={x}
                  y2={rowStart + rowStep * 4 + 25}
                  stroke="var(--rule)"
                  strokeWidth="1"
                  strokeDasharray={tick === 0 || tick === 100 ? "none" : "2 3"}
                  opacity={tick === 0 || tick === 100 ? 0.9 : 0.6}
                />
                <text
                  x={x}
                  y={rowStart - 26}
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

          {/* Metric Rows */}
          {METRICS.map((m, idx) => {
            const centerY = rowStart + idx * rowStep + 10;
            const unhY = centerY - 7;
            const polY = centerY + 7;

            const uData = unhardened[m.key];
            const pData = policyV2[m.key];

            const uX = toX(uData.rate_pct);
            const uCiLow = toX(uData.ci_pct[0]);
            const uCiHigh = toX(uData.ci_pct[1]);

            const pX = toX(pData.rate_pct);
            const pCiLow = toX(pData.ci_pct[0]);
            const pCiHigh = toX(pData.ci_pct[1]);

            const isUnsafe = m.key === "unsafe";

            return (
              <g key={m.key} className="metric-row">
                {/* Row divider background highlight for UNSAFE */}
                {isUnsafe && (
                  <rect
                    x="4"
                    y={centerY - 20}
                    width={svgWidth - 8}
                    height="42"
                    fill="var(--range-paper)"
                    rx="4"
                    opacity="0.6"
                  />
                )}

                {/* Left labels */}
                <text
                  x="8"
                  y={centerY - 2}
                  fontFamily="var(--font-ibm-mono)"
                  fontWeight={isUnsafe ? "700" : "600"}
                  fontSize={isUnsafe ? "12" : "11"}
                  fill="var(--ink)"
                >
                  {m.label}
                </text>
                <text
                  x="8"
                  y={centerY + 12}
                  fontFamily="var(--font-ibm-sans)"
                  fontSize="10"
                  fill="var(--ink-muted)"
                >
                  {m.name}
                </text>

                {/* Row center guide */}
                <line
                  x1={plotLeft}
                  y1={centerY}
                  x2={plotRight}
                  y2={centerY}
                  stroke="var(--rule)"
                  strokeWidth="0.5"
                  strokeDasharray="1 4"
                  opacity="0.4"
                />

                {/* 1. Unhardened CI line & Whiskers */}
                <line
                  x1={uCiLow}
                  y1={unhY}
                  x2={uCiHigh}
                  y2={unhY}
                  stroke="var(--breach)"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
                <line
                  x1={uCiLow}
                  y1={unhY - 4}
                  x2={uCiLow}
                  y2={unhY + 4}
                  stroke="var(--breach)"
                  strokeWidth="1.5"
                />
                <line
                  x1={uCiHigh}
                  y1={unhY - 4}
                  x2={uCiHigh}
                  y2={unhY + 4}
                  stroke="var(--breach)"
                  strokeWidth="1.5"
                />
                {/* Unhardened Point */}
                <circle
                  cx={uX}
                  cy={unhY}
                  r="3.5"
                  fill="var(--breach)"
                  stroke="var(--panel)"
                  strokeWidth="1"
                />

                {/* 2. Policy v2 CI line & Whiskers */}
                <line
                  x1={pCiLow}
                  y1={polY}
                  x2={pCiHigh}
                  y2={polY}
                  stroke="var(--cleared)"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
                <line
                  x1={pCiLow}
                  y1={polY - 4}
                  x2={pCiLow}
                  y2={polY + 4}
                  stroke="var(--cleared)"
                  strokeWidth="1.5"
                />
                <line
                  x1={pCiHigh}
                  y1={polY - 4}
                  x2={pCiHigh}
                  y2={polY + 4}
                  stroke="var(--cleared)"
                  strokeWidth="1.5"
                />
                {/* Policy v2 Point (Square) */}
                <rect
                  x={pX - 3.5}
                  y={polY - 3.5}
                  width="7"
                  height="7"
                  fill="var(--cleared)"
                  stroke="var(--panel)"
                  strokeWidth="1"
                  rx="1"
                />

                {/* Right text readouts */}
                <text
                  x={plotRight + 12}
                  y={unhY + 3.5}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="10"
                  fill="var(--breach)"
                  fontWeight="500"
                >
                  {uData.count}/{unhardened.n} ({uData.rate_pct.toFixed(1)}%)
                </text>

                <text
                  x={plotRight + 12}
                  y={polY + 3.5}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="10"
                  fill="var(--cleared)"
                  fontWeight="500"
                >
                  {pData.count}/{policyV2.n} ({pData.rate_pct.toFixed(1)}%)
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Accessible Table Breakdown */}
      <div className="mt-4 pt-3 border-t border-[var(--rule)]">
        <details className="text-xs text-[var(--ink-muted)]">
          <summary className="cursor-pointer font-medium hover:text-[var(--ink)] select-none">
            View exact data table and confidence intervals
          </summary>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--rule)] text-[var(--ink)]">
                  <th className="py-1.5 pr-3 font-semibold">Metric</th>
                  <th className="py-1.5 px-3 font-semibold text-right">Unhardened Count</th>
                  <th className="py-1.5 px-3 font-semibold text-right">Unhardened Rate</th>
                  <th className="py-1.5 px-3 font-semibold text-right">Unhardened 95% CI</th>
                  <th className="py-1.5 px-3 font-semibold text-right">Policy v2 Count</th>
                  <th className="py-1.5 px-3 font-semibold text-right">Policy v2 Rate</th>
                  <th className="py-1.5 pl-3 font-semibold text-right">Policy v2 95% CI</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--rule)] font-mono text-xs">
                {METRICS.map((m) => {
                  const u = unhardened[m.key];
                  const p = policyV2[m.key];
                  return (
                    <tr key={m.key} className="text-[var(--ink)]">
                      <td className="py-1.5 pr-3 font-medium font-sans">
                        {m.label} ({m.name})
                      </td>
                      <td className="py-1.5 px-3 text-right text-[var(--breach)]">
                        {u.count}/{unhardened.n}
                      </td>
                      <td className="py-1.5 px-3 text-right text-[var(--breach)]">
                        {u.rate_pct.toFixed(1)}%
                      </td>
                      <td className="py-1.5 px-3 text-right text-[var(--ink-muted)]">
                        [{u.ci_pct[0].toFixed(1)}%, {u.ci_pct[1].toFixed(1)}%]
                      </td>
                      <td className="py-1.5 px-3 text-right text-[var(--cleared)]">
                        {p.count}/{policyV2.n}
                      </td>
                      <td className="py-1.5 px-3 text-right text-[var(--cleared)]">
                        {p.rate_pct.toFixed(1)}%
                      </td>
                      <td className="py-1.5 pl-3 text-right text-[var(--ink-muted)]">
                        [{p.ci_pct[0].toFixed(1)}%, {p.ci_pct[1].toFixed(1)}%]
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </details>
      </div>
    </div>
  );
}
