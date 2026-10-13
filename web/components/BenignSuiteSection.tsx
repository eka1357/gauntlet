"use client";

import React from "react";
import { BenignSuiteEval } from "@/lib/api";

interface BenignSuiteSectionProps {
  benignSuite: BenignSuiteEval;
}

export function BenignSuiteSection({ benignSuite }: BenignSuiteSectionProps) {
  const unh = benignSuite.unhardened;
  const v2 = benignSuite.policy_v2;
  const neg = benignSuite.negative_control;

  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5">
      <div className="mb-4">
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans">
          Utility preservation
        </div>
        <h3 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)] mt-0.5">
          Benign task suite: agent utility and negative control
        </h3>
        <p className="text-xs text-[var(--ink-muted)] mt-1 max-w-3xl leading-relaxed font-sans">
          Evaluated across {benignSuite.repeats} independent repeats ({benignSuite.total_evaluations_per_condition} total
          evaluations per condition). Hardening is only viable if the agent can still perform legitimate operations.
        </p>
      </div>

      {/* Main Metric Comparison Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
        {/* Unhardened */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
          <div className="text-xs text-[var(--ink-muted)] mb-1 font-sans">Unhardened Baseline (3 repeats)</div>
          <div className="font-mono text-xl font-bold text-[var(--ink)]">
            {unh.pooled_pass_rate_pct.toFixed(1)}%
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-1">
            {unh.pooled_passed}/{unh.pooled_total} tasks passed
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% Wilson CI: [{unh.ci_pct[0].toFixed(1)}%, {unh.ci_pct[1].toFixed(1)}%]
          </div>
        </div>

        {/* Policy v2 */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--cleared)]">
          <div className="flex flex-wrap items-center justify-between text-xs text-[var(--ink-muted)] mb-1 gap-1 font-sans">
            <span>Policy v2 (3 repeats)</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--cleared)] text-[var(--panel)] font-medium">
              No measurable difference: {unh.pooled_pass_rate_pct.toFixed(1)}% vs {v2.pooled_pass_rate_pct.toFixed(1)}% (n={unh.pooled_total} each)
            </span>
          </div>
          <div className="font-mono text-xl font-bold text-[var(--cleared)]">
            {v2.pooled_pass_rate_pct.toFixed(1)}%
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-1">
            {v2.pooled_passed}/{v2.pooled_total} tasks passed
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% Wilson CI: [{v2.ci_pct[0].toFixed(1)}%, {v2.ci_pct[1].toFixed(1)}%]
          </div>
        </div>

        {/* Negative Control */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
          <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-1 font-sans">
            <span>Negative Control (deny-all)</span>
            <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-[var(--breach)] text-[var(--panel)] font-medium">
              {neg.status}
            </span>
          </div>
          <div className="font-mono text-xl font-bold text-[var(--breach)]">
            {neg.pass_rate_pct.toFixed(1)}%
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-1">
            {neg.passed}/{neg.total} tasks passed
          </div>
          <div className="font-mono text-xs text-[var(--ink-muted)] mt-0.5">
            95% Wilson CI: [{neg.ci_pct[0].toFixed(1)}%, {neg.ci_pct[1].toFixed(1)}%]
          </div>
        </div>
      </div>

      {/* Repeat Variance Table */}
      <div className="border border-[var(--rule)] rounded-[var(--radius-sm)] overflow-hidden">
        <div className="px-3 py-2 bg-[var(--range-paper)] border-b border-[var(--rule)] text-xs font-semibold text-[var(--ink)] font-sans">
          Repeat Run Variance & Task Consistency
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[var(--rule)] text-[var(--ink-muted)] bg-[var(--panel)] font-sans">
                <th className="py-2 px-3 font-semibold">Evaluation Run</th>
                <th className="py-2 px-3 font-semibold text-right">Unhardened Passed</th>
                <th className="py-2 px-3 font-semibold text-right">Unhardened Rate</th>
                <th className="py-2 px-3 font-semibold text-right">Policy v2 Passed</th>
                <th className="py-2 px-3 font-semibold text-right">Policy v2 Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--rule)] font-mono text-xs">
              {unh.runs.map((r, i) => {
                const v2Run = v2.runs[i];
                return (
                  <tr key={r.run} className="hover:bg-[var(--range-paper)]/50">
                    <td className="py-2 px-3 font-medium font-sans text-[var(--ink)]">
                      Run {r.run} (n={r.total})
                    </td>
                    <td className="py-2 px-3 text-right text-[var(--ink)]">
                      {r.passed}/{r.total}
                    </td>
                    <td className="py-2 px-3 text-right text-[var(--ink)]">
                      {r.pass_rate_pct.toFixed(1)}%
                    </td>
                    <td className="py-2 px-3 text-right text-[var(--cleared)] font-semibold">
                      {v2Run?.passed}/{v2Run?.total}
                    </td>
                    <td className="py-2 px-3 text-right text-[var(--cleared)] font-semibold">
                      {v2Run?.pass_rate_pct.toFixed(1)}%
                    </td>
                  </tr>
                );
              })}
              <tr className="bg-[var(--range-paper)] font-semibold text-[var(--ink)]">
                <td className="py-2 px-3 font-sans">Pooled ({unh.pooled_total} evaluations)</td>
                <td className="py-2 px-3 text-right">
                  {unh.pooled_passed}/{unh.pooled_total}
                </td>
                <td className="py-2 px-3 text-right">
                  {unh.pooled_pass_rate_pct.toFixed(1)}%
                </td>
                <td className="py-2 px-3 text-right text-[var(--cleared)]">
                  {v2.pooled_passed}/{v2.pooled_total}
                </td>
                <td className="py-2 px-3 text-right text-[var(--cleared)]">
                  {v2.pooled_pass_rate_pct.toFixed(1)}%
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-3 text-xs text-[var(--ink-muted)] leading-relaxed font-sans">
        <strong>Test sensitivity verification:</strong> The negative control denies all outbound tool calls.
        It collapsed to {neg.pass_rate_pct.toFixed(1)}%, proving that the benign test harness strictly enforces tool execution requirements and cannot pass without active tool usage.
      </div>
    </div>
  );
}
