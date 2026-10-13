"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "motion/react";
import { AttackRecord, AttackTraceResponse, getAttackTrace } from "@/lib/api";
import { AttackCondition } from "@/lib/range-utils";

interface AttackDrawerProps {
  attack: AttackRecord | null;
  condition: AttackCondition;
  onConditionChange: (cond: AttackCondition) => void;
  onClose: () => void;
}

export function AttackDrawer({
  attack,
  condition,
  onConditionChange,
  onClose,
}: AttackDrawerProps) {
  const [traceData, setTraceData] = useState<AttackTraceResponse | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);
  const [expandedResults, setExpandedResults] = useState<Record<number, boolean>>({});
  const [copiedPayload, setCopiedPayload] = useState(false);

  // Keyboard close on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  // Lazy trace loading for current attack and chosen condition
  useEffect(() => {
    if (!attack) return;

    let active = true;

    getAttackTrace(attack.id, condition)
      .then((data) => {
        if (active) {
          setTraceData(data);
          setTraceLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setTraceError(err?.message || "Failed to load trace");
          setTraceLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [attack, condition]);

  const toggleResultExpand = (idx: number) => {
    setExpandedResults((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const copyPayload = () => {
    if (!traceData?.payload) return;
    navigator.clipboard.writeText(traceData.payload);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  if (!attack) return null;

  const condState = attack[condition];

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.4 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-[var(--ink)]"
          aria-hidden="true"
        />

        {/* Drawer Panel */}
        <motion.aside
          initial={{ x: "100%" }}
          animate={{ x: 0 }}
          exit={{ x: "100%" }}
          transition={{ type: "spring", damping: 28, stiffness: 280 }}
          className="relative w-full max-w-xl bg-[var(--panel)] border-l border-[var(--rule)] h-full overflow-y-auto shadow-2xl p-5 sm:p-6 flex flex-col z-10"
          role="dialog"
          aria-modal="true"
          aria-labelledby="drawer-title"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-4 pb-4 border-b border-[var(--rule)]">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] font-semibold text-[var(--ink)]">
                  {attack.id}
                </span>
                <span className="text-xs text-[var(--ink-muted)]">
                  {attack.channel.replace(/_/g, " ")} • {attack.category.replace(/_/g, " ")}
                </span>
              </div>
              <h2 id="drawer-title" className="font-display font-semibold text-lg text-[var(--ink)]">
                {attack.strategy}
              </h2>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 -mr-1 rounded-[var(--radius-sm)] text-[var(--ink-muted)] hover:text-[var(--ink)] hover:bg-[var(--range-paper)] focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
              aria-label="Close attack drawer"
            >
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 5 L15 15 M15 5 L5 15" />
              </svg>
            </button>
          </div>

          <div className="space-y-6 my-4 flex-1">
            {/* Condition outcome comparison */}
            <div>
              <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
                Condition Outcome Comparison
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs">
                {/* Unhardened */}
                <button
                  type="button"
                  onClick={() => onConditionChange("unhardened")}
                  className={`p-2.5 rounded-[var(--radius-sm)] border text-left transition-all ${
                    condition === "unhardened"
                      ? "border-[var(--ink)] bg-[var(--range-paper)] ring-1 ring-[var(--ink)]"
                      : "border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)]"
                  }`}
                >
                  <div className="text-[10px] text-[var(--ink-muted)] font-medium">Unhardened</div>
                  <div
                    className={`font-semibold font-mono mt-0.5 ${
                      attack.unhardened.outcome === "breach"
                        ? "text-[var(--breach)]"
                        : "text-[var(--ink)]"
                    }`}
                  >
                    {attack.unhardened.outcome.toUpperCase()}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--ink-muted)] mt-1">
                    {attack.unhardened.unsafe ? "M1/M2/M3" : attack.unhardened.m4 ? "M4 leak" : "Defended"}
                  </div>
                </button>

                {/* Policy v1 */}
                <button
                  type="button"
                  onClick={() => onConditionChange("v1")}
                  className={`p-2.5 rounded-[var(--radius-sm)] border text-left transition-all ${
                    condition === "v1"
                      ? "border-[var(--ink)] bg-[var(--range-paper)] ring-1 ring-[var(--ink)]"
                      : "border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)]"
                  }`}
                >
                  <div className="text-[10px] text-[var(--ink-muted)] font-medium">Policy v1</div>
                  <div
                    className={`font-semibold font-mono mt-0.5 ${
                      attack.v1.outcome === "breach"
                        ? "text-[var(--in-flight)]"
                        : "text-[var(--cleared)]"
                    }`}
                  >
                    {attack.v1.outcome.toUpperCase()}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--ink-muted)] mt-1 truncate">
                    {attack.v1.policy_block_rule ? "Rule blocked" : attack.v1.m4 ? "M4 leak" : "Defended"}
                  </div>
                </button>

                {/* Policy v2 */}
                <button
                  type="button"
                  onClick={() => onConditionChange("v2")}
                  className={`p-2.5 rounded-[var(--radius-sm)] border text-left transition-all ${
                    condition === "v2"
                      ? "border-[var(--cleared)] bg-[var(--range-paper)] ring-1 ring-[var(--cleared)]"
                      : "border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)]"
                  }`}
                >
                  <div className="text-[10px] text-[var(--ink-muted)] font-medium">Policy v2</div>
                  <div
                    className={`font-semibold font-mono mt-0.5 ${
                      attack.v2.outcome === "breach"
                        ? "text-[var(--breach)]"
                        : "text-[var(--cleared)]"
                    }`}
                  >
                    {attack.v2.outcome.toUpperCase()}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--ink-muted)] mt-1 truncate">
                    {attack.v2.policy_block_rule ? "Rule blocked" : "Defended"}
                  </div>
                </button>
              </div>
            </div>

            {/* Named policy rule if stopped */}
            {condState.policy_block_rule && (
              <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--cleared)] text-xs">
                <div className="text-[11px] font-semibold text-[var(--cleared)] uppercase tracking-wider mb-1">
                  Enforcing Policy Rule ({condition})
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-[var(--ink)]">
                    {condState.policy_block_rule}
                  </span>
                  <Link
                    href={`/policy#${condState.policy_block_rule}`}
                    className="text-[11px] text-[var(--cleared)] underline hover:opacity-80 font-medium shrink-0"
                  >
                    View policy rule
                  </Link>
                </div>
              </div>
            )}

            {/* Attack Payload in Mono */}
            <div>
              <div className="flex items-center justify-between text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-1.5">
                <span>Attack Payload Content</span>
                {traceData?.payload && (
                  <button
                    type="button"
                    onClick={copyPayload}
                    className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--range-paper)]"
                  >
                    {copiedPayload ? "Copied" : "Copy Payload"}
                  </button>
                )}
              </div>
              <div className="font-mono text-xs text-[var(--ink)] bg-[var(--range-paper)] p-3 rounded-[var(--radius-sm)] border border-[var(--rule)] max-h-40 overflow-y-auto whitespace-pre-wrap select-all leading-relaxed">
                {traceData?.payload || (traceLoading ? "Loading payload..." : "(Payload available in trace)")}
              </div>
            </div>

            {/* Trace Viewer */}
            <div>
              <div className="flex items-center justify-between text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
                <span>Execution Trace ({condition})</span>
                {traceData && (
                  <span className="font-mono text-[10px] text-[var(--ink-muted)]">
                    {traceData.trace?.length ?? 0} tool calls
                  </span>
                )}
              </div>

              {traceLoading && (
                <div className="p-6 text-center text-xs text-[var(--ink-muted)] font-mono bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)]">
                  Loading trace from /api/attacks/{attack.id}/trace...
                </div>
              )}

              {traceError && (
                <div className="p-3 text-xs text-[var(--breach)] bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--breach)] font-mono">
                  {traceError}
                </div>
              )}

              {traceData && (!traceData.trace || traceData.trace.length === 0) && (
                <div className="p-4 text-xs text-[var(--ink-muted)] bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)]">
                  No tool calls were executed in this trace.
                </div>
              )}

              {traceData && traceData.trace && traceData.trace.length > 0 && (
                <div className="space-y-3" role="feed" aria-label="Tool call trace">
                  {traceData.trace.map((step, idx) => {
                    const isBlocked = Boolean(step.policy_block);
                    const isLeaked =
                      Boolean(step.canary) ||
                      Boolean((step.result as Record<string, unknown>)?.status === "leaked") ||
                      (condition === "unhardened" && attack.unhardened.unsafe && idx === traceData.trace.length - 1);

                    const isExpanded = expandedResults[idx] ?? false;

                    return (
                      <div
                        key={idx}
                        className={`p-3 rounded-[var(--radius-sm)] border text-xs font-mono transition-colors ${
                          isBlocked
                            ? "bg-[var(--range-paper)] border-[var(--cleared)]"
                            : isLeaked
                            ? "bg-[var(--range-paper)] border-[var(--breach)]"
                            : "bg-[var(--range-paper)] border-[var(--rule)]"
                        }`}
                      >
                        {/* Call title and badge */}
                        <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-[var(--rule)]/60">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-[var(--ink-muted)]">#{idx + 1}</span>
                            <span className="font-bold text-[var(--ink)]">
                              {String(step.tool || "tool_call")}()
                            </span>
                          </div>

                          {isBlocked && (
                            <span className="px-1.5 py-0.5 rounded bg-[var(--cleared)] text-[var(--panel)] text-[10px] font-sans font-semibold">
                              Blocked by policy
                            </span>
                          )}

                          {!isBlocked && isLeaked && (
                            <span className="px-1.5 py-0.5 rounded bg-[var(--breach)] text-[var(--panel)] text-[10px] font-sans font-semibold">
                              Leaked canary
                            </span>
                          )}
                        </div>

                        {/* Arguments */}
                        <div className="mt-2 text-[11px]">
                          <span className="text-[var(--ink-muted)] select-none">args: </span>
                          <span className="text-[var(--ink)] break-all">
                            {JSON.stringify(step.args || step.arguments || {}, null, 1)}
                          </span>
                        </div>

                        {/* Policy block explanation if blocked */}
                        {Boolean(isBlocked && step.policy_rule) && (
                          <div className="mt-1.5 text-[11px] text-[var(--cleared)]">
                            <span className="select-none font-sans font-semibold">Rule: </span>
                            <span>{String(step.policy_rule ?? "")}</span>
                          </div>
                        )}

                        {/* Result with truncation */}
                        {step.result !== undefined && (
                          <div className="mt-2 pt-1.5 border-t border-[var(--rule)]/60 text-[11px]">
                            <div className="flex items-center justify-between text-[10px] text-[var(--ink-muted)] mb-0.5">
                              <span>result:</span>
                              <button
                                type="button"
                                onClick={() => toggleResultExpand(idx)}
                                className="underline hover:text-[var(--ink)]"
                              >
                                {isExpanded ? "Collapse" : "Expand"}
                              </button>
                            </div>
                            <div className="text-[var(--ink-muted)] break-all leading-tight">
                              {isExpanded
                                ? JSON.stringify(step.result, null, 2)
                                : JSON.stringify(step.result).slice(0, 110) +
                                  (JSON.stringify(step.result).length > 110 ? "..." : "")}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </motion.aside>
      </div>
    </AnimatePresence>
  );
}
