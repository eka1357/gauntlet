"use client";

import React, { useEffect, useState, useRef, useCallback, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import Link from "next/link";
import { motion, AnimatePresence } from "motion/react";
import { AttackRecord, AttackTraceResponse, getAttackTrace } from "@/lib/api";
import { AttackCondition, AttackConditionStatus, getAttackConditionStatus } from "@/lib/range-utils";

interface AttackDrawerProps {
  attack: AttackRecord | null;
  condition: AttackCondition;
  onConditionChange: (cond: AttackCondition) => void;
  onClose: () => void;
}

const CONDITIONS: Array<{ key: AttackCondition; label: string }> = [
  { key: "unhardened", label: "Unhardened" },
  { key: "v1", label: "Policy v1" },
  { key: "v2", label: "Policy v2" },
];

function subscribeClient() {
  return () => {};
}

function getClientSnapshot() {
  return true;
}

function getServerSnapshot() {
  return false;
}

/**
 * Derives plain-language descriptions of each true metric flag.
 * M1: canary token exfiltration to non-allowlisted destination
 * M2: vault file access
 * M3: unauthorized outbound egress (email / http)
 * M4: canary leakage via side-channel without full breach
 */
export function getMetricBreachDescriptions(metrics: {
  m1?: boolean;
  m2?: boolean;
  m3?: boolean;
  m4?: boolean;
  unsafe?: boolean;
}): string[] {
  const lines: string[] = [];
  if (metrics.m2) {
    lines.push("Read a vault file (/vault/secret_notes.txt)");
  }
  if (metrics.m3) {
    lines.push("Sent to a non-allowlisted destination");
  }
  if (metrics.m1) {
    lines.push("Exfiltrated canary token to an external destination");
  }
  if (metrics.m4 && !metrics.unsafe) {
    lines.push("Leaked canary token via side-channel without unsafe egress");
  }
  return lines;
}

export function AttackDrawer({
  attack,
  condition,
  onConditionChange,
  onClose,
}: AttackDrawerProps) {
  // Use React 19 recommended hydration detection
  const mounted = useSyncExternalStore(subscribeClient, getClientSnapshot, getServerSnapshot);

  // Trace condition tab - defaults to condition currently selected in the grid
  const [selectedTraceTab, setSelectedTraceTab] = useState<AttackCondition>(condition);
  // Lazy cache of traces keyed by condition
  const [traceCache, setTraceCache] = useState<Partial<Record<AttackCondition, AttackTraceResponse>>>({});
  const [errorMap, setErrorMap] = useState<Partial<Record<AttackCondition, string>>>({});
  const [expandedResults, setExpandedResults] = useState<Record<number, boolean>>({});
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isPayloadExpanded, setIsPayloadExpanded] = useState(false);

  const closeBtnRef = useRef<HTMLButtonElement>(null);
  const triggerAttackIdRef = useRef<string | null>(null);

  // Synchronize state when attack changes during render
  const [prevAttackId, setPrevAttackId] = useState<string | null>(null);
  if (attack && attack.id !== prevAttackId) {
    setPrevAttackId(attack.id);
    setSelectedTraceTab(condition);
    setTraceCache({});
    setErrorMap({});
    setExpandedResults({});
    setIsPayloadExpanded(false);
  }

  // When attack opens, store its id and focus the close button
  useEffect(() => {
    if (attack) {
      triggerAttackIdRef.current = attack.id;
      closeBtnRef.current?.focus();
    }
  }, [attack]);

  // Focus return handler
  const handleClose = useCallback(() => {
    const targetId = triggerAttackIdRef.current || attack?.id;
    onClose();
    if (targetId) {
      requestAnimationFrame(() => {
        const square = document.querySelector(`[data-range-square="${targetId}"]`) as HTMLElement | null;
        square?.focus();
      });
    }
  }, [attack, onClose]);

  // Keyboard close on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        handleClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleClose]);

  // Lazy trace loading per tab: loads on demand and caches in traceCache
  useEffect(() => {
    if (!attack) return;
    const tabKey = selectedTraceTab;
    if (traceCache[tabKey] || errorMap[tabKey]) return;

    let active = true;

    getAttackTrace(attack.id, tabKey)
      .then((data) => {
        if (active) {
          setTraceCache((prev) => ({ ...prev, [tabKey]: data }));
          setErrorMap((prev) => ({ ...prev, [tabKey]: undefined }));
        }
      })
      .catch((err) => {
        if (active) {
          setErrorMap((prev) => ({ ...prev, [tabKey]: err?.message || "Failed to load trace" }));
        }
      });

    return () => {
      active = false;
    };
  }, [attack, selectedTraceTab, traceCache, errorMap]);

  const toggleResultExpand = (idx: number) => {
    setExpandedResults((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const handleTabSwitch = (tab: AttackCondition) => {
    setSelectedTraceTab(tab);
    onConditionChange(tab);
  };

  const currentTrace = traceCache[selectedTraceTab];
  const isTraceLoading = Boolean(attack && !currentTrace && !errorMap[selectedTraceTab]);
  const currentTraceError = errorMap[selectedTraceTab];

  // Derive payload from any cached trace or the current tab trace
  const payloadText =
    currentTrace?.payload ||
    traceCache.unhardened?.payload ||
    traceCache.v1?.payload ||
    traceCache.v2?.payload ||
    "";

  const copyPayload = () => {
    if (!payloadText) return;
    navigator.clipboard.writeText(payloadText);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  if (!attack || !mounted) return null;

  const currentCondRecord = attack[condition];
  const activeBreachLines = getMetricBreachDescriptions(currentCondRecord);

  const drawerContent = (
    <AnimatePresence>
      <div className="fixed inset-0 w-screen h-screen z-50 overflow-hidden flex justify-end">
        {/* Full-page Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.4 }}
          exit={{ opacity: 0 }}
          onClick={handleClose}
          className="fixed inset-0 w-full h-full bg-[var(--ink)]"
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
              <div className="flex items-center gap-2 mb-1.5">
                <span className="font-mono text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] font-semibold text-[var(--ink)]">
                  {attack.id}
                </span>
                <span className="text-xs font-sans text-[var(--ink-muted)]">
                  {attack.channel.replace(/_/g, " ")}, {attack.category.replace(/_/g, " ")}
                </span>
              </div>
              <h2 id="drawer-title" className="font-display font-semibold text-[20px] leading-snug text-[var(--ink)]">
                {attack.strategy}
              </h2>
            </div>

            <button
              ref={closeBtnRef}
              autoFocus
              type="button"
              onClick={handleClose}
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
              <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans mb-2">
                Condition outcome comparison
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                {CONDITIONS.map(({ key: condKey, label }) => {
                  const status: AttackConditionStatus = getAttackConditionStatus(attack, condKey);
                  const isCurrent = condition === condKey;
                  const condMetrics = attack[condKey];
                  const flagLines = getMetricBreachDescriptions(condMetrics);

                  let statusColor = "text-[var(--ink)]";
                  if (status === "Unsafe") {
                    statusColor = "text-[var(--breach)]";
                  } else if (status === "Canary-only leak") {
                    statusColor = "text-[var(--in-flight)]";
                  } else if (status === "Attempted, blocked by policy") {
                    statusColor = "text-[var(--cleared)]";
                  }

                  let subtext = "Target defended";
                  if (status === "Unsafe") {
                    subtext = flagLines.length > 0 ? flagLines[0] : "Unsafe action executed";
                  } else if (status === "Canary-only leak") {
                    subtext = "Side-channel canary leak";
                  } else if (status === "Attempted, blocked by policy") {
                    subtext = condMetrics.policy_block_rule ? "Rule stopped" : "Policy blocked";
                  }

                  return (
                    <button
                      key={condKey}
                      type="button"
                      onClick={() => handleTabSwitch(condKey)}
                      className={`p-2.5 rounded-[var(--radius-sm)] border text-left transition-all ${
                        isCurrent
                          ? "border-[var(--ink)] bg-[var(--range-paper)] ring-1 ring-[var(--ink)]"
                          : "border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)]"
                      }`}
                    >
                      <div className="text-xs text-[var(--ink-muted)] font-medium font-sans">{label}</div>
                      <div className={`font-semibold font-sans text-xs mt-1 leading-snug break-words ${statusColor}`}>
                        {status}
                      </div>
                      <div className="font-sans text-xs text-[var(--ink-muted)] mt-1 break-words leading-tight" title={subtext}>
                        {subtext}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Plain-language lines for true metric flags */}
            {activeBreachLines.length > 0 && (
              <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--breach)] text-xs">
                <div className="font-semibold text-[var(--breach)] font-sans mb-1.5 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[var(--breach)] shrink-0" />
                  <span>
                    True metric flags under {CONDITIONS.find((c) => c.key === condition)?.label}:
                  </span>
                </div>
                <ul className="space-y-1 pl-4 list-disc text-[var(--ink)] font-sans">
                  {activeBreachLines.map((line, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {line}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Named policy rule if stopped */}
            {currentCondRecord.policy_block_rule && (
              <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--cleared)] text-xs">
                <div className="text-xs font-semibold text-[var(--cleared)] font-sans mb-1">
                  Enforcing policy rule ({condition})
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-xs text-[var(--ink)]">
                    {currentCondRecord.policy_block_rule}
                  </span>
                  <Link
                    href={`/policy#${currentCondRecord.policy_block_rule}`}
                    className="text-xs text-[var(--cleared)] underline hover:opacity-80 font-medium font-sans shrink-0"
                  >
                    View policy rule
                  </Link>
                </div>
              </div>
            )}

            {/* Defended summary if safe and no rule fired */}
            {!currentCondRecord.unsafe && !currentCondRecord.policy_block_rule && !currentCondRecord.m4 && (
              <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs text-[var(--ink-muted)] font-sans">
                Target agent defended under {CONDITIONS.find((c) => c.key === condition)?.label}. No vault files accessed, canary tokens leaked, or unauthorized outbound messages sent.
              </div>
            )}

            {/* Attack Payload with scrollable expand/collapse and word-boundary wrapping */}
            <div>
              <div className="flex items-center justify-between text-xs font-semibold text-[var(--ink-muted)] font-sans mb-1.5">
                <span>Attack payload content</span>
                <div className="flex items-center gap-2">
                  {payloadText && (
                    <button
                      type="button"
                      onClick={() => setIsPayloadExpanded(!isPayloadExpanded)}
                      className="text-xs font-sans px-2 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--range-paper)]"
                    >
                      {isPayloadExpanded ? "Collapse" : "Expand"}
                    </button>
                  )}
                  {payloadText && (
                    <button
                      type="button"
                      onClick={copyPayload}
                      className="font-mono text-xs px-2 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--range-paper)]"
                    >
                      {copiedPayload ? "Copied" : "Copy payload"}
                    </button>
                  )}
                </div>
              </div>
              <div
                className={`font-mono text-xs text-[var(--ink)] bg-[var(--range-paper)] p-3 rounded-[var(--radius-sm)] border border-[var(--rule)] select-all leading-relaxed whitespace-pre-wrap break-words overflow-y-auto ${
                  isPayloadExpanded ? "max-h-96" : "max-h-36"
                }`}
                style={{ overflowWrap: "break-word", wordBreak: "normal" }}
              >
                {payloadText || (isTraceLoading ? "Loading payload from trace..." : "(Payload available in trace)")}
              </div>
            </div>

            {/* Trace Viewer with lazy condition tabs */}
            <div>
              <div className="flex items-center justify-between text-xs font-semibold text-[var(--ink-muted)] font-sans mb-2">
                <span>Execution trace</span>
                {currentTrace && (
                  <span className="font-mono text-xs text-[var(--ink-muted)]">
                    {currentTrace.trace?.length ?? 0} tool calls
                  </span>
                )}
              </div>

              {/* Tabs: Unhardened | Policy v1 | Policy v2 */}
              <div
                className="flex items-center gap-1 p-1 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] mb-3"
                role="tablist"
                aria-label="Execution trace condition tabs"
              >
                {CONDITIONS.map(({ key: condKey, label }) => {
                  const isSelected = selectedTraceTab === condKey;
                  return (
                    <button
                      key={condKey}
                      type="button"
                      role="tab"
                      aria-selected={isSelected}
                      onClick={() => handleTabSwitch(condKey)}
                      className={`flex-1 py-1 px-2.5 rounded-[var(--radius-sm)] text-xs font-sans transition-all ${
                        isSelected
                          ? "bg-[var(--panel)] text-[var(--ink)] shadow-sm font-semibold border border-[var(--rule)]"
                          : "text-[var(--ink-muted)] hover:text-[var(--ink)] font-normal"
                      }`}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>

              {isTraceLoading && (
                <div className="p-6 text-center text-xs text-[var(--ink-muted)] font-mono bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)]">
                  Loading trace ({selectedTraceTab}) from /api/attacks/{attack.id}/trace...
                </div>
              )}

              {currentTraceError && (
                <div className="p-3 text-xs text-[var(--breach)] bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--breach)] font-mono">
                  {currentTraceError}
                </div>
              )}

              {currentTrace && (!currentTrace.trace || currentTrace.trace.length === 0) && !isTraceLoading && (
                <div className="p-4 text-xs text-[var(--ink-muted)] bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)] font-sans">
                  No tool calls were executed in this trace ({selectedTraceTab}).
                </div>
              )}

              {currentTrace && currentTrace.trace && currentTrace.trace.length > 0 && !isTraceLoading && (
                <div className="space-y-3" role="feed" aria-label={`Tool call trace for ${selectedTraceTab}`}>
                  {currentTrace.trace.map((step, idx) => {
                    const isBlocked = Boolean(step.policy_block);
                    const isLeaked =
                      Boolean(step.canary) ||
                      Boolean((step.result as Record<string, unknown>)?.status === "leaked") ||
                      (selectedTraceTab === "unhardened" && attack.unhardened.unsafe && idx === currentTrace.trace.length - 1);

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
                            <span className="text-xs text-[var(--ink-muted)]">#{idx + 1}</span>
                            <span className="font-bold text-[var(--ink)]">
                              {String(step.tool || "tool_call")}()
                            </span>
                          </div>

                          {isBlocked && (
                            <span className="px-2 py-0.5 rounded bg-[var(--cleared)] text-[var(--panel)] text-xs font-sans font-semibold">
                              Blocked by policy
                            </span>
                          )}

                          {!isBlocked && isLeaked && (
                            <span className="px-2 py-0.5 rounded bg-[var(--breach)] text-[var(--panel)] text-xs font-sans font-semibold">
                              Leaked canary
                            </span>
                          )}
                        </div>

                        {/* Arguments */}
                        <div className="mt-2 text-xs leading-relaxed">
                          <span className="text-[var(--ink-muted)] select-none">args: </span>
                          <span className="text-[var(--ink)] break-words" style={{ overflowWrap: "break-word" }}>
                            {JSON.stringify(step.args || step.arguments || {}, null, 1)}
                          </span>
                        </div>

                        {/* Policy block explanation if blocked */}
                        {Boolean(isBlocked && step.policy_rule) && (
                          <div className="mt-1.5 text-xs text-[var(--cleared)]">
                            <span className="select-none font-sans font-semibold">Rule: </span>
                            <span>{String(step.policy_rule ?? "")}</span>
                          </div>
                        )}

                        {/* Result with truncation */}
                        {step.result !== undefined && (
                          <div className="mt-2 pt-1.5 border-t border-[var(--rule)]/60 text-xs">
                            <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-0.5 font-sans">
                              <span>result:</span>
                              <button
                                type="button"
                                onClick={() => toggleResultExpand(idx)}
                                className="underline hover:text-[var(--ink)] font-sans"
                              >
                                {isExpanded ? "Collapse" : "Expand"}
                              </button>
                            </div>
                            <div
                              className="text-[var(--ink-muted)] leading-relaxed font-mono text-xs break-words"
                              style={{ overflowWrap: "break-word" }}
                            >
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

  return createPortal(drawerContent, document.body);
}
