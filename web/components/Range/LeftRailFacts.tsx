"use client";

import React, { useState } from "react";
import { PolicyHashes } from "@/lib/api";

interface LeftRailFactsProps {
  totalAttacks: number;
  standardCount: number;
  probeCount: number;
  policyHashes: PolicyHashes | null;
}

export function LeftRailFacts({
  totalAttacks,
  standardCount,
  probeCount,
  policyHashes,
}: LeftRailFactsProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const v1Hash = policyHashes?.v1 ?? "f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265";
  const v2Hash = policyHashes?.v2 ?? "31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e";

  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 space-y-5 text-xs">
      <div>
        <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
          Run Facts
        </div>
        <div className="space-y-2 text-[var(--ink)]">
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Target Agent</span>
            <span className="font-mono font-medium">inbox-assistant</span>
          </div>
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Scope</span>
            <span className="font-sans">Freight EDI & Mail</span>
          </div>
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Attacks</span>
            <span className="font-mono font-semibold">
              {totalAttacks} <span className="font-normal text-[var(--ink-muted)] text-[11px]">({standardCount} std, {probeCount} probe)</span>
            </span>
          </div>
        </div>
      </div>

      <div>
        <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
          Model Roles
        </div>
        <div className="space-y-1.5 font-mono text-[11px] text-[var(--ink)]">
          <div className="flex items-start justify-between py-1 border-b border-[var(--rule)]/60">
            <span className="font-semibold text-[var(--ink)]">Ultra</span>
            <span className="text-[var(--ink-muted)] text-right font-sans">Recon, Policy, Report</span>
          </div>
          <div className="flex items-start justify-between py-1 border-b border-[var(--rule)]/60">
            <span className="font-semibold text-[var(--ink)]">Super</span>
            <span className="text-[var(--ink-muted)] text-right font-sans">Target Agent Brain</span>
          </div>
          <div className="flex items-start justify-between py-1 border-b border-[var(--rule)]/60">
            <span className="font-semibold text-[var(--ink)]">Nano</span>
            <span className="text-[var(--ink-muted)] text-right font-sans">Swarm Attack Generator</span>
          </div>
          <div className="flex items-start justify-between py-1">
            <span className="font-semibold text-[var(--ink)]">Omni</span>
            <span className="text-[var(--ink-muted)] text-right font-sans">Image / Invoice Reader</span>
          </div>
        </div>
      </div>

      <div>
        <div className="text-[11px] font-semibold text-[var(--ink-muted)] uppercase tracking-wider mb-2">
          Policy SHA-256
        </div>
        <div className="space-y-2">
          <div className="p-2 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-[var(--ink-muted)]">Policy v1</span>
              <button
                type="button"
                onClick={() => handleCopy("v1", v1Hash)}
                className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--ink)] hover:text-[var(--panel)] transition-colors focus-visible:outline-1"
                aria-label="Copy Policy v1 hash"
              >
                {copiedKey === "v1" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="font-mono text-[11px] text-[var(--ink)] truncate" title={v1Hash}>
              {v1Hash.slice(0, 10)}...{v1Hash.slice(-8)}
            </div>
          </div>

          <div className="p-2 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-[var(--ink-muted)] font-medium">Policy v2 (Active)</span>
              <button
                type="button"
                onClick={() => handleCopy("v2", v2Hash)}
                className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--ink)] hover:text-[var(--panel)] transition-colors focus-visible:outline-1"
                aria-label="Copy Policy v2 hash"
              >
                {copiedKey === "v2" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="font-mono text-[11px] text-[var(--ink)] font-semibold truncate" title={v2Hash}>
              {v2Hash.slice(0, 10)}...{v2Hash.slice(-8)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
