"use client";

import React, { useState } from "react";
import { ModelRole, PolicyHashes } from "@/lib/api";

interface LeftRailFactsProps {
  totalAttacks: number;
  standardCount: number;
  probeCount: number;
  policyHashes: PolicyHashes | null;
  modelRoles?: ModelRole[] | null;
  horizontal?: boolean;
}

export function LeftRailFacts({
  totalAttacks,
  standardCount,
  probeCount,
  policyHashes,
  modelRoles,
  horizontal = false,
}: LeftRailFactsProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const v1Hash = policyHashes?.v1 ?? "f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265";
  const v2Hash = policyHashes?.v2 ?? "31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e";

  const activeRoles: ModelRole[] = modelRoles && modelRoles.length > 0
    ? modelRoles
    : [
        { role: "Ultra", model_id: "nvidia/Nemotron-3-Ultra-550b-a55b", description: "Recon, defender, triage" },
        { role: "Super", model_id: "nvidia/nemotron-3-super-120b-a12b", description: "Target agent brain" },
        { role: "Lightning", model_id: "nvidia/Nemotron-3_5-Lightning", description: "Payload generation" },
      ];

  const containerClasses = horizontal
    ? "grid grid-cols-1 md:grid-cols-3 gap-6 text-xs"
    : "space-y-5 text-xs";

  return (
    <div className={containerClasses}>
      {/* 1. Run Facts */}
      <div>
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans mb-2">
          Run facts
        </div>
        <div className="space-y-2 text-[var(--ink)] font-sans">
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Target agent</span>
            <span className="font-mono font-medium text-xs">inbox-assistant</span>
          </div>
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Scope</span>
            <span className="font-sans text-xs">Freight EDI & Mail</span>
          </div>
          <div className="flex items-center justify-between pb-1.5 border-b border-[var(--rule)]">
            <span className="text-[var(--ink-muted)]">Attacks</span>
            <span className="font-mono font-semibold text-xs">
              {totalAttacks} <span className="font-normal text-[var(--ink-muted)] font-sans text-xs">({standardCount} standard, {probeCount} probes)</span>
            </span>
          </div>
        </div>
      </div>

      {/* 2. Model Roles (dynamically rendered from API) */}
      <div>
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans mb-2">
          Model roles
        </div>
        <div className="space-y-2 text-xs text-[var(--ink)] font-sans">
          {activeRoles.map((roleItem) => (
            <div
              key={roleItem.role}
              className="flex items-start justify-between py-1 border-b border-[var(--rule)]/60 gap-2"
            >
              <div className="min-w-0">
                <span className="font-semibold text-[var(--ink)] font-sans text-xs">{roleItem.role}</span>
                {roleItem.model_id && (
                  <div className="font-mono text-xs text-[var(--ink-muted)] truncate max-w-[180px]">
                    {roleItem.model_id.replace("nvidia/", "")}
                  </div>
                )}
              </div>
              <span className="text-[var(--ink-muted)] text-right font-sans text-xs shrink-0">
                {roleItem.description}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Policy SHA-256 */}
      <div>
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans mb-2">
          Policy SHA-256
        </div>
        <div className="space-y-2">
          <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
            <div className="flex items-center justify-between text-xs mb-1 font-sans">
              <span className="text-[var(--ink-muted)]">Policy v1</span>
              <button
                type="button"
                onClick={() => handleCopy("v1", v1Hash)}
                className="font-mono text-xs px-2 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--ink)] hover:text-[var(--panel)] transition-colors focus-visible:outline-1"
                aria-label="Copy Policy v1 hash"
              >
                {copiedKey === "v1" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="font-mono text-xs text-[var(--ink)] truncate" title={v1Hash}>
              {v1Hash.slice(0, 10)}...{v1Hash.slice(-8)}
            </div>
          </div>

          <div className="p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
            <div className="flex items-center justify-between text-xs mb-1 font-sans">
              <span className="text-[var(--ink-muted)] font-medium">Policy v2 (Active)</span>
              <button
                type="button"
                onClick={() => handleCopy("v2", v2Hash)}
                className="font-mono text-xs px-2 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] text-[var(--ink)] hover:bg-[var(--ink)] hover:text-[var(--panel)] transition-colors focus-visible:outline-1"
                aria-label="Copy Policy v2 hash"
              >
                {copiedKey === "v2" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="font-mono text-xs text-[var(--ink)] font-semibold truncate" title={v2Hash}>
              {v2Hash.slice(0, 10)}...{v2Hash.slice(-8)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
