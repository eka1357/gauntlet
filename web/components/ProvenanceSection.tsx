"use client";

import React from "react";
import { PolicyHashes, RunCosts } from "@/lib/api";

interface ProvenanceSectionProps {
  policyHashes: PolicyHashes;
  costs: RunCosts;
  totalCostUsd?: number;
  seed?: number;
  elapsedSec?: number;
}

export function ProvenanceSection({
  policyHashes,
  costs,
  totalCostUsd,
  seed,
  elapsedSec,
}: ProvenanceSectionProps) {
  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5">
      <div className="mb-4">
        <div className="text-xs font-semibold text-[var(--ink-muted)] uppercase tracking-wider">
          Audit & Accounting
        </div>
        <h3 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)] mt-0.5">
          Policy cryptographic hashes and run expenditure
        </h3>
        <p className="text-xs text-[var(--ink-muted)] mt-1">
          Exact cryptographic fingerprints for reproducible verification and Token Factory API spend accounting.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Hashes in Mono */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] space-y-3">
          <div className="text-xs font-semibold text-[var(--ink)]">
            Policy Artifact Checksums (SHA-256)
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-1">
              <span>Policy v1 (Iteration 1)</span>
              <span className="font-mono text-[10px]">hardened_policy.yaml</span>
            </div>
            <div className="font-mono text-[11px] text-[var(--ink)] bg-[var(--panel)] p-2 rounded-[var(--radius-sm)] border border-[var(--rule)] break-all select-all">
              {policyHashes.v1}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-1">
              <span>Policy v2 (Iteration 2)</span>
              <span className="font-mono text-[10px]">policy_v2.yaml</span>
            </div>
            <div className="font-mono text-[11px] text-[var(--ink)] bg-[var(--panel)] p-2 rounded-[var(--radius-sm)] border border-[var(--rule)] break-all select-all font-semibold">
              {policyHashes.v2}
            </div>
          </div>

          {(seed !== undefined || elapsedSec !== undefined) && (
            <div className="pt-2 border-t border-[var(--rule)] flex items-center justify-between font-mono text-[11px] text-[var(--ink-muted)]">
              {seed !== undefined && <span>Seed: {seed}</span>}
              {elapsedSec !== undefined && <span>Duration: {elapsedSec.toFixed(1)}s</span>}
            </div>
          )}
        </div>

        {/* Run Costs in Mono */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-[var(--ink)] mb-3">
              Token Factory Run Expenditure Breakdown
            </div>

            <div className="space-y-2 font-mono text-xs text-[var(--ink)]">
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)]">Policy v1 Evaluation Run</span>
                <span className="font-semibold">${costs.policy_v1_run_usd.toFixed(4)}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)]">Confirmation Set 2 Run (Realistic)</span>
                <span className="font-semibold">${costs.confirmation_set2_run_usd.toFixed(4)}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)]">Benign Variance & Naive Set Run</span>
                <span className="font-semibold">${costs.benign_variance_naive_run_usd.toFixed(4)}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t-2 border-[var(--rule)] flex items-center justify-between font-mono">
            <div>
              <span className="font-sans font-semibold text-xs text-[var(--ink)]">Total Stored Cost</span>
              {totalCostUsd && totalCostUsd !== costs.total_usd && (
                <span className="block font-sans text-[10px] text-[var(--ink-muted)]">
                  Primary confirmation: ${totalCostUsd.toFixed(4)}
                </span>
              )}
            </div>
            <span className="text-base font-bold text-[var(--ink)] bg-[var(--panel)] px-2.5 py-1 rounded-[var(--radius-sm)] border border-[var(--rule)]">
              ${costs.total_usd.toFixed(4)}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
