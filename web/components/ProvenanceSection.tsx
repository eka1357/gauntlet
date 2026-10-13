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
  seed,
  elapsedSec,
}: ProvenanceSectionProps) {
  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5">
      <div className="mb-4">
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans">
          Audit & accounting
        </div>
        <h3 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)] mt-0.5">
          Policy cryptographic hashes and run expenditure
        </h3>
        <p className="text-xs text-[var(--ink-muted)] mt-1 font-sans">
          Exact cryptographic fingerprints for reproducible verification and Token Factory API spend accounting.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Hashes in Mono */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] space-y-3">
          <div className="text-xs font-semibold text-[var(--ink)] font-sans">
            Policy artifact checksums (SHA-256)
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-1 font-sans">
              <span>Policy v1 (Iteration 1)</span>
              <span className="font-mono text-xs">hardened_policy.yaml</span>
            </div>
            <div className="font-mono text-xs text-[var(--ink)] bg-[var(--panel)] p-2 rounded-[var(--radius-sm)] border border-[var(--rule)] break-all select-all">
              {policyHashes.v1}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-[var(--ink-muted)] mb-1 font-sans">
              <span>Policy v2 (Iteration 2)</span>
              <span className="font-mono text-xs">policy_v2.yaml</span>
            </div>
            <div className="font-mono text-xs text-[var(--ink)] bg-[var(--panel)] p-2 rounded-[var(--radius-sm)] border border-[var(--rule)] break-all select-all font-semibold">
              {policyHashes.v2}
            </div>
          </div>

          {(seed !== undefined || elapsedSec !== undefined) && (
            <div className="pt-2 border-t border-[var(--rule)] flex items-center justify-between font-mono text-xs text-[var(--ink-muted)]">
              {seed !== undefined && <span>Seed: {seed}</span>}
              {elapsedSec !== undefined && <span>Duration: {elapsedSec.toFixed(1)}s</span>}
            </div>
          )}
        </div>

        {/* Run Costs in Mono */}
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-[var(--ink)] mb-3 font-sans">
              Token Factory run expenditure breakdown
            </div>

            <div className="space-y-2 font-mono text-xs text-[var(--ink)]">
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)] text-xs">Policy v1 Evaluation Run</span>
                <span className="font-semibold text-xs">${costs.policy_v1_run_usd.toFixed(4)}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)] text-xs">Confirmation Set 2 Run (Realistic)</span>
                <span className="font-semibold text-xs">${costs.confirmation_set2_run_usd.toFixed(4)}</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[var(--rule)]">
                <span className="font-sans text-[var(--ink-muted)] text-xs">Benign Variance & Naive Set Run</span>
                <span className="font-semibold text-xs">${costs.benign_variance_naive_run_usd.toFixed(4)}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t-2 border-[var(--rule)] flex items-center justify-between">
            <div>
              <span className="font-sans font-semibold text-xs text-[var(--ink)]">
                Cost of the three recorded confirmation runs
              </span>
              <span className="block font-sans text-xs text-[var(--ink-muted)]">
                Excludes attack generation, the first verification run and development runs.
              </span>
            </div>
            <span className="font-mono text-sm font-bold text-[var(--ink)] bg-[var(--panel)] px-2.5 py-1 rounded-[var(--radius-sm)] border border-[var(--rule)] shrink-0 ml-2">
              ${costs.total_usd.toFixed(4)}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
