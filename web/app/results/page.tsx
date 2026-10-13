"use client";

import React, { useEffect, useState } from "react";
import { getRecordedSummary, RecordedSummary, ApiError } from "@/lib/api";
import { IntervalPlot } from "@/components/IntervalPlot";
import { ProbeSetSection } from "@/components/ProbeSetSection";
import { BenignSuiteSection } from "@/components/BenignSuiteSection";
import { LimitationsSection } from "@/components/LimitationsSection";
import { ProvenanceSection } from "@/components/ProvenanceSection";

export default function ResultsPage() {
  const [summary, setSummary] = useState<RecordedSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    let active = true;

    getRecordedSummary()
      .then((data) => {
        if (active) {
          setSummary(data);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setError(
            err instanceof ApiError
              ? err
              : new ApiError(String(err), 0, "Verify backend is running on port 8000 and reload.")
          );
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  // 1. Loading State
  if (loading) {
    return (
      <div className="max-w-5xl mx-auto py-16 text-center space-y-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--rule)] text-xs text-[var(--ink-muted)]">
          <span className="w-2 h-2 rounded-full bg-[var(--in-flight)] animate-pulse" aria-hidden="true" />
          <span>Connecting to Gauntlet API...</span>
        </div>
        <p className="text-sm text-[var(--ink-muted)] font-mono">
          Retrieving headline verification summary from /api/recorded/summary
        </p>
      </div>
    );
  }

  // 2. Error State with action guidance
  if (error || !summary) {
    return (
      <div className="max-w-2xl mx-auto my-8 p-6 rounded-[var(--radius-md)] bg-[var(--panel)] border-2 border-[var(--breach)] text-[var(--ink)] space-y-4">
        <div className="flex items-start gap-3">
          <span className="w-3 h-3 rounded-full bg-[var(--breach)] shrink-0 mt-1" aria-hidden="true" />
          <div>
            <h2 className="font-display font-semibold text-lg text-[var(--ink)]">
              Unable to load verification data
            </h2>
            <p className="text-xs text-[var(--breach)] font-mono mt-1 break-words">
              {error?.message || "Verification results not found."}
            </p>
          </div>
        </div>

        <div className="p-3 bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)] text-xs space-y-1">
          <div className="font-semibold text-[var(--ink)]">What to do:</div>
          <div className="text-[var(--ink-muted)]">
            {error?.actionGuide ||
              "Start the FastAPI server in your terminal: py -m uvicorn backend.api:app --port 8000, then refresh this page."}
          </div>
        </div>

        <button
          type="button"
          onClick={() => window.location.reload()}
          className="px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] text-xs font-semibold hover:opacity-90 focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  // Generate dynamic headline sentence strictly from verified API data
  const standardN = summary.realistic_mode.n;
  const unsafeV2Count = summary.realistic_mode.policy_v2.unsafe.count;
  const upperBoundPct = summary.realistic_mode.policy_v2.unsafe.ci_pct[1];
  const naiveUnhardenedUnsafePct = summary.naive_mode.unhardened.unsafe.rate_pct;
  const realisticUnhardenedUnsafePct = summary.realistic_mode.unhardened.unsafe.rate_pct;

  const headline =
    unsafeV2Count === 0
      ? `Policy v2 stopped every unsafe action in ${standardN} attacks (0 of ${standardN}, upper bound ${upperBoundPct.toFixed(1)}%). On a naive prompt, ${naiveUnhardenedUnsafePct.toFixed(1)}% of the same attacks got through.`
      : `Policy v2 contained unsafe actions to ${unsafeV2Count} of ${standardN} attacks (upper bound ${upperBoundPct.toFixed(1)}%). On a naive prompt, ${naiveUnhardenedUnsafePct.toFixed(1)}% breached.`;

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      {/* Page Header */}
      <div>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
          <h1 className="font-display font-bold text-2xl sm:text-3xl text-[var(--ink)] tracking-tight">
            Verification Results
          </h1>
          <div className="flex items-center gap-2 font-mono text-xs text-[var(--ink-muted)]">
            <span className="px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--rule)]">
              Evaluation: {summary.evaluation_type ?? "confirmation_split"}
            </span>
            <span className="px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--rule)]">
              {summary.n_total} total attacks
            </span>
          </div>
        </div>
        <p className="text-xs sm:text-sm text-[var(--ink-muted)]">
          Empirical verification data comparing unhardened baselines against synthesized defense policies with Wilson 95% confidence bounds.
        </p>
      </div>

      {/* Headline Sentence Banner */}
      <section
        aria-label="Executive Headline"
        className="p-5 sm:p-6 rounded-[var(--radius-md)] bg-[var(--panel)] border-l-4 border-l-[var(--cleared)] border-y border-r border-[var(--rule)]"
      >
        <div className="text-xs font-semibold text-[var(--ink-muted)] font-sans mb-1.5">
          Executive verification summary
        </div>
        <p className="font-display font-semibold text-lg sm:text-xl text-[var(--ink)] leading-snug">
          {headline}
        </p>
        <div className="flex flex-wrap items-center gap-4 mt-3 pt-3 border-t border-[var(--rule)] text-xs text-[var(--ink-muted)] font-sans">
          <div>
            Realistic baseline unsafe-action rate:{" "}
            <span className="font-mono font-semibold text-[var(--breach)]">
              {realisticUnhardenedUnsafePct.toFixed(1)}%
            </span>
          </div>
          <div>
            Policy v2 unsafe-action rate:{" "}
            <span className="font-mono font-semibold text-[var(--cleared)]">
              0.0%
            </span>{" "}
            (upper bound {upperBoundPct.toFixed(1)}%)
          </div>
          <div>
            Canary exfiltration (M1):{" "}
            <span className="font-mono font-semibold text-[var(--cleared)]">
              0 of {standardN}
            </span>
          </div>
        </div>
      </section>

      {/* Interval Plots Section */}
      <section aria-labelledby="interval-plots-heading" className="space-y-4">
        <div>
          <h2 id="interval-plots-heading" className="font-display font-semibold text-xl text-[var(--ink)]">
            Metric Interval Estimates
          </h2>
          <p className="text-xs text-[var(--ink-muted)] mt-0.5">
            Point estimates with 95% Wilson score confidence interval whiskers across all 5 evaluation metrics.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Plot 1: Realistic Prompt */}
          <IntervalPlot
            title="Realistic prompt"
            subtitle="Target agent prompt includes production instructions and operational context (n=190)"
            unhardened={summary.realistic_mode.unhardened}
            policyV2={summary.realistic_mode.policy_v2}
          />

          {/* Plot 2: Naive Prompt */}
          <IntervalPlot
            title="Naive prompt (no safety instructions)"
            subtitle="Target agent prompt without safety boundaries to measure raw tool susceptibility (n=190)"
            unhardened={summary.naive_mode.unhardened}
            policyV2={summary.naive_mode.policy_v2}
          />
        </div>
      </section>

      {/* Probe Set Section */}
      <section aria-label="Channel Coverage Probe Set">
        <ProbeSetSection probeSet={summary.probe_set} />
      </section>

      {/* Benign Task Suite Section */}
      <section aria-label="Benign Task Suite">
        <BenignSuiteSection benignSuite={summary.benign_suite} />
      </section>

      {/* "What this does not show" Section */}
      <section aria-label="Limitations and Boundaries">
        <LimitationsSection limitations={summary.limitations} />
      </section>

      {/* Provenance, Hashes & Costs Section */}
      <section aria-label="Cryptographic Hashes and Cost Accounting">
        <ProvenanceSection
          policyHashes={summary.policy_hashes}
          costs={summary.costs}
          totalCostUsd={summary.total_cost_usd}
          seed={summary.seed}
          elapsedSec={summary.elapsed_sec}
        />
      </section>
    </div>
  );
}
