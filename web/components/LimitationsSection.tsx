"use client";

import React from "react";

interface LimitationsSectionProps {
  limitations: string[];
}

export function LimitationsSection({ limitations }: LimitationsSectionProps) {
  return (
    <div className="bg-[var(--panel)] border-2 border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-6">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-2 h-2 rounded-full bg-[var(--in-flight)]" aria-hidden="true" />
        <h3 className="font-display font-semibold text-lg text-[var(--ink)]">
          What this does not show
        </h3>
      </div>
      <p className="text-xs text-[var(--ink-muted)] mb-4 max-w-2xl leading-relaxed">
        Gauntlet emphasizes verifiable evidence over hype. The following boundaries and limitations apply to this test instrument:
      </p>

      <ul className="grid grid-cols-1 md:grid-cols-2 gap-3" role="list">
        {limitations.map((limitation, index) => (
          <li
            key={index}
            className="flex items-start gap-2.5 p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs text-[var(--ink)]"
          >
            <span
              className="font-mono text-[11px] text-[var(--ink-muted)] font-semibold shrink-0 mt-0.5"
              aria-hidden="true"
            >
              [{String(index + 1).padStart(2, "0")}]
            </span>
            <span className="leading-relaxed font-sans">{limitation}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
