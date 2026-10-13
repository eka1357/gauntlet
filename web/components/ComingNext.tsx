import React from "react";
import Link from "next/link";

interface ComingNextProps {
  pageName: string;
  description: string;
}

export function ComingNext({ pageName, description }: ComingNextProps) {
  return (
    <div className="max-w-2xl mx-auto py-12 sm:py-20 text-center">
      <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--rule)] text-xs font-mono text-[var(--ink-muted)] mb-4">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--in-flight)]" aria-hidden="true" />
        <span>Coming next</span>
      </div>

      <h1 className="font-display font-bold text-2xl sm:text-3xl text-[var(--ink)] mb-3">
        {pageName}
      </h1>

      <p className="text-sm text-[var(--ink-muted)] leading-relaxed mb-6 max-w-lg mx-auto">
        {description}
      </p>

      <div className="flex items-center justify-center gap-3">
        <Link
          href="/results"
          className="inline-flex items-center justify-center px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] text-xs font-semibold hover:opacity-90 transition-opacity focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ink)]"
        >
          View Verification Results
        </Link>
      </div>
    </div>
  );
}
