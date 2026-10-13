"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Logo } from "./Logo";
import { getRecordedSummary, RunCosts } from "@/lib/api";

interface AppShellProps {
  children: React.ReactNode;
}

// Only active pages are shown; non-built pages (Policy, Live, Report) are hidden
const NAV_ITEMS = [
  { label: "Workspace", href: "/" },
  { label: "Results", href: "/results" },
  { label: "Policy", href: "/policy" },
  { label: "Live", href: "/live" },
];

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const [costs, setCosts] = useState<RunCosts | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let mounted = true;
    getRecordedSummary()
      .then((data) => {
        if (!mounted) return;
        if (data.costs) {
          setCosts(data.costs);
        }
      })
      .catch(() => {
        if (mounted) setCosts(null);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const allRunsCost = costs ? `$${costs.total_usd.toFixed(2)}` : "$--.--";

  return (
    <div className="min-h-screen flex flex-col bg-[var(--range-paper)] text-[var(--ink)]">
      {/* Top Bar */}
      <header className="sticky top-0 z-40 w-full bg-[var(--panel)] border-b border-[var(--rule)]">
        <div className="flex items-center justify-between h-14 px-4 sm:px-6">
          <div className="flex items-center gap-4">
            {/* Mobile menu toggle */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-1.5 -ml-1.5 rounded-[var(--radius-sm)] text-[var(--ink)] hover:bg-[var(--range-paper)] focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileMenuOpen}
            >
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2">
                {mobileMenuOpen ? (
                  <path d="M4 4 L16 16 M16 4 L4 16" />
                ) : (
                  <path d="M3 5 H17 M3 10 H17 M3 15 H17" />
                )}
              </svg>
            </button>

            {/* Logo mark and Wordmark */}
            <Link
              href="/"
              className="flex items-center gap-2.5 focus-visible:outline-2 focus-visible:outline-[var(--ink)] rounded-[var(--radius-sm)] p-1 -m-1"
            >
              <Logo size={24} className="text-[var(--ink)] shrink-0" />
              <span className="font-display font-bold text-lg tracking-tight text-[var(--ink)]">
                Gauntlet
              </span>
            </Link>

            {/* Run Label */}
            <div className="hidden sm:inline-flex items-center gap-2 px-2.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs text-[var(--ink)] font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--cleared)]" aria-hidden="true" />
              <span>Recorded run</span>
            </div>
          </div>

          {/* Right side cost accounting */}
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="sm:hidden inline-flex items-center gap-1.5 text-xs text-[var(--ink)] font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--cleared)]" aria-hidden="true" />
              <span>Recorded</span>
            </div>

            {/* Recorded confirmation runs cost */}
            <div className="hidden md:flex flex-col text-right text-xs">
              <div className="flex items-center gap-1.5 justify-end">
                <span className="text-[var(--ink-muted)] font-sans">Cost of the three recorded confirmation runs:</span>
                <span className="font-mono font-medium text-[var(--ink)] bg-[var(--range-paper)] px-2 py-0.5 rounded-[var(--radius-sm)] border border-[var(--rule)]">
                  {allRunsCost}
                </span>
              </div>
              <div className="text-xs text-[var(--ink-muted)] font-sans">
                Excludes attack generation, the first verification run and development runs.
              </div>
            </div>
          </div>
        </div>

        {/* Mobile Navigation Dropdown */}
        {mobileMenuOpen && (
          <nav
            className="md:hidden border-t border-[var(--rule)] bg-[var(--panel)] px-4 py-3 flex flex-col gap-1"
            aria-label="Mobile Navigation"
          >
            {NAV_ITEMS.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`px-3 py-2 text-sm font-medium rounded-[var(--radius-sm)] transition-colors ${
                    active
                      ? "bg-[var(--range-paper)] text-[var(--ink)] font-semibold border-l-2 border-[var(--ink)]"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink)] hover:bg-[var(--range-paper)]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        )}
      </header>

      {/* Main Layout */}
      <div className="flex-1 flex w-full">
        {/* Desktop Left Rail Navigation */}
        <aside
          className="hidden md:flex flex-col w-52 shrink-0 border-r border-[var(--rule)] bg-[var(--panel)] py-6 px-3"
          aria-label="Sidebar Navigation"
        >
          <div className="text-xs font-semibold text-[var(--ink-muted)] px-3 mb-2 font-sans">
            Test instrumentation
          </div>
          <nav className="flex flex-col gap-1" aria-label="Main Navigation">
            {NAV_ITEMS.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center justify-between px-3 py-2 text-sm rounded-[var(--radius-sm)] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--ink)] ${
                    active
                      ? "bg-[var(--range-paper)] text-[var(--ink)] font-semibold border-l-2 border-[var(--ink)]"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink)] hover:bg-[var(--range-paper)] font-medium"
                  }`}
                >
                  <span>{item.label}</span>
                  {active && (
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--ink)]" aria-hidden="true" />
                  )}
                </Link>
              );
            })}
          </nav>

          <div className="mt-auto pt-6 px-3 border-t border-[var(--rule)]">
            <div className="text-xs text-[var(--ink-muted)] space-y-1">
              <div>Target: inbox-assistant</div>
              <div className="font-mono text-xs">policy-v2 (synthesized)</div>
            </div>
          </div>
        </aside>

        {/* Content Area */}
        <main className="flex-1 min-w-0 max-w-full overflow-x-hidden bg-[var(--range-paper)] p-4 sm:p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
