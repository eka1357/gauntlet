"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Logo } from "./Logo";
import { getRecordedSummary } from "@/lib/api";

interface AppShellProps {
  children: React.ReactNode;
}

const NAV_ITEMS = [
  { label: "Workspace", href: "/workspace" },
  { label: "Results", href: "/results" },
  { label: "Policy", href: "/policy" },
  { label: "Live", href: "/live" },
  { label: "Report", href: "/report" },
];

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const [totalCost, setTotalCost] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let mounted = true;
    getRecordedSummary()
      .then((data) => {
        if (!mounted) return;
        const cost = data.costs?.total_usd ?? data.total_cost_usd;
        if (typeof cost === "number") {
          setTotalCost(`$${cost.toFixed(2)}`);
        }
      })
      .catch(() => {
        // Quiet fallback if backend is momentarily unreachable
        if (mounted) setTotalCost(null);
      });
    return () => {
      mounted = false;
    };
  }, []);

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
              href="/results"
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

          {/* Right side stats */}
          <div className="flex items-center gap-4">
            <div className="sm:hidden inline-flex items-center gap-1.5 text-xs text-[var(--ink)] font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--cleared)]" aria-hidden="true" />
              <span>Recorded</span>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-[var(--ink-muted)]">Cost</span>
              <span className="font-mono font-medium text-[var(--ink)] bg-[var(--range-paper)] px-2 py-0.5 rounded-[var(--radius-sm)] border border-[var(--rule)]">
                {totalCost ?? "$--.--"}
              </span>
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
              const active = pathname === item.href || (item.href === "/results" && pathname === "/");
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

      {/* Main Layout: Left Rail + Center Content */}
      <div className="flex-1 flex w-full">
        {/* Desktop Left Rail Navigation */}
        <aside
          className="hidden md:flex flex-col w-52 shrink-0 border-r border-[var(--rule)] bg-[var(--panel)] py-6 px-3"
          aria-label="Sidebar Navigation"
        >
          <div className="text-[11px] font-medium text-[var(--ink-muted)] px-3 mb-2 tracking-wide uppercase">
            Test Instrumentation
          </div>
          <nav className="flex flex-col gap-1" aria-label="Main Navigation">
            {NAV_ITEMS.map((item) => {
              const active = pathname === item.href || (item.href === "/results" && pathname === "/");
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
              <div className="font-mono text-[11px]">policy-v2 (synthesized)</div>
            </div>
          </div>
        </aside>

        {/* Content Area */}
        <main className="flex-1 min-w-0 bg-[var(--range-paper)] p-4 sm:p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
