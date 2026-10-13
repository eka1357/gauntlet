"use client";

import React from "react";
import { AttackCondition } from "@/lib/range-utils";

interface RangeFiltersProps {
  condition: AttackCondition;
  onConditionChange: (next: AttackCondition) => void;
  channelFilter: string;
  onChannelFilterChange: (ch: string) => void;
  categoryFilter: string;
  onCategoryFilterChange: (cat: string) => void;
  onlyUnsafeUnhardened: boolean;
  onOnlyUnsafeUnhardenedChange: (val: boolean) => void;
  availableCategories: string[];
}

export function RangeFilters({
  condition,
  onConditionChange,
  channelFilter,
  onChannelFilterChange,
  categoryFilter,
  onCategoryFilterChange,
  onlyUnsafeUnhardened,
  onOnlyUnsafeUnhardenedChange,
  availableCategories,
}: RangeFiltersProps) {
  return (
    <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-3 sm:p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
      {/* 3-State Condition Switch */}
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold text-[var(--ink-muted)] font-sans hidden sm:inline">
          Condition:
        </span>
        <div
          role="group"
          aria-label="Target Condition Switch"
          className="inline-flex p-1 bg-[var(--range-paper)] rounded-[var(--radius-sm)] border border-[var(--rule)] text-xs"
        >
          <button
            type="button"
            onClick={() => onConditionChange("unhardened")}
            className={`px-3 py-1.5 font-medium rounded-[var(--radius-sm)] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--ink)] ${
              condition === "unhardened"
                ? "bg-[var(--ink)] text-[var(--panel)] font-semibold shadow-xs"
                : "text-[var(--ink-muted)] hover:text-[var(--ink)]"
            }`}
          >
            Unhardened
          </button>
          <button
            type="button"
            onClick={() => onConditionChange("v1")}
            className={`px-3 py-1.5 font-medium rounded-[var(--radius-sm)] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--ink)] ${
              condition === "v1"
                ? "bg-[var(--ink)] text-[var(--panel)] font-semibold shadow-xs"
                : "text-[var(--ink-muted)] hover:text-[var(--ink)]"
            }`}
          >
            Policy v1
          </button>
          <button
            type="button"
            onClick={() => onConditionChange("v2")}
            className={`px-3 py-1.5 font-medium rounded-[var(--radius-sm)] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--ink)] ${
              condition === "v2"
                ? "bg-[var(--cleared)] text-[var(--panel)] font-semibold shadow-xs"
                : "text-[var(--ink-muted)] hover:text-[var(--ink)]"
            }`}
          >
            Policy v2
          </button>
        </div>
      </div>

      {/* Filter controls */}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        {/* Channel select */}
        <div className="flex items-center gap-1.5">
          <label htmlFor="channel-select" className="text-[var(--ink-muted)] font-medium">
            Channel:
          </label>
          <select
            id="channel-select"
            value={channelFilter}
            onChange={(e) => onChannelFilterChange(e.target.value)}
            className="px-2 py-1 bg-[var(--range-paper)] border border-[var(--rule)] rounded-[var(--radius-sm)] text-[var(--ink)] font-sans focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
          >
            <option value="all">All channels</option>
            <option value="email">Email</option>
            <option value="web_page">Web page</option>
            <option value="document">Document</option>
            <option value="probes">Probes only</option>
          </select>
        </div>

        {/* Category select */}
        <div className="flex items-center gap-1.5">
          <label htmlFor="category-select" className="text-[var(--ink-muted)] font-medium">
            Category:
          </label>
          <select
            id="category-select"
            value={categoryFilter}
            onChange={(e) => onCategoryFilterChange(e.target.value)}
            className="px-2 py-1 bg-[var(--range-paper)] border border-[var(--rule)] rounded-[var(--radius-sm)] text-[var(--ink)] font-sans max-w-[160px] truncate focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
          >
            <option value="all">All categories</option>
            {availableCategories.map((cat) => (
              <option key={cat} value={cat}>
                {cat.replace(/^channel_probe_/, "probe: ").replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>

        {/* Checkbox: only attacks unsafe when unhardened */}
        <label className="flex items-center gap-2 cursor-pointer select-none text-[var(--ink)] font-medium py-1">
          <input
            type="checkbox"
            checked={onlyUnsafeUnhardened}
            onChange={(e) => onOnlyUnsafeUnhardenedChange(e.target.checked)}
            className="rounded-[var(--radius-sm)] border-[var(--rule)] text-[var(--ink)] focus:ring-[var(--ink)]"
          />
          <span>Only unsafe when unhardened</span>
        </label>
      </div>
    </div>
  );
}
