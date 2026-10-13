"use client";

import React, { useState, useRef, useMemo, useSyncExternalStore } from "react";
import { motion } from "motion/react";
import { AttackRecord } from "@/lib/api";
import { AttackCondition, getAttackSquareState } from "@/lib/range-utils";

const SQUARE_SIZE = 13;
const GAP = 3;
const STEP = SQUARE_SIZE + GAP; // 16px
const MAX_COLS = 30;
const GRID_START_X = 125;

function subscribeToReducedMotion(callback: () => void) {
  if (typeof window === "undefined") return () => {};
  const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
  mq.addEventListener("change", callback);
  return () => mq.removeEventListener("change", callback);
}

function getReducedMotionSnapshot() {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function getReducedMotionServerSnapshot() {
  return false;
}

interface RangeGridProps {
  attacks: AttackRecord[];
  condition: AttackCondition;
  selectedAttackId: string | null;
  onSelectAttack: (attack: AttackRecord) => void;
  isWiping?: boolean;
}

interface GridItem {
  attack: AttackRecord;
  col: number;
  rowIdx: number;
  x: number;
  y: number;
  globalIndex: number;
}

interface RowDefinition {
  id: string;
  label: string;
  sublabel: string;
  isProbe: boolean;
  attacks: AttackRecord[];
}

export function RangeGrid({
  attacks,
  condition,
  selectedAttackId,
  onSelectAttack,
  isWiping = false,
}: RangeGridProps) {
  const [focusedIndex, setFocusedIndex] = useState<number>(0);
  const [hoveredItem, setHoveredItem] = useState<{
    attack: AttackRecord;
    x: number;
    y: number;
  } | null>(null);

  const prefersReducedMotion = useSyncExternalStore(
    subscribeToReducedMotion,
    getReducedMotionSnapshot,
    getReducedMotionServerSnapshot
  );
  const containerRef = useRef<HTMLDivElement>(null);

  // Group attacks into the 6 designated rows per DESIGN.md:
  // email, web page, document + 3 probe rows (partner address, URL smuggling, calendar fields)
  const rows = useMemo<RowDefinition[]>(() => {
    const emailAttacks = attacks
      .filter((a) => a.channel === "email" && !a.is_probe)
      .sort((a, b) => a.category.localeCompare(b.category));

    const webAttacks = attacks
      .filter((a) => a.channel === "web_page" && !a.is_probe)
      .sort((a, b) => a.category.localeCompare(b.category));

    const docAttacks = attacks
      .filter((a) => a.channel === "document" && !a.is_probe)
      .sort((a, b) => a.category.localeCompare(b.category));

    const partnerProbes = attacks
      .filter((a) => a.is_probe && a.category === "channel_probe_partner_address")
      .sort((a, b) => a.id.localeCompare(b.id));

    const urlProbes = attacks
      .filter((a) => a.is_probe && a.category === "channel_probe_url_smuggling")
      .sort((a, b) => a.id.localeCompare(b.id));

    const calProbes = attacks
      .filter((a) => a.is_probe && a.category === "channel_probe_calendar_fields")
      .sort((a, b) => a.id.localeCompare(b.id));

    return [
      { id: "email", label: "Email", sublabel: `${emailAttacks.length} attacks`, isProbe: false, attacks: emailAttacks },
      { id: "web_page", label: "Web page", sublabel: `${webAttacks.length} attacks`, isProbe: false, attacks: webAttacks },
      { id: "document", label: "Document", sublabel: `${docAttacks.length} attacks`, isProbe: false, attacks: docAttacks },
      { id: "probe_partner", label: "Partner address", sublabel: `${partnerProbes.length} probes`, isProbe: true, attacks: partnerProbes },
      { id: "probe_url", label: "URL smuggling", sublabel: `${urlProbes.length} probes`, isProbe: true, attacks: urlProbes },
      { id: "probe_cal", label: "Calendar fields", sublabel: `${calProbes.length} probes`, isProbe: true, attacks: calProbes },
    ];
  }, [attacks]);

  const { gridItems, rowPositions, totalHeight } = useMemo(() => {
    const items: GridItem[] = [];
    const positions: Array<{ id: string; label: string; sublabel: string; y: number; isProbe: boolean; count: number }> = [];

    let currentY = 16;
    let globalCounter = 0;

    rows.forEach((row, rIdx) => {
      // Add extra spacing before probes
      if (row.isProbe && rIdx === 3) {
        currentY += 28;
      }

      const rowStartY = currentY;
      const subRowCount = Math.max(1, Math.ceil(row.attacks.length / MAX_COLS));

      positions.push({
        id: row.id,
        label: row.label,
        sublabel: row.sublabel,
        y: rowStartY,
        isProbe: row.isProbe,
        count: row.attacks.length,
      });

      row.attacks.forEach((attack, idx) => {
        const col = idx % MAX_COLS;
        const subRow = Math.floor(idx / MAX_COLS);
        const x = GRID_START_X + col * STEP;
        const y = rowStartY + subRow * STEP;

        items.push({
          attack,
          col,
          rowIdx: rIdx,
          x,
          y,
          globalIndex: globalCounter++,
        });
      });

      currentY += subRowCount * STEP + 14;
    });

    return { gridItems: items, rowPositions: positions, totalHeight: currentY + 10 };
  }, [rows]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (gridItems.length === 0) return;

    if (e.key === "ArrowRight") {
      e.preventDefault();
      setFocusedIndex((prev) => (prev + 1) % gridItems.length);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      setFocusedIndex((prev) => (prev - 1 + gridItems.length) % gridItems.length);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((prev) => (prev + MAX_COLS < gridItems.length ? prev + MAX_COLS : prev));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((prev) => (prev - MAX_COLS >= 0 ? prev - MAX_COLS : prev));
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const item = gridItems[focusedIndex];
      if (item) {
        onSelectAttack(item.attack);
      }
    }
  };

  const svgWidth = GRID_START_X + MAX_COLS * STEP + 15; // ~620px

  return (
    <div
      ref={containerRef}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 relative outline-none focus-visible:ring-2 focus-visible:ring-[var(--ink)]"
      aria-label="The Range attack grid. Use arrow keys to navigate squares, Enter to inspect trace in drawer."
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3 pb-2 border-b border-[var(--rule)]">
        <div>
          <h2 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)]">
            The Range
          </h2>
          <p className="text-xs text-[var(--ink-muted)]">
            Telemetry grid ({attacks.length} total attack squares) grouped by channel and targeted probe vectors.
          </p>
        </div>
        <div className="text-[11px] font-mono text-[var(--ink-muted)] self-start sm:self-auto">
          Arrow keys to browse • Click or Enter to inspect trace
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="w-full overflow-x-auto relative">
        <svg
          viewBox={`0 0 ${svgWidth} ${totalHeight}`}
          className="w-full h-auto min-w-[580px] select-none"
          role="grid"
          aria-label="Attack Range grid"
        >
          {/* Row Labels & Dividers */}
          {rowPositions.map((pos, idx) => {
            const isFirstProbe = pos.isProbe && idx === 3;
            return (
              <g key={pos.id}>
                {/* Visual separator before probes with caption */}
                {isFirstProbe && (
                  <g>
                    <line
                      x1="4"
                      y1={pos.y - 20}
                      x2={svgWidth - 4}
                      y2={pos.y - 20}
                      stroke="var(--rule)"
                      strokeWidth="1"
                      strokeDasharray="2 3"
                    />
                    <text
                      x="4"
                      y={pos.y - 8}
                      fontFamily="var(--font-ibm-sans)"
                      fontSize="10"
                      fontWeight="600"
                      fill="var(--ink-muted)"
                    >
                      Channel-coverage probes (attacker provided secret in payload)
                    </text>
                  </g>
                )}

                {/* Row label */}
                <text
                  x="4"
                  y={pos.y + 10}
                  fontFamily="var(--font-ibm-sans)"
                  fontSize="11"
                  fontWeight="600"
                  fill="var(--ink)"
                >
                  {pos.label}
                </text>
                <text
                  x="4"
                  y={pos.y + 22}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="9"
                  fill="var(--ink-muted)"
                >
                  {pos.count}
                </text>
              </g>
            );
          })}

          {/* Squares */}
          {gridItems.map((item) => {
            const visualState = getAttackSquareState(item.attack, condition);
            const isSelected = selectedAttackId === item.attack.id;
            const isFocused = focusedIndex === item.globalIndex;

            // Resolve target colors
            let fillHex = "#94A3B8"; // Grey defended
            if (visualState.fillColor === "breach") {
              fillHex = "#C4352A"; // Red
            } else if (visualState.fillColor === "in-flight") {
              fillHex = "#D9962B"; // Amber
            }

            let strokeHex = "transparent";
            let strokeWidth = 0;
            if (visualState.hasTealOutline) {
              strokeHex = "#1E7A68"; // Cleared teal
              strokeWidth = 2;
            }
            if (isSelected || isFocused) {
              strokeHex = "var(--ink)";
              strokeWidth = 2.5;
            }

            // Before/after wipe left-to-right sweep calculation
            // Delay is based on column index (0..29) across 900ms total
            const colDelay = prefersReducedMotion ? 0 : (item.col / MAX_COLS) * 0.65;
            const animDuration = prefersReducedMotion ? 0 : isWiping ? 0.25 : 0.12;

            return (
              <g
                key={item.attack.id}
                role="gridcell"
                aria-label={`${item.attack.id} ${item.attack.category} ${item.attack[condition].outcome}`}
                tabIndex={-1}
                onClick={() => {
                  setFocusedIndex(item.globalIndex);
                  onSelectAttack(item.attack);
                }}
                onMouseEnter={() =>
                  setHoveredItem({
                    attack: item.attack,
                    x: item.x,
                    y: item.y,
                  })
                }
                onMouseLeave={() => setHoveredItem(null)}
                className="cursor-pointer group"
              >
                <motion.rect
                  x={item.x}
                  y={item.y}
                  width={SQUARE_SIZE}
                  height={SQUARE_SIZE}
                  rx="2"
                  initial={false}
                  animate={{
                    fill: fillHex,
                    stroke: strokeHex,
                    strokeWidth: strokeWidth,
                  }}
                  transition={{
                    delay: isWiping ? colDelay : 0,
                    duration: animDuration,
                    ease: "easeOut",
                  }}
                />
              </g>
            );
          })}
        </svg>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div
            style={{
              left: Math.min(hoveredItem.x + 18, 420),
              top: Math.max(hoveredItem.y - 10, 10),
            }}
            className="absolute z-30 pointer-events-none p-2.5 rounded-[var(--radius-sm)] bg-[var(--panel)] border border-[var(--ink)] shadow-lg text-xs max-w-xs transition-opacity"
            role="tooltip"
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="font-mono text-[10px] font-bold text-[var(--ink)]">
                {hoveredItem.attack.id}
              </span>
              <span
                className={`font-mono text-[10px] font-semibold px-1 rounded ${
                  getAttackSquareState(hoveredItem.attack, condition).isUnsafe
                    ? "bg-[var(--breach)] text-[var(--panel)]"
                    : getAttackSquareState(hoveredItem.attack, condition).isCanaryOnly
                    ? "bg-[var(--in-flight)] text-[var(--panel)]"
                    : "bg-[#94A3B8] text-[var(--panel)]"
                }`}
              >
                {hoveredItem.attack[condition].outcome.toUpperCase()}
              </span>
            </div>
            <div className="font-sans text-[11px] text-[var(--ink-muted)] mb-1">
              {hoveredItem.attack.category.replace(/_/g, " ")}
            </div>
            <div className="font-sans text-[11px] text-[var(--ink)] line-clamp-2 leading-tight">
              {hoveredItem.attack.strategy}
            </div>
            {hoveredItem.attack[condition].policy_block_rule && (
              <div className="mt-1.5 pt-1 border-t border-[var(--rule)] font-mono text-[10px] text-[var(--cleared)] truncate">
                Stopped by: {hoveredItem.attack[condition].policy_block_rule}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
