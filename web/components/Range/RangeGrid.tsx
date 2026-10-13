"use client";

import React, { useState, useRef, useMemo, useEffect, useSyncExternalStore } from "react";
import Link from "next/link";
import { motion } from "motion/react";
import { AttackRecord } from "@/lib/api";
import { AttackCondition, getAttackSquareState } from "@/lib/range-utils";

const GAP = 3;
const MAX_COLS = 30;
const GRID_START_X = 136;

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
  // Do not auto-focus or pre-select on load; focus rings appear only on keyboard use
  const [focusedIndex, setFocusedIndex] = useState<number | null>(null);
  const [isKeyboardFocus, setIsKeyboardFocus] = useState<boolean>(false);
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

  // Responsive container width measurement to dynamically scale squares up to 18px
  const [containerWidth, setContainerWidth] = useState<number>(760);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      const w = el.clientWidth;
      if (w > 0) setContainerWidth(w);
    };
    update();
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 0) {
          setContainerWidth(entry.contentRect.width);
        }
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Compute square size: up to 18px with 3px gaps, filling panel width without breaking mobile (390px)
  const { squareSize, step, svgWidth } = useMemo(() => {
    const availWidth = Math.max(containerWidth - 40 - GRID_START_X - 16, 0);
    const colStep = Math.floor(availWidth / MAX_COLS);
    const size = Math.min(18, Math.max(13, colStep - GAP));
    const computedStep = size + GAP;
    const computedSvgWidth = GRID_START_X + MAX_COLS * computedStep + 16;
    return {
      squareSize: size,
      step: computedStep,
      svgWidth: computedSvgWidth,
    };
  }, [containerWidth]);

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
      {
        id: "email",
        label: "Email body",
        sublabel: `${emailAttacks.length} attacks`,
        isProbe: false,
        attacks: emailAttacks,
      },
      {
        id: "web_page",
        label: "Web page",
        sublabel: `${webAttacks.length} attacks`,
        isProbe: false,
        attacks: webAttacks,
      },
      {
        id: "document",
        label: "Document",
        sublabel: `${docAttacks.length} attacks`,
        isProbe: false,
        attacks: docAttacks,
      },
      {
        id: "probe_partner",
        label: "Partner probe",
        sublabel: `${partnerProbes.length} probes`,
        isProbe: true,
        attacks: partnerProbes,
      },
      {
        id: "probe_url",
        label: "URL probe",
        sublabel: `${urlProbes.length} probes`,
        isProbe: true,
        attacks: urlProbes,
      },
      {
        id: "probe_cal",
        label: "Calendar probe",
        sublabel: `${calProbes.length} probes`,
        isProbe: true,
        attacks: calProbes,
      },
    ];
  }, [attacks]);

  // Compute 2D layout coordinates for all squares with dynamic step
  const { gridItems, rowPositions, totalHeight } = useMemo(() => {
    const items: GridItem[] = [];
    const positions: Array<{ id: string; label: string; count: string; y: number; isProbe: boolean }> = [];
    let currentY = 16;
    let globalCounter = 0;

    rows.forEach((row, rowIdx) => {
      const isFirstProbe = row.isProbe && rowIdx === 3;
      if (isFirstProbe) {
        currentY += 28; // Distinct visual spacing before probes
      }

      const rowStartY = currentY;
      positions.push({
        id: row.id,
        label: row.label,
        count: row.sublabel,
        y: rowStartY,
        isProbe: row.isProbe,
      });

      const count = row.attacks.length;
      const subRowCount = Math.max(1, Math.ceil(count / MAX_COLS));

      row.attacks.forEach((attack, idxInRow) => {
        const col = idxInRow % MAX_COLS;
        const subRow = Math.floor(idxInRow / MAX_COLS);
        const x = GRID_START_X + col * step;
        const y = rowStartY + subRow * step;

        items.push({
          attack,
          col,
          rowIdx,
          x,
          y,
          globalIndex: globalCounter++,
        });
      });

      currentY += subRowCount * step + 18;
    });

    return { gridItems: items, rowPositions: positions, totalHeight: currentY + 12 };
  }, [rows, step]);

  // Keyboard navigation on squares with roving tabindex
  const handleSquareKeyDown = (e: React.KeyboardEvent, item: GridItem) => {
    let nextIndex: number | null = null;
    if (e.key === "ArrowRight") {
      e.preventDefault();
      nextIndex = (item.globalIndex + 1) % gridItems.length;
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      nextIndex = (item.globalIndex - 1 + gridItems.length) % gridItems.length;
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      nextIndex = Math.min(item.globalIndex + MAX_COLS, gridItems.length - 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      nextIndex = Math.max(item.globalIndex - MAX_COLS, 0);
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelectAttack(item.attack);
      return;
    }

    if (nextIndex !== null) {
      setFocusedIndex(nextIndex);
      setIsKeyboardFocus(true);
      const nextAttackId = gridItems[nextIndex]?.attack.id;
      if (nextAttackId) {
        requestAnimationFrame(() => {
          const targetEl = document.querySelector(`[data-range-square="${nextAttackId}"]`) as HTMLElement | null;
          targetEl?.focus();
        });
      }
    }
  };

  return (
    <div
      ref={containerRef}
      className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 relative outline-none"
      aria-label="The Range attack grid"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3 pb-2 border-b border-[var(--rule)]">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <h1 className="font-display font-semibold text-base sm:text-lg text-[var(--ink)]">
              The Range
            </h1>
            <span className="font-sans text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)] font-medium">
              Realistic prompt (safety instructions in the system prompt)
            </span>
          </div>
          <p className="text-xs text-[var(--ink-muted)] font-sans">
            Telemetry grid ({attacks.length} total attack squares) grouped by channel and targeted probe vectors. Naive-prompt results are on the{" "}
            <Link href="/results" prefetch={false} className="underline hover:text-[var(--ink)]">
              Results page
            </Link>.
          </p>
        </div>
        <div className="text-xs font-sans text-[var(--ink-muted)] self-start sm:self-auto">
          Use arrow keys to browse, click or Enter to inspect trace
        </div>
      </div>

      {/* SVG Canvas - scrollable horizontally on mobile (390px) without breaking page width */}
      <div
        tabIndex={0}
        role="region"
        aria-label="Interactive attack grid container"
        className="w-full overflow-x-auto relative focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
      >
        <svg
          viewBox={`0 0 ${svgWidth} ${totalHeight}`}
          style={{ width: `${svgWidth}px`, maxWidth: "none" }}
          className="h-auto select-none"
          role="region"
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
                      fontSize="12"
                      fontWeight="600"
                      fill="var(--ink-muted)"
                    >
                      Channel-coverage probes (attacker provided secret in payload)
                    </text>
                  </g>
                )}

                {/* Row label (minimum 12px) */}
                <text
                  x="4"
                  y={pos.y + 11}
                  fontFamily="var(--font-ibm-sans)"
                  fontSize="12"
                  fontWeight="600"
                  fill="var(--ink)"
                >
                  {pos.label}
                </text>
                <text
                  x="4"
                  y={pos.y + 25}
                  fontFamily="var(--font-ibm-mono)"
                  fontSize="12"
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
            const isFocusedWithKeyboard = isKeyboardFocus && focusedIndex === item.globalIndex;

            // Resolve target colors using CSS tokens (no raw hex)
            let fillHex = "var(--defended)"; // Grey defended
            if (visualState.fillColor === "breach") {
              fillHex = "var(--breach)"; // Red
            } else if (visualState.fillColor === "in-flight") {
              fillHex = "var(--in-flight)"; // Amber
            }

            let strokeHex = "rgba(0, 0, 0, 0)";
            let strokeWidth = 0;
            if (visualState.hasTealOutline) {
              strokeHex = "var(--cleared)"; // Cleared teal
              strokeWidth = 2;
            }
            if (isSelected || isFocusedWithKeyboard) {
              strokeHex = "var(--ink)";
              strokeWidth = 2.5;
            }

            // Before/after wipe left-to-right sweep calculation
            const colDelay = prefersReducedMotion ? 0 : (item.col / MAX_COLS) * 0.65;
            const animDuration = prefersReducedMotion ? 0 : isWiping ? 0.25 : 0.12;

            return (
              <g
                key={item.attack.id}
                role="button"
                data-range-square={item.attack.id}
                aria-label={`${item.attack.id} ${item.attack.category.replace(/_/g, " ")}: ${visualState.status}`}
                tabIndex={focusedIndex === item.globalIndex || (focusedIndex === null && item.globalIndex === 0) ? 0 : -1}
                onClick={() => {
                  setIsKeyboardFocus(false);
                  setFocusedIndex(item.globalIndex);
                  onSelectAttack(item.attack);
                }}
                onKeyDown={(e) => handleSquareKeyDown(e, item)}
                onFocus={() => {
                  setFocusedIndex(item.globalIndex);
                  setIsKeyboardFocus(true);
                }}
                onMouseEnter={() =>
                  setHoveredItem({
                    attack: item.attack,
                    x: item.x,
                    y: item.y,
                  })
                }
                onMouseLeave={() => setHoveredItem(null)}
                className="cursor-pointer group outline-none"
              >
                <motion.rect
                  x={item.x}
                  y={item.y}
                  width={squareSize}
                  height={squareSize}
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

                {/* Colour independence: unsafe squares get a diagonal slash */}
                {visualState.isUnsafe && (
                  <motion.line
                    x1={item.x + 2.5}
                    y1={item.y + 2.5}
                    x2={item.x + squareSize - 2.5}
                    y2={item.y + squareSize - 2.5}
                    stroke="var(--panel)"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    initial={false}
                    animate={{ opacity: 1 }}
                    transition={{
                      delay: isWiping ? colDelay : 0,
                      duration: animDuration,
                    }}
                  />
                )}

                {/* Colour independence: amber canary-only leaks get a center dot */}
                {visualState.isCanaryOnly && (
                  <motion.circle
                    cx={item.x + squareSize / 2}
                    cy={item.y + squareSize / 2}
                    r="2.2"
                    fill="var(--ink)"
                    initial={false}
                    animate={{ opacity: 1 }}
                    transition={{
                      delay: isWiping ? colDelay : 0,
                      duration: animDuration,
                    }}
                  />
                )}
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip */}
        {hoveredItem && (
          <div
            className="absolute z-30 pointer-events-none bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-sm)] shadow-xl p-2.5 max-w-xs transition-opacity duration-100"
            style={{
              left: `${Math.min(hoveredItem.x + 15, Math.max(svgWidth - 260, 20))}px`,
              top: `${Math.max(hoveredItem.y - 45, 10)}px`,
            }}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="font-mono text-xs font-bold text-[var(--ink)]">
                {hoveredItem.attack.id}
              </span>
              <span
                className={`font-sans text-xs font-semibold px-1.5 py-0.5 rounded ${
                  getAttackSquareState(hoveredItem.attack, condition).isUnsafe
                    ? "bg-[var(--breach)] text-[var(--panel)]"
                    : getAttackSquareState(hoveredItem.attack, condition).isCanaryOnly
                    ? "bg-[var(--in-flight)] text-[var(--ink)]"
                    : "bg-[var(--range-paper)] text-[var(--ink)] border border-[var(--rule)]"
                }`}
              >
                {getAttackSquareState(hoveredItem.attack, condition).status}
              </span>
            </div>
            <div className="font-sans text-xs text-[var(--ink-muted)] mb-1">
              {hoveredItem.attack.category.replace(/_/g, " ")}
            </div>
            <div className="font-sans text-xs text-[var(--ink)] line-clamp-2 leading-tight">
              {hoveredItem.attack.strategy}
            </div>
            {hoveredItem.attack[condition].policy_block_rule && (
              <div className="mt-1.5 pt-1 border-t border-[var(--rule)] font-mono text-xs text-[var(--cleared)] truncate">
                Rule: {hoveredItem.attack[condition].policy_block_rule}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
