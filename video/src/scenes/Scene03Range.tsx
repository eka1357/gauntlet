import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

const SQUARE_SIZE = 22;
const GAP = 5;
const STEP = SQUARE_SIZE + GAP;
const MAX_COLS = 30;

export function Scene03Range({ scene, buildData }: SceneProps) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const rows = buildData.range.rows;

  // Global square indexing for the fill-in animation
  let squareCounter = 0;
  const totalSquares = buildData.display.nTotal;

  // Animation spans over first 7.5 seconds to match narration pacing
  const animSpanFrames = Math.round(7.5 * fps);

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        padding: "50px 70px 100px 70px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        boxSizing: "border-box",
        position: "relative",
      }}
    >
      {/* Top Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: `2px solid ${TOKENS.rule}`,
          paddingBottom: 16,
          marginBottom: 20,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <h1
            style={{
              fontFamily: fontDisplay,
              fontSize: 32,
              fontWeight: 700,
              color: TOKENS.ink,
              margin: 0,
            }}
          >
            {scene.onScreen ?? "The Range"}
          </h1>
          <span
            style={{
              fontFamily: fontSans,
              fontSize: 15,
              fontWeight: 600,
              color: TOKENS.ink,
              backgroundColor: TOKENS.panel,
              border: `1px solid ${TOKENS.rule}`,
              borderRadius: 4,
              padding: "4px 12px",
            }}
          >
            Realistic prompt • Unhardened baseline
          </span>
        </div>

        <div style={{ fontFamily: fontMono, fontSize: 16, color: TOKENS.inkMuted }}>
          Telemetry grid ({totalSquares} total attacks) grouped by channel and probe vectors
        </div>
      </div>

      {/* Main Content: Left Grid, Right Telemetry Panel */}
      <div
        style={{
          display: "flex",
          gap: 40,
          flex: 1,
          alignItems: "flex-start",
        }}
      >
        {/* Left: The Range Grid SVG */}
        <div
          style={{
            flex: 1,
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 8,
            padding: "24px 28px",
            boxShadow: "0 2px 8px rgba(19, 35, 46, 0.04)",
          }}
        >
          <svg width="1020" height="520" viewBox="0 0 1020 520">
            {(() => {
              let currentY = 16;
              const elements: React.ReactNode[] = [];

              rows.forEach((row, rowIdx) => {
                const isFirstProbe = row.probe && rowIdx === 3;
                if (isFirstProbe) {
                  currentY += 24;
                  elements.push(
                    <g key="probe-divider">
                      <line
                        x1="0"
                        y1={currentY - 14}
                        x2="1000"
                        y2={currentY - 14}
                        stroke={TOKENS.rule}
                        strokeWidth="1.5"
                        strokeDasharray="4 4"
                      />
                      <text
                        x="0"
                        y={currentY - 2}
                        fontFamily={fontSans}
                        fontSize="13"
                        fontWeight="600"
                        fill={TOKENS.inkMuted}
                      >
                        Channel-coverage probes (attacker provided secret in payload)
                      </text>
                    </g>
                  );
                }

                const rowStartY = currentY;
                const count = row.squares.length;
                const subRowCount = Math.max(1, Math.ceil(count / MAX_COLS));

                // Row label
                elements.push(
                  <g key={`label-${row.id}`}>
                    <text
                      x="0"
                      y={rowStartY + 16}
                      fontFamily={fontSans}
                      fontSize="14"
                      fontWeight="600"
                      fill={TOKENS.ink}
                    >
                      {row.label}
                    </text>
                    <text
                      x="0"
                      y={rowStartY + 34}
                      fontFamily={fontMono}
                      fontSize="13"
                      fill={TOKENS.inkMuted}
                    >
                      {count} {row.probe ? "probes" : "attacks"}
                    </text>
                  </g>
                );

                // Squares
                row.squares.forEach((sqState, idxInRow) => {
                  const myGlobalIdx = squareCounter++;
                  const col = idxInRow % MAX_COLS;
                  const subRow = Math.floor(idxInRow / MAX_COLS);
                  const x = 160 + col * STEP;
                  const y = rowStartY + subRow * STEP;

                  // Progressive fill-in reveal
                  const revealFrame = (myGlobalIdx / 235) * animSpanFrames;
                  const isRevealed = frame >= revealFrame;
                  const opacity = isRevealed ? 1 : 0.12;

                  let fillColor = TOKENS.defended;
                  if (sqState === "unsafe") fillColor = TOKENS.breach;
                  else if (sqState === "canary") fillColor = TOKENS.inFlight;

                  elements.push(
                    <g key={`sq-${myGlobalIdx}`} opacity={opacity}>
                      <rect
                        x={x}
                        y={y}
                        width={SQUARE_SIZE}
                        height={SQUARE_SIZE}
                        rx="3"
                        fill={fillColor}
                      />
                      {/* Red slash on unsafe squares */}
                      {sqState === "unsafe" && (
                        <line
                          x1={x + 3.5}
                          y1={y + 3.5}
                          x2={x + SQUARE_SIZE - 3.5}
                          y2={y + SQUARE_SIZE - 3.5}
                          stroke={TOKENS.panel}
                          strokeWidth="2"
                          strokeLinecap="round"
                        />
                      )}
                      {/* Amber dot on canary-only leak */}
                      {sqState === "canary" && (
                        <circle
                          cx={x + SQUARE_SIZE / 2}
                          cy={y + SQUARE_SIZE / 2}
                          r="2.75"
                          fill={TOKENS.ink}
                        />
                      )}
                    </g>
                  );
                });

                currentY += subRowCount * STEP + 16;
              });

              return elements;
            })()}
          </svg>
        </div>

        {/* Right Telemetry Column */}
        <div
          style={{
            width: 480,
            display: "flex",
            flexDirection: "column",
            gap: 20,
          }}
        >
          {/* Breach rate card */}
          <div
            style={{
              backgroundColor: TOKENS.panel,
              border: `1.5px solid ${TOKENS.rule}`,
              borderRadius: 8,
              padding: "24px 28px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontFamily: fontSans, fontSize: 14, fontWeight: 600, color: TOKENS.inkMuted }}>
                Unsafe-action rate (standard attacks)
              </span>
              <span
                style={{
                  fontFamily: fontMono,
                  fontSize: 12,
                  fontWeight: 600,
                  backgroundColor: TOKENS.rangePaper,
                  padding: "2px 8px",
                  borderRadius: 3,
                  color: TOKENS.ink,
                }}
              >
                Unhardened
              </span>
            </div>

            <div
              style={{
                fontFamily: fontDisplay,
                fontSize: 68,
                fontWeight: 700,
                color: TOKENS.ink,
                lineHeight: 1.05,
                margin: "4px 0",
              }}
            >
              {buildData.display.standard.before.ratePct}%
            </div>

            <div style={{ fontFamily: fontSans, fontSize: 16, fontWeight: 600, color: TOKENS.ink }}>
              {buildData.display.standard.before.count} of {buildData.display.standard.n} standard attacks
            </div>
            <div style={{ fontFamily: fontMono, fontSize: 13, color: TOKENS.inkMuted, marginTop: 4 }}>
              95% Wilson CI: [{buildData.display.standard.before.ciLo}%, {buildData.display.standard.before.ciHi}%]
            </div>

            <div
              style={{
                marginTop: 16,
                paddingTop: 14,
                borderTop: `1px solid ${TOKENS.rule}`,
                fontFamily: fontSans,
                fontSize: 14,
                color: TOKENS.ink,
                lineHeight: 1.45,
              }}
            >
              <strong>Channel isolation:</strong> All {buildData.display.standard.before.count} unsafe actions occurred through email (49 of 150). Web pages and documents produced none (0 of 40).
            </div>
          </div>

          {/* Square Legend */}
          <div
            style={{
              backgroundColor: TOKENS.panel,
              border: `1.5px solid ${TOKENS.rule}`,
              borderRadius: 8,
              padding: "18px 24px",
            }}
          >
            <div style={{ fontFamily: fontSans, fontSize: 13, fontWeight: 700, color: TOKENS.inkMuted, marginBottom: 12, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Square Legend
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <svg width="22" height="22">
                  <rect width="22" height="22" rx="3" fill={TOKENS.breach} />
                  <line x1="3.5" y1="3.5" x2="18.5" y2="18.5" stroke={TOKENS.panel} strokeWidth="2" strokeLinecap="round" />
                </svg>
                <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
                  Red with diagonal slash: <strong>Unsafe action</strong> ({buildData.display.standard.before.count} standard)
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <svg width="22" height="22">
                  <rect width="22" height="22" rx="3" fill={TOKENS.inFlight} />
                  <circle cx="11" cy="11" r="2.75" fill={TOKENS.ink} />
                </svg>
                <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
                  Amber with center dot: <strong>Canary-only leak</strong> (9 attacks)
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <svg width="22" height="22">
                  <rect width="22" height="22" rx="3" fill={TOKENS.defended} />
                </svg>
                <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
                  Plain grey: <strong>Defended attack</strong> (176 attacks)
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
