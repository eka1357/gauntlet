import React from "react";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene05Benign({ scene, buildData }: SceneProps) {
  const benign = buildData.display.benign;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        padding: "60px 100px 100px 100px",
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
          borderBottom: `2px solid ${TOKENS.rule}`,
          paddingBottom: 20,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <h1 style={{ fontFamily: fontDisplay, fontSize: 36, fontWeight: 700, color: TOKENS.ink, margin: 0 }}>
              Still does its job
            </h1>
            <span
              style={{
                fontFamily: fontSans,
                fontSize: 16,
                fontWeight: 600,
                color: TOKENS.cleared,
                backgroundColor: TOKENS.panel,
                border: `1.5px solid ${TOKENS.cleared}`,
                borderRadius: 4,
                padding: "3px 12px",
              }}
            >
              Zero Utility Regression
            </span>
          </div>

          <div style={{ fontFamily: fontMono, fontSize: 16, color: TOKENS.inkMuted }}>
            {benign.tasks} benign tasks × {benign.repeats} repeats = 105 evaluations per condition
          </div>
        </div>
      </div>

      {/* 3 Comparison Cards: Unhardened, Policy v2, Negative Control */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 32,
          margin: "auto 0",
        }}
      >
        {/* Card 1: Unhardened */}
        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 8,
            padding: "32px 32px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontFamily: fontSans, fontSize: 16, fontWeight: 700, color: TOKENS.ink }}>
                Unhardened
              </span>
              <span style={{ fontFamily: fontMono, fontSize: 13, color: TOKENS.inkMuted }}>Baseline</span>
            </div>

            <div
              style={{
                fontFamily: fontDisplay,
                fontSize: 64,
                fontWeight: 700,
                color: TOKENS.ink,
                lineHeight: 1.05,
                marginBottom: 8,
              }}
            >
              {benign.rows[0].pct}%
            </div>

            <div style={{ fontFamily: fontSans, fontSize: 18, fontWeight: 600, color: TOKENS.ink }}>
              {benign.rows[0].passed} of {benign.rows[0].total} passed
            </div>
            <div style={{ fontFamily: fontMono, fontSize: 14, color: TOKENS.inkMuted, marginTop: 4 }}>
              95% Wilson CI: [{benign.rows[0].ciLo}%, {benign.rows[0].ciHi}%]
            </div>
          </div>

          <div
            style={{
              marginTop: 24,
              paddingTop: 16,
              borderTop: `1px solid ${TOKENS.rule}`,
              fontFamily: fontSans,
              fontSize: 14,
              color: TOKENS.inkMuted,
            }}
          >
            Agent handles legitimate dispatching, shipment booking, and internal status checks without interference.
          </div>
        </div>

        {/* Card 2: Policy v2 */}
        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `2px solid ${TOKENS.cleared}`,
            borderRadius: 8,
            padding: "32px 32px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            boxShadow: "0 6px 20px rgba(24, 105, 89, 0.08)",
          }}
        >
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontFamily: fontSans, fontSize: 16, fontWeight: 700, color: TOKENS.cleared }}>
                Policy v2 (Hardened)
              </span>
              <span
                style={{
                  fontFamily: fontMono,
                  fontSize: 12,
                  fontWeight: 700,
                  backgroundColor: TOKENS.cleared,
                  color: TOKENS.panel,
                  padding: "2px 8px",
                  borderRadius: 3,
                }}
              >
                PROVEN
              </span>
            </div>

            <div
              style={{
                fontFamily: fontDisplay,
                fontSize: 64,
                fontWeight: 700,
                color: TOKENS.cleared,
                lineHeight: 1.05,
                marginBottom: 8,
              }}
            >
              {benign.rows[1].pct}%
            </div>

            <div style={{ fontFamily: fontSans, fontSize: 18, fontWeight: 600, color: TOKENS.ink }}>
              {benign.rows[1].passed} of {benign.rows[1].total} passed
            </div>
            <div style={{ fontFamily: fontMono, fontSize: 14, color: TOKENS.inkMuted, marginTop: 4 }}>
              95% Wilson CI: [{benign.rows[1].ciLo}%, {benign.rows[1].ciHi}%]
            </div>
          </div>

          <div
            style={{
              marginTop: 24,
              paddingTop: 16,
              borderTop: `1px solid ${TOKENS.rule}`,
              fontFamily: fontSans,
              fontSize: 14,
              color: TOKENS.cleared,
              fontWeight: 600,
            }}
          >
            Δ = 0.0 percentage points. The policy denies exfiltration destinations without breaking legitimate tools.
          </div>
        </div>

        {/* Card 3: Negative Control */}
        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 8,
            padding: "32px 32px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontFamily: fontSans, fontSize: 16, fontWeight: 700, color: TOKENS.ink }}>
                {benign.control.label}
              </span>
              <span
                style={{
                  fontFamily: fontMono,
                  fontSize: 12,
                  fontWeight: 600,
                  backgroundColor: TOKENS.breach,
                  color: TOKENS.panel,
                  padding: "2px 8px",
                  borderRadius: 3,
                }}
              >
                {benign.control.status.toUpperCase()}
              </span>
            </div>

            <div
              style={{
                fontFamily: fontDisplay,
                fontSize: 64,
                fontWeight: 700,
                color: TOKENS.inkMuted,
                lineHeight: 1.05,
                marginBottom: 8,
              }}
            >
              {benign.control.pct}%
            </div>

            <div style={{ fontFamily: fontSans, fontSize: 18, fontWeight: 600, color: TOKENS.ink }}>
              {benign.control.passed} of {benign.control.total} passed
            </div>
            <div style={{ fontFamily: fontMono, fontSize: 14, color: TOKENS.inkMuted, marginTop: 4 }}>
              95% Wilson CI: [{benign.control.ciLo}%, {benign.control.ciHi}%]
            </div>
          </div>

          <div
            style={{
              marginTop: 24,
              paddingTop: 16,
              borderTop: `1px solid ${TOKENS.rule}`,
              fontFamily: fontSans,
              fontSize: 14,
              color: TOKENS.inkMuted,
            }}
          >
            Negative control condition ({benign.control.condition}): proves the benign suite is capable of catching an over-defended or broken agent.
          </div>
        </div>
      </div>
    </div>
  );
}
