import React from "react";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene06Limitations({ scene, buildData }: SceneProps) {
  const limitations = buildData.display.limitations;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        padding: "70px 120px 110px 120px",
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
          paddingBottom: 24,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span
            style={{
              width: 14,
              height: 14,
              borderRadius: "50%",
              backgroundColor: TOKENS.inFlight,
              display: "inline-block",
            }}
          />
          <h1
            style={{
              fontFamily: fontDisplay,
              fontSize: 44,
              fontWeight: 700,
              color: TOKENS.ink,
              margin: 0,
              letterSpacing: "-0.02em",
            }}
          >
            {scene.onScreen ?? "What this does not show"}
          </h1>
        </div>
        <p
          style={{
            fontFamily: fontSans,
            fontSize: 20,
            color: TOKENS.inkMuted,
            marginTop: 12,
            marginBottom: 0,
            maxWidth: 1200,
            lineHeight: 1.4,
          }}
        >
          Gauntlet emphasizes verifiable evidence over hype. The following boundaries and limitations apply to this test instrument:
        </p>
      </div>

      {/* 3 Plain-Text Limitation Cards */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 24,
          margin: "auto 0",
        }}
      >
        {limitations.map((lim, idx) => (
          <div
            key={idx}
            style={{
              backgroundColor: TOKENS.panel,
              border: `1.5px solid ${TOKENS.rule}`,
              borderRadius: 8,
              padding: "24px 32px",
              display: "flex",
              alignItems: "center",
              gap: 24,
              boxShadow: "0 2px 6px rgba(19, 35, 46, 0.03)",
            }}
          >
            <span
              style={{
                fontFamily: fontMono,
                fontSize: 18,
                fontWeight: 700,
                color: TOKENS.inkMuted,
                backgroundColor: TOKENS.rangePaper,
                padding: "6px 14px",
                borderRadius: 4,
                border: `1px solid ${TOKENS.rule}`,
              }}
            >
              [{String(idx + 1).padStart(2, "0")}]
            </span>

            <span
              style={{
                fontFamily: fontSans,
                fontSize: 26,
                fontWeight: 500,
                color: TOKENS.ink,
                lineHeight: 1.35,
              }}
            >
              {lim}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
