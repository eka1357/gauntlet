import React from "react";
import { OffthreadVideo, staticFile, useCurrentFrame } from "remotion";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene04bLive({ scene, buildData }: SceneProps) {
  const frame = useCurrentFrame();

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Background Video: Live Run Recording */}
      {/* trimBefore starts at frame 3460 (~115.3s) where attack #8 completes, mini-range fills in, and green completion banner flashes */}
      <OffthreadVideo
        src={staticFile("footage/live.webm")}
        trimBefore={3460}
        style={{
          width: "100%",
          height: "100%",
          objectFit: "cover",
        }}
      />

      {/* Prominent Overlay Badge: positioned in the clean top header bar */}
      <div
        style={{
          position: "absolute",
          top: 20,
          left: 280,
          display: "flex",
          alignItems: "center",
          gap: 10,
          backgroundColor: TOKENS.ink,
          color: TOKENS.panel,
          border: `1.5px solid ${TOKENS.rule}`,
          borderRadius: 6,
          padding: "8px 18px",
          boxShadow: "0 6px 20px rgba(19, 35, 46, 0.2)",
        }}
      >
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: "50%",
            backgroundColor: TOKENS.breach,
            display: "inline-block",
          }}
        />
        <span
          style={{
            fontFamily: fontDisplay,
            fontSize: 18,
            fontWeight: 700,
            letterSpacing: "-0.01em",
          }}
        >
          Live run, recorded locally
        </span>
      </div>

      {/* Telemetry Card: showing only what that run produced - placed below top header */}
      <div
        style={{
          position: "absolute",
          top: 130,
          right: 48,
          width: 440,
          backgroundColor: "rgba(248, 250, 251, 0.95)",
          border: `1.5px solid ${TOKENS.rule}`,
          borderRadius: 8,
          padding: "20px 24px",
          boxShadow: "0 8px 24px rgba(19, 35, 46, 0.12)",
          backdropFilter: "blur(6px)",
        }}
      >
        <div
          style={{
            fontFamily: fontSans,
            fontSize: 12,
            fontWeight: 700,
            color: TOKENS.inkMuted,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginBottom: 10,
          }}
        >
          Live Run Telemetry • run_74ebf1dc6093
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
              Evaluated attacks
            </span>
            <span style={{ fontFamily: fontMono, fontSize: 14, fontWeight: 700, color: TOKENS.ink }}>
              8 fresh attacks (16 runs)
            </span>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
              Unhardened unsafe
            </span>
            <span style={{ fontFamily: fontMono, fontSize: 14, fontWeight: 700, color: TOKENS.breach }}>
              4 of 8 (50.0%)
            </span>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
              Policy v2 unsafe
            </span>
            <span style={{ fontFamily: fontMono, fontSize: 14, fontWeight: 700, color: TOKENS.cleared }}>
              0 of 8 (0.0%)
            </span>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: fontSans, fontSize: 14, color: TOKENS.ink }}>
              Actual inference cost
            </span>
            <span style={{ fontFamily: fontMono, fontSize: 14, fontWeight: 700, color: TOKENS.ink }}>
              $0.0389 USD
            </span>
          </div>
        </div>

        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: `1px solid ${TOKENS.rule}`,
            fontFamily: fontSans,
            fontSize: 12,
            color: TOKENS.inkMuted,
            lineHeight: 1.4,
          }}
        >
          Fresh random email attacks • Short runs show outcome variance • The recorded run carries full evidence.
        </div>
      </div>
    </div>
  );
}
