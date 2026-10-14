import React from "react";
import { interpolate, OffthreadVideo, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { fontDisplay, fontMono, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene02Drawer({ scene, buildData }: SceneProps) {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Smooth pan upwards so the #5 send_email() tool call is fully visible above captions
  const scale = interpolate(frame, [0, durationInFrames], [1.0, 1.08], {
    extrapolateRight: "clamp",
  });
  const translateX = interpolate(frame, [0, durationInFrames], [0, -30], {
    extrapolateRight: "clamp",
  });
  const translateY = interpolate(frame, [0, durationInFrames], [0, -100], {
    extrapolateRight: "clamp",
  });

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
      {/* Video Container with slow zoom */}
      <div
        style={{
          width: "100%",
          height: "100%",
          transform: `scale(${scale}) translate(${translateX}px, ${translateY}px)`,
          transformOrigin: "center center",
        }}
      >
        <OffthreadVideo
          src={staticFile("footage/drawer_open.webm")}
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover",
          }}
        />
      </div>

      {/* Top telemetry bar overlay - kept to the left half so drawer header is never covered */}
      <div
        style={{
          position: "absolute",
          top: 28,
          left: 48,
          maxWidth: 860,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          backgroundColor: "rgba(248, 250, 251, 0.94)",
          border: `1.5px solid ${TOKENS.rule}`,
          borderRadius: 6,
          padding: "12px 20px",
          backdropFilter: "blur(4px)",
          boxShadow: "0 4px 16px rgba(19, 35, 46, 0.08)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <span
            style={{
              backgroundColor: TOKENS.breach,
              color: TOKENS.panel,
              fontFamily: fontMono,
              fontSize: 13,
              fontWeight: 700,
              padding: "3px 8px",
              borderRadius: 3,
              letterSpacing: "0.04em",
            }}
          >
            BREACH TRACE
          </span>
          <span style={{ fontFamily: fontDisplay, fontSize: 18, fontWeight: 700, color: TOKENS.ink }}>
            Attack conf2_std_email_011: Instruction Splitting via Spoofed Error
          </span>
        </div>

        <div style={{ fontFamily: fontMono, fontSize: 14, color: TOKENS.inkMuted }}>
          Destination: <span style={{ color: TOKENS.breach }}>resync@customs-edi-router.net</span> (Unallowlisted)
        </div>
      </div>
    </div>
  );
}
