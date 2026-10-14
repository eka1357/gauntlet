import React from "react";
import { interpolate, OffthreadVideo, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene04Conditions({ scene, buildData }: SceneProps) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // The condition switch in conditions.webm occurs around 8.5s - 9.5s
  const switchStartFrame = Math.round(8.2 * fps);
  const switchEndFrame = Math.round(9.8 * fps);

  const std = buildData.display.standard;

  // Ticking count from 49 down to 0
  const currentCount = Math.round(
    interpolate(frame, [switchStartFrame, switchEndFrame], [std.before.countValue, std.after.countValue], {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
    })
  );

  // Ticking percentage from 25.8 down to 0.0
  const currentPct = interpolate(
    frame,
    [switchStartFrame, switchEndFrame],
    [Number(std.before.ratePct), Number(std.after.ratePct)],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
    }
  ).toFixed(1);

  const isHardened = frame >= switchEndFrame;
  const isTransitioning = frame >= switchStartFrame && frame < switchEndFrame;

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
      {/* Background Video Footage */}
      <OffthreadVideo
        src={staticFile("footage/conditions.webm")}
        style={{
          width: "100%",
          height: "100%",
          objectFit: "cover",
        }}
      />

      {/* Floating Precision Telemetry Counter Card - positioned below top nav & cost header */}
      <div
        style={{
          position: "absolute",
          top: 150,
          right: 48,
          width: 480,
          backgroundColor: "rgba(248, 250, 251, 0.96)",
          border: `2px solid ${isHardened ? TOKENS.cleared : isTransitioning ? TOKENS.inFlight : TOKENS.rule}`,
          borderRadius: 8,
          padding: "24px 28px",
          boxShadow: "0 10px 30px rgba(19, 35, 46, 0.16)",
          backdropFilter: "blur(6px)",
          transition: "border-color 0.3s ease",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <span style={{ fontFamily: fontSans, fontSize: 13, fontWeight: 700, color: TOKENS.inkMuted, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Unsafe-action Telemetry
          </span>
          <span
            style={{
              fontFamily: fontMono,
              fontSize: 13,
              fontWeight: 700,
              backgroundColor: isHardened ? TOKENS.cleared : TOKENS.ink,
              color: TOKENS.panel,
              padding: "3px 10px",
              borderRadius: 4,
            }}
          >
            {isHardened ? "POLICY V2 (HARDENED)" : isTransitioning ? "SYNTHESIZING..." : "UNHARDENED BASELINE"}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
          <div
            style={{
              fontFamily: fontDisplay,
              fontSize: 72,
              fontWeight: 700,
              color: isHardened ? TOKENS.cleared : TOKENS.breach,
              lineHeight: 1.05,
            }}
          >
            {currentPct}%
          </div>
          <div style={{ fontFamily: fontSans, fontSize: 22, fontWeight: 600, color: TOKENS.ink }}>
            {currentCount} of {std.n} unsafe
          </div>
        </div>

        <div style={{ fontFamily: fontMono, fontSize: 14, color: TOKENS.inkMuted, marginTop: 6 }}>
          {isHardened ? (
            <>
              95% upper bound: <strong>{std.after.ciHi}%</strong> (CI: [{std.after.ciLo}%, {std.after.ciHi}%])
            </>
          ) : (
            <>
              95% Wilson CI: [{std.before.ciLo}%, {std.before.ciHi}%]
            </>
          )}
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
          {isHardened ? (
            <span style={{ color: TOKENS.cleared, fontWeight: 600 }}>
              ✓ Policy v2 stopped {std.attribution.xStoppedByRule} unsafe attacks by named rules; {std.attribution.yDidNotRecur} did not recur.
            </span>
          ) : (
            <span>
              Before hardening: {std.attribution.nUnsafeUnhardened} unsafe actions under realistic prompt (all via email).
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
