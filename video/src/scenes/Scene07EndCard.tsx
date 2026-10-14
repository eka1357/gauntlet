import React from "react";
import { Logo } from "../components/Logo";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene07EndCard({ scene, buildData }: SceneProps) {
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        padding: "80px 120px 110px 120px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        alignItems: "center",
        boxSizing: "border-box",
        position: "relative",
      }}
    >
      {/* Top Tagline */}
      <div
        style={{
          fontFamily: fontMono,
          fontSize: 16,
          fontWeight: 600,
          color: TOKENS.inkMuted,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
        }}
      >
        Nebius × NVIDIA Global AI Hackathon • Test Instrument
      </div>

      {/* Main Center Callout */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
          maxWidth: 960,
        }}
      >
        {/* Gate Logo */}
        <div style={{ marginBottom: 24 }}>
          <Logo size={104} color={TOKENS.ink} strokeWidth={3} />
        </div>

        {/* Project Title */}
        <h1
          style={{
            fontFamily: fontDisplay,
            fontSize: 76,
            fontWeight: 800,
            color: TOKENS.ink,
            letterSpacing: "-0.03em",
            margin: "0 0 16px 0",
            lineHeight: 1,
          }}
        >
          Gauntlet
        </h1>

        <p
          style={{
            fontFamily: fontSans,
            fontSize: 30,
            fontWeight: 400,
            color: TOKENS.inkMuted,
            margin: "0 0 40px 0",
            lineHeight: 1.3,
          }}
        >
          Hardens AI agents before they ship.
        </p>

        {/* Links and MIT Badge */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 20,
          }}
        >
          {/* Repo Link */}
          <div
            style={{
              backgroundColor: TOKENS.ink,
              color: TOKENS.panel,
              fontFamily: fontMono,
              fontSize: 22,
              fontWeight: 600,
              padding: "14px 32px",
              borderRadius: 6,
              boxShadow: "0 4px 16px rgba(19, 35, 46, 0.15)",
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <span>{buildData.repoLink}</span>
          </div>

          {/* License Badge */}
          <div
            style={{
              backgroundColor: TOKENS.panel,
              color: TOKENS.ink,
              border: `2px solid ${TOKENS.rule}`,
              fontFamily: fontMono,
              fontSize: 22,
              fontWeight: 700,
              padding: "14px 28px",
              borderRadius: 6,
            }}
          >
            {buildData.license} License
          </div>
        </div>
      </div>

      {/* Bottom Footer Details */}
      <div
        style={{
          fontFamily: fontSans,
          fontSize: 16,
          color: TOKENS.inkMuted,
          textAlign: "center",
        }}
      >
        Deterministic oracle • Policy-as-code defense • Recorded, inspectable traces
      </div>
    </div>
  );
}
