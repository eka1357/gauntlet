import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { Logo } from "../components/Logo";
import { fontDisplay, fontMono, fontSans, TOKENS } from "../theme";
import type { BuildData, SceneData } from "../types";

interface SceneProps {
  scene: SceneData;
  buildData: BuildData;
}

export function Scene01Hook({ scene, buildData }: SceneProps) {
  const frame = useCurrentFrame();

  const titleOpacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: "clamp" });
  const subOpacity = interpolate(frame, [15, 30], [0, 1], { extrapolateRight: "clamp" });
  const cardsOpacity = interpolate(frame, [30, 45], [0, 1], { extrapolateRight: "clamp" });

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        backgroundColor: TOKENS.rangePaper,
        padding: "50px 100px 110px 100px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        boxSizing: "border-box",
        position: "relative",
      }}
    >
      {/* Top Header Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: `2px solid ${TOKENS.rule}`,
          paddingBottom: 20,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <Logo size={40} color={TOKENS.ink} strokeWidth={3} />
          <span
            style={{
              fontFamily: fontDisplay,
              fontSize: 32,
              fontWeight: 700,
              color: TOKENS.ink,
              letterSpacing: "-0.02em",
            }}
          >
            Gauntlet
          </span>
          <span
            style={{
              fontFamily: fontSans,
              fontSize: 15,
              fontWeight: 500,
              color: TOKENS.inkMuted,
              backgroundColor: TOKENS.panel,
              border: `1px solid ${TOKENS.rule}`,
              borderRadius: 4,
              padding: "4px 12px",
            }}
          >
            Test Instrumentation
          </span>
        </div>

        <div
          style={{
            fontFamily: fontMono,
            fontSize: 15,
            color: TOKENS.inkMuted,
            display: "flex",
            gap: 28,
          }}
        >
          <span>Target: inbox-assistant</span>
          <span>Evaluation: confirmation_set2</span>
          <span>Total attacks: {buildData.display.nTotal}</span>
        </div>
      </div>

      {/* Main Center Statement */}
      <div style={{ maxWidth: 1400, marginTop: -20 }}>
        <div
          style={{
            opacity: titleOpacity,
            fontFamily: fontDisplay,
            fontSize: 58,
            fontWeight: 700,
            lineHeight: 1.15,
            color: TOKENS.ink,
            letterSpacing: "-0.03em",
            marginBottom: 24,
          }}
        >
          {scene.onScreen ?? "Your agent reads email. Some of it is written by an attacker."}
        </div>

        <div
          style={{
            opacity: subOpacity,
            fontFamily: fontSans,
            fontSize: 28,
            fontWeight: 400,
            lineHeight: 1.45,
            color: TOKENS.inkMuted,
            maxWidth: 1200,
          }}
        >
          Gauntlet attacks the target with evolving prompt injections, clusters what breaks, writes the fix as policy-as-code, and proves the fix with verified before/after runs.
        </div>
      </div>

      {/* Channel attack vectors indicator boxes */}
      <div
        style={{
          opacity: cardsOpacity,
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 24,
          marginBottom: 70,
        }}
      >
        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 6,
            padding: "18px 22px",
          }}
        >
          <div style={{ fontFamily: fontMono, fontSize: 13, color: TOKENS.breach, fontWeight: 600, marginBottom: 6 }}>
            CHANNEL 01 • PRIMARY VECTOR
          </div>
          <div style={{ fontFamily: fontDisplay, fontSize: 22, fontWeight: 600, color: TOKENS.ink, marginBottom: 4 }}>
            Inbound Email
          </div>
          <div style={{ fontFamily: fontSans, fontSize: 15, color: TOKENS.inkMuted, lineHeight: 1.4 }}>
            Spoofed EDI gateway errors, authority framing, and instruction splitting via body text.
          </div>
        </div>

        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 6,
            padding: "18px 22px",
          }}
        >
          <div style={{ fontFamily: fontMono, fontSize: 13, color: TOKENS.inkMuted, fontWeight: 600, marginBottom: 6 }}>
            CHANNEL 02 • UNTRUSTED WEB
          </div>
          <div style={{ fontFamily: fontDisplay, fontSize: 22, fontWeight: 600, color: TOKENS.ink, marginBottom: 4 }}>
            Web Pages
          </div>
          <div style={{ fontFamily: fontSans, fontSize: 15, color: TOKENS.inkMuted, lineHeight: 1.4 }}>
            External partner portals and tracking URLs fetched during automated processing.
          </div>
        </div>

        <div
          style={{
            backgroundColor: TOKENS.panel,
            border: `1.5px solid ${TOKENS.rule}`,
            borderRadius: 6,
            padding: "18px 22px",
          }}
        >
          <div style={{ fontFamily: fontMono, fontSize: 13, color: TOKENS.inkMuted, fontWeight: 600, marginBottom: 6 }}>
            CHANNEL 03 • FILE INGESTION
          </div>
          <div style={{ fontFamily: fontDisplay, fontSize: 22, fontWeight: 600, color: TOKENS.ink, marginBottom: 4 }}>
            Documents & Invoices
          </div>
          <div style={{ fontFamily: fontSans, fontSize: 15, color: TOKENS.inkMuted, lineHeight: 1.4 }}>
            Bill of lading PDFs and invoice images containing embedded instructions.
          </div>
        </div>
      </div>
    </div>
  );
}
