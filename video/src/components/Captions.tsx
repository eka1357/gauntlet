import React from "react";
import { useCurrentFrame } from "remotion";
import { fontSans, TOKENS } from "../theme";
import type { CaptionChunk } from "../types";

interface CaptionsProps {
  captions: CaptionChunk[];
  audioDurationFrames: number;
  totalDurationFrames: number;
}

export function Captions({ captions, audioDurationFrames, totalDurationFrames }: CaptionsProps) {
  const frame = useCurrentFrame();

  if (!captions || captions.length === 0) return null;

  // Calculate timing for each chunk based on word count
  const totalWords = captions.reduce((sum, c) => sum + Math.max(1, c.words), 0);
  
  let accumulatedFrames = 0;
  let activeCaptionIndex = 0;

  for (let i = 0; i < captions.length; i++) {
    const chunkWords = Math.max(1, captions[i].words);
    const chunkFrames = (chunkWords / totalWords) * audioDurationFrames;
    if (frame >= accumulatedFrames && (frame < accumulatedFrames + chunkFrames || i === captions.length - 1)) {
      activeCaptionIndex = i;
      break;
    }
    accumulatedFrames += chunkFrames;
  }

  const activeText = captions[activeCaptionIndex]?.text ?? "";

  return (
    <div
      style={{
        position: "absolute",
        bottom: 30,
        left: 0,
        right: 0,
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        zIndex: 50,
        pointerEvents: "none",
        padding: "0 60px",
      }}
    >
      <div
        style={{
          backgroundColor: TOKENS.ink,
          color: TOKENS.panel,
          border: `1.5px solid ${TOKENS.rule}`,
          borderRadius: 6,
          padding: "10px 26px",
          maxWidth: 1380,
          boxShadow: "0 8px 24px rgba(19, 35, 46, 0.25)",
          textAlign: "center",
        }}
      >
        <span
          style={{
            fontFamily: fontSans,
            fontSize: 24,
            fontWeight: 500,
            lineHeight: 1.3,
            letterSpacing: "-0.01em",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {activeText}
        </span>
      </div>
    </div>
  );
}
