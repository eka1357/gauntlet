import React from "react";
import { Audio, Series, staticFile, useVideoConfig } from "remotion";
import { Captions } from "./components/Captions";
import { Scene01Hook } from "./scenes/Scene01Hook";
import { Scene02Drawer } from "./scenes/Scene02Drawer";
import { Scene03Range } from "./scenes/Scene03Range";
import { Scene04Conditions } from "./scenes/Scene04Conditions";
import { Scene04bLive } from "./scenes/Scene04bLive";
import { Scene05Benign } from "./scenes/Scene05Benign";
import { Scene06Limitations } from "./scenes/Scene06Limitations";
import { Scene07EndCard } from "./scenes/Scene07EndCard";
import type { BuildData, SceneData } from "./types";

export interface SceneTiming {
  durationInFrames: number;
  audioDurationFrames: number;
}

export interface CompositionProps extends Record<string, unknown> {
  buildData: BuildData;
  sceneDurations?: Record<string, SceneTiming>;
  showCaptions?: boolean;
}

const SCENE_COMPONENTS: Record<string, React.ComponentType<{ scene: SceneData; buildData: BuildData }>> = {
  "01": Scene01Hook,
  "02": Scene02Drawer,
  "03": Scene03Range,
  "04": Scene04Conditions,
  "04b": Scene04bLive,
  "05": Scene05Benign,
  "06": Scene06Limitations,
  "07": Scene07EndCard,
};

export function GauntletComposition({ buildData, sceneDurations, showCaptions = false }: CompositionProps) {
  const { fps, durationInFrames } = useVideoConfig();
  const PADDING_SEC = 0.6;

  // Background music volume curve:
  // Fade in over first 1.5s, play at subtle level (0.09) so voiceover is distinct, fade out over last 2.5s
  const bgmVolume = (f: number) => {
    const fadeInFrames = 45;
    const fadeOutFrames = 75;
    const targetVol = 0.09;
    if (f < fadeInFrames) {
      return (f / fadeInFrames) * targetVol;
    }
    if (f > durationInFrames - fadeOutFrames) {
      return Math.max(0, ((durationInFrames - f) / fadeOutFrames) * targetVol);
    }
    return targetVol;
  };

  return (
    <>
      {/* Background Music */}
      {buildData.hasBgm && (
        <Audio
          src={staticFile("audio/bgm.mp3")}
          volume={bgmVolume}
        />
      )}

      <Series>
        {buildData.scenes.map((scene) => {
          const Component = SCENE_COMPONENTS[scene.id];
          if (!Component) return null;

          // Duration calculation: audio duration + 0.6s padding
          const audioSec = scene.audio.durationSec ?? scene.audio.placeholderSec ?? 10;
          const fallbackAudioFrames = Math.round(audioSec * fps);
          const fallbackDurationFrames = Math.round((audioSec + PADDING_SEC) * fps);

          const timing = sceneDurations?.[scene.id];
          const durationInFrames = timing?.durationInFrames ?? fallbackDurationFrames;
          const audioDurationFrames = timing?.audioDurationFrames ?? fallbackAudioFrames;

          return (
            <Series.Sequence key={scene.id} durationInFrames={durationInFrames}>
              {/* Visual Scene */}
              <Component scene={scene} buildData={buildData} />

              {/* Audio Track */}
              <Audio src={staticFile(scene.audio.file)} />

              {/* Optional Burned-in High-Contrast Captions (default: switched off) */}
              {showCaptions && (
                <Captions
                  captions={scene.captions}
                  audioDurationFrames={audioDurationFrames}
                  totalDurationFrames={durationInFrames}
                />
              )}
            </Series.Sequence>
          );
        })}
      </Series>
    </>
  );
}
