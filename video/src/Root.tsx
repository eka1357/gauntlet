import React from "react";
import { CalculateMetadataFunction, Composition, staticFile } from "remotion";
import { getAudioDurationInSeconds } from "@remotion/media-utils";
import { CompositionProps, GauntletComposition, SceneTiming } from "./Composition";
import buildData from "./generated/build-data.json";

const FPS = 30;
const PADDING_SEC = 0.6;

export const calculateMetadata: CalculateMetadataFunction<CompositionProps> = async ({ props }) => {
  const currentBuildData = props.buildData ?? buildData;
  const sceneDurations: Record<string, SceneTiming> = {};
  let totalFrames = 0;

  for (const scene of currentBuildData.scenes) {
    let audioSec = scene.audio.durationSec ?? scene.audio.placeholderSec ?? 10;
    try {
      const detected = await getAudioDurationInSeconds(staticFile(scene.audio.file));
      if (detected && detected > 0) {
        audioSec = detected;
      }
    } catch {
      // Fallback to precomputed durationSec
    }

    const sceneSec = audioSec + PADDING_SEC;
    const durationInFrames = Math.round(sceneSec * FPS);
    const audioDurationFrames = Math.round(audioSec * FPS);

    sceneDurations[scene.id] = {
      durationInFrames,
      audioDurationFrames,
    };
    totalFrames += durationInFrames;
  }

  return {
    durationInFrames: totalFrames,
    props: {
      ...props,
      buildData: currentBuildData,
      sceneDurations,
    },
  };
};

// Initial default calculation
const defaultTotalFrames = buildData.scenes.reduce((sum, s) => {
  const sec = (s.audio.durationSec ?? s.audio.placeholderSec ?? 10) + PADDING_SEC;
  return sum + Math.round(sec * FPS);
}, 0);

export function Root() {
  return (
    <Composition<any, CompositionProps>
      id="Gauntlet"
      component={GauntletComposition}
      durationInFrames={defaultTotalFrames}
      fps={FPS}
      width={1920}
      height={1080}
      defaultProps={{
        buildData,
      }}
      calculateMetadata={calculateMetadata}
    />
  );
}
