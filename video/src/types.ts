import buildData from "./generated/build-data.json";

export type BuildData = typeof buildData;
export type SceneData = BuildData["scenes"][number];
export type CaptionChunk = SceneData["captions"][number];

export interface VideoProps {
  buildData: BuildData;
}
