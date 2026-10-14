import { loadFont as loadBricolage } from "@remotion/google-fonts/BricolageGrotesque";
import { loadFont as loadIBMPlexSans } from "@remotion/google-fonts/IBMPlexSans";
import { loadFont as loadIBMPlexMono } from "@remotion/google-fonts/IBMPlexMono";
import buildData from "./generated/build-data.json";

export const { fontFamily: fontDisplay } = loadBricolage("normal", {
  weights: ["600", "700", "800"],
  ignoreTooManyRequestsWarning: true,
});
export const { fontFamily: fontSans } = loadIBMPlexSans("normal", {
  weights: ["400", "500", "600", "700"],
  ignoreTooManyRequestsWarning: true,
});
export const { fontFamily: fontMono } = loadIBMPlexMono("normal", {
  weights: ["400", "600", "700"],
  ignoreTooManyRequestsWarning: true,
});

export const TOKENS = {
  rangePaper: buildData.tokens["range-paper"],
  panel: buildData.tokens["panel"],
  ink: buildData.tokens["ink"],
  rule: buildData.tokens["rule"],
  breach: buildData.tokens["breach"],
  cleared: buildData.tokens["cleared"],
  inFlight: buildData.tokens["in-flight"],
  inFlightText: buildData.tokens["in-flight-text"],
  defended: buildData.tokens["defended"],
  inkMuted: buildData.tokens["ink-muted"],
} as const;
