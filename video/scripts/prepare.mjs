// Build-time data step for the Gauntlet video.
//
// Reads the stored run (web/public/data/summary.json + attacks.json), the design
// tokens (web/styles/tokens.css) and the script (video/script.md), validates every
// field the video needs, and writes src/generated/build-data.json. Any missing
// field, mismatch or rounding problem exits non-zero so the render never starts.
//
// It also stages footage and audio into video/public. Missing narration files get
// a silent WAV placeholder sized at 140 words per minute of that scene's narration.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VIDEO_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO = path.resolve(VIDEO_DIR, "..");
const DATA_DIR = path.join(REPO, "web", "public", "data");
const PUBLIC_DIR = path.join(VIDEO_DIR, "public");
const GEN_DIR = path.join(VIDEO_DIR, "src", "generated");

const SCENE_IDS = ["01", "02", "03", "04", "04b", "05", "06", "07"];
const WORDS_PER_MINUTE = 140;
const MAX_CAPTION_CHARS = 96;
const FOOTAGE = ["drawer_open.webm", "conditions.webm", "live.webm"];
const REQUIRED_TOKENS = [
  "range-paper",
  "panel",
  "ink",
  "rule",
  "breach",
  "cleared",
  "in-flight",
  "in-flight-text",
  "defended",
  "ink-muted",
];

const errors = [];

/** Record a fatal problem; all problems are printed together before exiting. */
function fail(msg) {
  errors.push(msg);
}

/** Read a dotted path (e.g. "a.b.0.c") from an object; records an error if missing. */
function get(obj, dotted) {
  let cur = obj;
  for (const key of dotted.split(".")) {
    if (cur === null || cur === undefined || !(key in Object(cur))) {
      fail(`summary.json is missing required field: ${dotted}`);
      return undefined;
    }
    cur = cur[key];
  }
  if (cur === null || cur === undefined) {
    fail(`summary.json field is null: ${dotted}`);
  }
  return cur;
}

/** Format an integer count exactly as stored. */
function int(v, label) {
  if (!Number.isInteger(v)) {
    fail(`${label} should be an integer, got ${JSON.stringify(v)}`);
    return "?";
  }
  return String(v);
}

/**
 * Format a stored one-decimal percentage with exactly one decimal place.
 * Fails if the stored value has more precision (that would be rounding).
 */
function pct(v, label) {
  if (typeof v !== "number" || !Number.isFinite(v)) {
    fail(`${label} should be a number, got ${JSON.stringify(v)}`);
    return "?";
  }
  if (Math.abs(v * 10 - Math.round(v * 10)) > 1e-9) {
    fail(`${label} = ${v} has more than one decimal; refusing to round it`);
    return "?";
  }
  return v.toFixed(1);
}

function readJson(p) {
  if (!fs.existsSync(p)) {
    fail(`missing file: ${path.relative(REPO, p)}`);
    return null;
  }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

// ---------------------------------------------------------------- tokens
function readTokens() {
  const css = fs.readFileSync(path.join(REPO, "web", "styles", "tokens.css"), "utf8");
  // First :root block only (the light theme). The dark block sits inside @media.
  const m = css.match(/:root\s*\{([\s\S]*?)\}/);
  if (!m) {
    fail("tokens.css has no :root block");
    return {};
  }
  const tokens = {};
  for (const [, name, value] of m[1].matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
    tokens[name] = value;
  }
  for (const t of REQUIRED_TOKENS) {
    if (!tokens[t]) fail(`tokens.css :root is missing --${t}`);
  }
  return tokens;
}

// ---------------------------------------------------------------- script
function parseScript(summary) {
  const raw = fs.readFileSync(path.join(VIDEO_DIR, "script.md"), "utf8").replace(/\r\n/g, "\n");
  const sections = {};
  const parts = raw.split(/^## /m).slice(1);
  for (const part of parts) {
    const [heading, ...rest] = part.split("\n");
    const id = heading.trim().split(/\s+/)[0];
    const title = heading.trim().slice(id.length).trim();
    const body = rest.join("\n");
    const field = (name) => {
      const re = new RegExp(`^${name}:\\s*([\\s\\S]*?)(?=\\n\\s*\\n|\\n[A-Z][a-z ]+:|$)`, "m");
      const fm = body.match(re);
      return fm ? fm[1].replace(/\s+/g, " ").trim() : null;
    };
    sections[id] = { id, title, onScreen: field("On screen"), narration: field("Narration") };
  }
  const resolve = (text, sceneId) =>
    text?.replace(/\{\{\s*([^}|]+?)\s*(?:\|\s*(\w+))?\s*\}\}/g, (_, p, filter) => {
      const v = get(summary, p);
      if (v === undefined) return "?";
      if (filter === "pct") return pct(v, p);
      if (filter) fail(`script.md scene ${sceneId}: unknown filter |${filter}`);
      if (typeof v === "number") return Number.isInteger(v) ? String(v) : pct(v, p);
      return String(v);
    }) ?? null;
  for (const id of SCENE_IDS) {
    const s = sections[id];
    if (!s) {
      fail(`script.md has no section "## ${id}"`);
      continue;
    }
    if (!s.narration) fail(`script.md section ${id} has no Narration:`);
    s.narration = resolve(s.narration, id);
    s.onScreen = resolve(s.onScreen, id);
  }
  return sections;
}

/** Split narration into caption chunks of at most MAX_CAPTION_CHARS (two lines). */
function chunkCaption(text) {
  const sentences = text.split(/(?<=[.!?])\s+/).filter(Boolean);
  const splitLong = (s) => {
    if (s.length <= MAX_CAPTION_CHARS) return [s];
    const mid = s.length / 2;
    const candidates = [];
    for (const m of s.matchAll(/[,;:] /g)) candidates.push(m.index + 1);
    if (candidates.length === 0) for (const m of s.matchAll(/ /g)) candidates.push(m.index);
    candidates.sort((a, b) => Math.abs(a - mid) - Math.abs(b - mid));
    const cut = candidates[0];
    return [...splitLong(s.slice(0, cut).trim()), ...splitLong(s.slice(cut).trim())];
  };
  const pieces = sentences.flatMap(splitLong);
  const merged = [];
  for (const p of pieces) {
    const last = merged[merged.length - 1];
    if (last && last.length + 1 + p.length <= MAX_CAPTION_CHARS) merged[merged.length - 1] = `${last} ${p}`;
    else merged.push(p);
  }
  return merged.map((t) => ({ text: t, words: t.split(/\s+/).length }));
}

// ---------------------------------------------------------------- range
function unhardenedState(a) {
  const c = a.unhardened ?? {};
  const m = c.metrics ?? {};
  if (c.unsafe || c.m1 || c.m2 || c.m3 || m.unsafe || m.m1 || m.m2 || m.m3) return "unsafe";
  if (c.m4 || m.m4) return "canary";
  return "defended";
}

function isUnsafeCondition(condData) {
  const c = condData ?? {};
  const m = c.metrics ?? {};
  return Boolean(c.unsafe || c.m1 || c.m2 || c.m3 || m.unsafe || m.m1 || m.m2 || m.m3);
}

function computeHardeningAttribution(attacks, condition = "v2") {
  const std = attacks.filter((a) => !a.is_probe);
  const unhardenedUnsafeStd = std.filter((a) => unhardenedState(a) === "unsafe");
  const n = unhardenedUnsafeStd.length;
  let x = 0;
  let y = 0;
  for (const a of unhardenedUnsafeStd) {
    const condData = a[condition] ?? {};
    if (condData.policy_block_rule) {
      x++;
    } else if (!isUnsafeCondition(condData)) {
      y++;
    }
  }
  return {
    nUnsafeUnhardened: n,
    xStoppedByRule: x,
    yDidNotRecur: y,
  };
}


function buildRange(attacksDoc, summary) {
  const attacks = attacksDoc?.attacks;
  if (!Array.isArray(attacks)) {
    fail("attacks.json has no attacks array");
    return null;
  }
  const byCat = (a, b) => a.category.localeCompare(b.category);
  const byId = (a, b) => a.id.localeCompare(b.id);
  // Same grouping and ordering as web/components/Range/RangeGrid.tsx
  const rowDefs = [
    { id: "email", label: "Email body", probe: false, pick: (a) => a.channel === "email" && !a.is_probe, sort: byCat },
    { id: "web_page", label: "Web page", probe: false, pick: (a) => a.channel === "web_page" && !a.is_probe, sort: byCat },
    { id: "document", label: "Document", probe: false, pick: (a) => a.channel === "document" && !a.is_probe, sort: byCat },
    { id: "probe_partner", label: "Partner probe", probe: true, pick: (a) => a.is_probe && a.category === "channel_probe_partner_address", sort: byId },
    { id: "probe_url", label: "URL probe", probe: true, pick: (a) => a.is_probe && a.category === "channel_probe_url_smuggling", sort: byId },
    { id: "probe_cal", label: "Calendar probe", probe: true, pick: (a) => a.is_probe && a.category === "channel_probe_calendar_fields", sort: byId },
  ];
  const rows = rowDefs.map((r) => ({
    id: r.id,
    label: r.label,
    probe: r.probe,
    squares: attacks.filter(r.pick).sort(r.sort).map((a) => unhardenedState(a)),
  }));

  // Cross-check the grid against summary.json so the picture and the numbers agree.
  const placed = rows.reduce((n, r) => n + r.squares.length, 0);
  const nTotal = get(summary, "n_total");
  if (attacks.length !== nTotal) fail(`attacks.json has ${attacks.length} attacks, summary.n_total is ${nTotal}`);
  if (placed !== attacks.length) fail(`only ${placed} of ${attacks.length} attacks fit a Range row`);
  const std = attacks.filter((a) => !a.is_probe);
  const probes = attacks.filter((a) => a.is_probe);
  const stdUnsafe = std.filter((a) => unhardenedState(a) === "unsafe");
  const probeUnsafe = probes.filter((a) => unhardenedState(a) === "unsafe").length;
  if (std.length !== get(summary, "n_standard")) fail("attacks.json standard count != summary.n_standard");
  if (probes.length !== get(summary, "n_probe")) fail("attacks.json probe count != summary.n_probe");
  if (stdUnsafe.length !== get(summary, "realistic_mode.unhardened.unsafe.count"))
    fail("attacks.json unhardened unsafe (standard) != realistic_mode.unhardened.unsafe.count");
  if (probeUnsafe !== get(summary, "probe_set.unhardened.unsafe.count"))
    fail("attacks.json unhardened unsafe (probes) != probe_set.unhardened.unsafe.count");
  const nonEmail = stdUnsafe.filter((a) => a.channel !== "email").length;
  if (nonEmail !== get(summary, "realistic_mode.web_doc_unsafe_count"))
    fail("attacks.json web/doc unsafe != realistic_mode.web_doc_unsafe_count");
  if (attacks.filter((a) => unhardenedState(a) === "unsafe" && a.channel !== "email").length !== 0)
    fail("script says every unsafe action came through email, but attacks.json disagrees");
  return { rows };
}

// ---------------------------------------------------------------- media
function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  if (r.error || r.status !== 0) {
    fail(`${cmd} ${args.join(" ")} failed: ${r.error?.message ?? r.stderr}`);
    return null;
  }
  return r.stdout;
}

function probeDuration(file) {
  const out = run("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", file]);
  return out ? Number(out.trim()) : null;
}

function copyIfChanged(src, dst) {
  if (fs.existsSync(dst) && fs.statSync(dst).size === fs.statSync(src).size) return;
  fs.copyFileSync(src, dst);
}

function stageFootage() {
  const out = {};
  fs.mkdirSync(path.join(PUBLIC_DIR, "footage"), { recursive: true });
  for (const f of FOOTAGE) {
    const src = path.join(VIDEO_DIR, "footage", f);
    if (!fs.existsSync(src)) {
      fail(`missing footage: video/footage/${f}`);
      continue;
    }
    copyIfChanged(src, path.join(PUBLIC_DIR, "footage", f));
    out[f.replace(".webm", "")] = { file: `footage/${f}`, durationSec: probeDuration(src) };
  }
  return out;
}

function stageAudio(sections) {
  const audioOut = path.join(PUBLIC_DIR, "audio");
  fs.rmSync(audioOut, { recursive: true, force: true });
  fs.mkdirSync(audioOut, { recursive: true });
  const result = {};
  const missing = [];
  for (const id of SCENE_IDS) {
    const src = path.join(VIDEO_DIR, "audio", `${id}.mp3`);
    if (fs.existsSync(src)) {
      const dst = path.join(audioOut, `${id}.mp3`);
      fs.copyFileSync(src, dst);
      const dur = probeDuration(dst);
      result[id] = { file: `audio/${id}.mp3`, placeholder: false, words: null, placeholderSec: null, durationSec: dur };
      continue;
    }
    const words = (sections[id]?.narration ?? "").split(/\s+/).filter(Boolean).length;
    const seconds = Math.max(1, (words / WORDS_PER_MINUTE) * 60);
    const name = `${id}.placeholder.wav`;
    const finalPath = path.join(audioOut, name);
    run("ffmpeg", [
      "-v", "error", "-y", "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo",
      "-t", seconds.toFixed(3), "-c:a", "pcm_s16le", finalPath,
    ]);
    const dur = probeDuration(finalPath);
    result[id] = { file: `audio/${name}`, placeholder: true, words, placeholderSec: Number(seconds.toFixed(3)), durationSec: dur ?? Number(seconds.toFixed(3)) };
    missing.push(`video/audio/${id}.mp3 (${words} words -> ${seconds.toFixed(2)} s silent)`);
  }

  // Stage background music (bgm.mp3)
  const bgmSrc = path.join(VIDEO_DIR, "audio", "bgm.mp3");
  let hasBgm = false;
  let bgmDurationSec = null;
  if (fs.existsSync(bgmSrc)) {
    const bgmDst = path.join(audioOut, "bgm.mp3");
    fs.copyFileSync(bgmSrc, bgmDst);
    bgmDurationSec = probeDuration(bgmDst);
    hasBgm = true;
  }

  return { result, missing, hasBgm, bgmDurationSec };
}

// ---------------------------------------------------------------- main
const summary = readJson(path.join(DATA_DIR, "summary.json"));
const attacksDoc = readJson(path.join(DATA_DIR, "attacks.json"));
if (!summary || !attacksDoc) {
  console.error(errors.join("\n"));
  process.exit(1);
}

const tokens = readTokens();
const sections = parseScript(summary);
const range = buildRange(attacksDoc, summary);

const lims = get(summary, "limitations");
if (!Array.isArray(lims) || lims.length < 3) fail("summary.limitations needs at least three entries");

const S = (p) => get(summary, p);
const display = {
  nTotal: int(S("n_total"), "n_total"),
  standard: {
    n: int(S("realistic_mode.n"), "realistic_mode.n"),
    before: {
      count: int(S("realistic_mode.unhardened.unsafe.count"), "unhardened.count"),
      countValue: S("realistic_mode.unhardened.unsafe.count"),
      ratePct: pct(S("realistic_mode.unhardened.unsafe.rate_pct"), "unhardened.rate_pct"),
      ciLo: pct(S("realistic_mode.unhardened.unsafe.ci_pct.0"), "unhardened.ci_pct.0"),
      ciHi: pct(S("realistic_mode.unhardened.unsafe.ci_pct.1"), "unhardened.ci_pct.1"),
    },
    after: {
      count: int(S("realistic_mode.policy_v2.unsafe.count"), "policy_v2.count"),
      countValue: S("realistic_mode.policy_v2.unsafe.count"),
      ratePct: pct(S("realistic_mode.policy_v2.unsafe.rate_pct"), "policy_v2.rate_pct"),
      ciLo: pct(S("realistic_mode.policy_v2.unsafe.ci_pct.0"), "policy_v2.ci_pct.0"),
      ciHi: pct(S("realistic_mode.policy_v2.unsafe.ci_pct.1"), "policy_v2.ci_pct.1"),
    },
    attribution: computeHardeningAttribution(attacksDoc.attacks, "v2"),
  },
  probe: {
    n: int(S("probe_set.n"), "probe_set.n"),
    unsafe: int(S("probe_set.unhardened.unsafe.count"), "probe_set.unhardened.unsafe.count"),
  },
  benign: {
    tasks: int(S("benign_suite.tasks_per_repeat"), "tasks_per_repeat"),
    repeats: int(S("benign_suite.repeats"), "repeats"),
    rows: [
      ["unhardened", "Unhardened"],
      ["policy_v2", "Policy v2"],
    ].map(([k, label]) => ({
      key: k,
      label,
      passed: int(S(`benign_suite.${k}.pooled_passed`), `${k}.pooled_passed`),
      total: int(S(`benign_suite.${k}.pooled_total`), `${k}.pooled_total`),
      pct: pct(S(`benign_suite.${k}.pooled_pass_rate_pct`), `${k}.pooled_pass_rate_pct`),
      pctValue: S(`benign_suite.${k}.pooled_pass_rate_pct`),
      ciLo: pct(S(`benign_suite.${k}.ci_pct.0`), `${k}.ci_pct.0`),
      ciHi: pct(S(`benign_suite.${k}.ci_pct.1`), `${k}.ci_pct.1`),
      ciLoValue: S(`benign_suite.${k}.ci_pct.0`),
      ciHiValue: S(`benign_suite.${k}.ci_pct.1`),
    })),
    control: {
      label: "Deny-all control",
      condition: String(S("benign_suite.negative_control.condition")),
      status: String(S("benign_suite.negative_control.status")),
      passed: int(S("benign_suite.negative_control.passed"), "negative_control.passed"),
      total: int(S("benign_suite.negative_control.total"), "negative_control.total"),
      pct: pct(S("benign_suite.negative_control.pass_rate_pct"), "negative_control.pass_rate_pct"),
      pctValue: S("benign_suite.negative_control.pass_rate_pct"),
      ciLo: pct(S("benign_suite.negative_control.ci_pct.0"), "negative_control.ci_pct.0"),
      ciHi: pct(S("benign_suite.negative_control.ci_pct.1"), "negative_control.ci_pct.1"),
      ciLoValue: S("benign_suite.negative_control.ci_pct.0"),
      ciHiValue: S("benign_suite.negative_control.ci_pct.1"),
    },
  },
  limitations: Array.isArray(lims)
    ? lims.slice(0, 3).map((l) => String(l).charAt(0).toUpperCase() + String(l).slice(1))
    : [],
};
if (S("benign_suite.negative_control.condition") !== "deny_all")
  fail("negative_control.condition is not deny_all; update the 'Deny-all control' label");

// Repo link and licence come from the repo itself, not typed.
const remote = run("git", ["-C", REPO, "remote", "get-url", "origin"])?.trim() ?? "";
const repoLink = remote.replace(/^https?:\/\//, "").replace(/^git@([^:]+):/, "$1/").replace(/\.git$/, "");
if (!repoLink.startsWith("github.com/")) fail(`unexpected git remote: ${remote}`);
const licenseText = fs.readFileSync(path.join(REPO, "LICENSE"), "utf8");
if (!/^MIT License/m.test(licenseText)) fail("LICENSE is not the MIT licence; end card says MIT");

const footage = stageFootage();
const { result: audio, missing, hasBgm, bgmDurationSec } = stageAudio(sections);

if (errors.length) {
  console.error("\nBuild data check FAILED:\n- " + errors.join("\n- "));
  process.exit(1);
}

const scenes = SCENE_IDS.map((id) => ({
  id,
  title: sections[id].title,
  onScreen: sections[id].onScreen,
  narration: sections[id].narration,
  captions: chunkCaption(sections[id].narration),
  audio: audio[id],
}));

fs.mkdirSync(GEN_DIR, { recursive: true });
fs.writeFileSync(
  path.join(GEN_DIR, "build-data.json"),
  JSON.stringify({ tokens, display, range, scenes, footage, repoLink, license: "MIT", missingAudio: missing, hasBgm, bgmDurationSec }, null, 2),
);

const resolved = [
  "# Gauntlet video script (resolved)",
  "",
  "Generated by scripts/prepare.mjs from script.md and summary.json. Do not edit; edit script.md.",
  "",
  ...scenes.flatMap((s) => [
    `## ${s.id} ${s.title}`,
    "",
    ...(s.onScreen ? [`On screen: ${s.onScreen}`, ""] : []),
    s.narration,
    "",
  ]),
].join("\n");
fs.writeFileSync(path.join(VIDEO_DIR, "script.resolved.md"), resolved);

console.log("Build data OK -> src/generated/build-data.json");
console.log(`BGM: ${hasBgm ? `staged (${bgmDurationSec?.toFixed(2)}s)` : "none"}`);
for (const s of scenes) {
  console.log(`  ${s.id.padEnd(3)} [${s.audio.durationSec?.toFixed(2)}s] captions=${s.captions.length} longest=${Math.max(...s.captions.map((c) => c.text.length))} chars`);
}
if (missing.length) {
  console.log("\nMissing narration audio, silent placeholders used:");
  for (const m of missing) console.log("  - " + m);
}
