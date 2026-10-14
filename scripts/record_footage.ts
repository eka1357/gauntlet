/**
 * scripts/record_footage.ts
 *
 * Records 1920x1080 footage of the deployed Gauntlet site into video/footage/.
 * Clips recorded:
 *   a) drawer_open.webm: Load /, click unsafe email square (conf2_std_email_011),
 *      open drawer, slowly scroll trace to leaking tool call, hold 3s.
 *   b) conditions.webm: Switch Range condition unhardened -> Policy v1 -> Policy v2,
 *      holding 4s each.
 *   c) results.webm: Open /results/, scroll slowly through the headline table.
 *   d) policy.webm: Open /policy/, scroll the v2 YAML.
 *   e) report.webm: Open /report/, scroll the top.
 *
 * Uses browser zoom so text is crisp at 1080p, hides scrollbars,
 * injects a soft cursor and click ripple, and pauses 1.2s between actions.
 */

import { chromium } from 'playwright';
import type { Browser, BrowserContext, Page } from 'playwright';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const DEMO_URL = (process.env.DEMO_URL || 'https://gauntlet-ecru.vercel.app').replace(/\/+$/, '');
const OUTPUT_DIR = path.resolve('video/footage');
const FRAMES_DIR = path.join(OUTPUT_DIR, 'frames');
const TMP_DIR = path.join(OUTPUT_DIR, '.tmp_recordings');
const VIEWPORT = { width: 1920, height: 1080 };
const ZOOM_LEVEL = 1.12;
const ACTION_PAUSE_MS = 1200;

// Ensure directories exist
fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(FRAMES_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

function pause(ms: number = ACTION_PAUSE_MS): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Injects custom CSS (zoom, hidden scrollbars) and soft cursor + click ripple logic.
 */
async function setupPageEnvironment(page: Page): Promise<void> {
  // Inject soft cursor & click ripple
  await page.addInitScript(() => {
    window.addEventListener('DOMContentLoaded', () => {
      // 1. Cursor element
      const cursor = document.createElement('div');
      cursor.id = 'gauntlet-soft-cursor';
      cursor.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 2px 6px rgba(0,0,0,0.35));">
          <path d="M4.5 2.5L18.5 13.5L11.5 14.5L8.5 21.5L4.5 2.5Z" fill="#0f172a" stroke="#ffffff" stroke-width="1.8" stroke-linejoin="round"/>
        </svg>
      `;
      cursor.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        pointer-events: none;
        z-index: 9999999;
        transform: translate(-100px, -100px);
        transition: transform 0.04s ease-out;
      `;
      document.body.appendChild(cursor);

      // Track cursor position
      window.addEventListener('mousemove', (e) => {
        cursor.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
      });

      // 2. Click ripple
      window.addEventListener('mousedown', (e) => {
        const ripple = document.createElement('div');
        ripple.className = 'gauntlet-click-ripple';
        ripple.style.cssText = `
          position: fixed;
          left: ${e.clientX}px;
          top: ${e.clientY}px;
          width: 10px;
          height: 10px;
          border-radius: 50%;
          border: 2px solid rgba(15, 23, 42, 0.55);
          background: rgba(15, 23, 42, 0.15);
          pointer-events: none;
          z-index: 9999998;
          transform: translate(-50%, -50%) scale(1);
          animation: ripple-fx 0.5s cubic-bezier(0.1, 0.8, 0.3, 1) forwards;
        `;
        document.body.appendChild(ripple);
        setTimeout(() => ripple.remove(), 550);
      });

      // 3. Inject CSS for hidden scrollbars & ripple keyframes
      const style = document.createElement('style');
      style.textContent = `
        * { cursor: none !important; }
        *::-webkit-scrollbar { display: none !important; }
        * { scrollbar-width: none !important; -ms-overflow-style: none !important; }
        @keyframes ripple-fx {
          0% { transform: translate(-50%, -50%) scale(1); opacity: 0.9; }
          100% { transform: translate(-50%, -50%) scale(5.5); opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    });
  });
}

/**
 * Applies layout zoom and ensures fixed elements (e.g. drawer) stay within viewport.
 */
async function applyZoom(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `
      *::-webkit-scrollbar { display: none !important; }
      * { scrollbar-width: none !important; -ms-overflow-style: none !important; }
      html { zoom: ${ZOOM_LEVEL}; }
      div.fixed.w-screen { width: 100vw !important; max-width: 100% !important; }
    `,
  });
}

/**
 * Smoothly moves cursor across the screen to target coordinates.
 */
async function smoothMoveTo(page: Page, targetX: number, targetY: number, steps: number = 28): Promise<void> {
  await page.mouse.move(targetX, targetY, { steps });
}

/**
 * Glides cursor to element center, clicks with visible ripple, and pauses.
 */
async function clickWithRipple(page: Page, selector: string): Promise<void> {
  const element = page.locator(selector).first();
  await element.scrollIntoViewIfNeeded();
  const box = await element.boundingBox();
  if (!box) {
    throw new Error(`Element not found for selector: ${selector}`);
  }
  const targetX = box.x + box.width / 2;
  const targetY = box.y + box.height / 2;

  await smoothMoveTo(page, targetX, targetY, 25);
  await page.waitForTimeout(200);

  // Trigger mousedown for ripple animation
  await page.mouse.down();
  await page.waitForTimeout(100);
  await page.mouse.up();
  await page.waitForTimeout(200);
}

/**
 * Smoothly scrolls an element or window over a specified duration using quadratic easing.
 */
async function smoothScrollElement(
  page: Page,
  selector: string,
  targetScrollTop: number,
  durationMs: number = 2500
): Promise<void> {
  await page.evaluate(
    ({ sel, target, duration }) => {
      return new Promise<void>((resolve) => {
        const el = document.querySelector(sel);
        if (!el) {
          resolve();
          return;
        }
        const start = el.scrollTop;
        const delta = target - start;
        const startTime = performance.now();

        function step(now: number) {
          const elapsed = now - startTime;
          const progress = Math.min(1, elapsed / duration);
          // Ease in-out quad
          const ease = progress < 0.5 ? 2 * progress * progress : 1 - Math.pow(-2 * progress + 2, 2) / 2;
          el.scrollTop = start + delta * ease;
          if (progress < 1) {
            requestAnimationFrame(step);
          } else {
            resolve();
          }
        }
        requestAnimationFrame(step);
      });
    },
    { sel: selector, target: targetScrollTop, duration: durationMs }
  );
}

async function smoothScrollWindow(
  page: Page,
  targetScrollY: number,
  durationMs: number = 2500
): Promise<void> {
  await page.evaluate(
    ({ target, duration }) => {
      return new Promise<void>((resolve) => {
        const start = window.scrollY;
        const delta = target - start;
        const startTime = performance.now();

        function step(now: number) {
          const elapsed = now - startTime;
          const progress = Math.min(1, elapsed / duration);
          const ease = progress < 0.5 ? 2 * progress * progress : 1 - Math.pow(-2 * progress + 2, 2) / 2;
          window.scrollTo(0, start + delta * ease);
          if (progress < 1) {
            requestAnimationFrame(step);
          } else {
            resolve();
          }
        }
        requestAnimationFrame(step);
      });
    },
    { target: targetScrollY, duration: durationMs }
  );
}

/**
 * Records a single clip into video/footage/<clipName>.webm
 */
async function recordClip(
  browser: Browser,
  clipName: string,
  actionFn: (page: Page) => Promise<void>
): Promise<string> {
  console.log(`\n========================================`);
  console.log(`[Recording] ${clipName}.webm`);
  console.log(`========================================`);

  const context: BrowserContext = await browser.newContext({
    viewport: VIEWPORT,
    recordVideo: {
      dir: TMP_DIR,
      size: VIEWPORT,
    },
  });

  const page = await context.newPage();
  await setupPageEnvironment(page);

  try {
    await actionFn(page);
  } finally {
    const video = page.video();
    await page.close();
    await context.close();

    if (video) {
      const finalPath = path.join(OUTPUT_DIR, `${clipName}.webm`);
      await video.saveAs(finalPath);
      console.log(`[Saved] ${finalPath} (${(fs.statSync(finalPath).size / 1024).toFixed(1)} KB)`);
      return finalPath;
    } else {
      throw new Error(`Failed to capture video stream for ${clipName}`);
    }
  }
}

/**
 * Extracts 3 evenly-spaced frames from a .webm clip using ffmpeg.
 */
function extractFrames(clipName: string): void {
  const clipPath = path.join(OUTPUT_DIR, `${clipName}.webm`);
  if (!fs.existsSync(clipPath)) {
    console.error(`Clip not found: ${clipPath}`);
    return;
  }

  // Get clip duration using ffprobe or ffmpeg
  try {
    const output = execFileSync(
      'ffmpeg',
      ['-i', clipPath],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
  } catch (err: unknown) {
    const stderr = (err as { stderr?: string }).stderr || '';
    const match = stderr.match(/Duration:\s*(\d+):(\d+):([\d.]+)/);
    let durationSec = 6.0;
    if (match) {
      const hours = parseFloat(match[1]);
      const mins = parseFloat(match[2]);
      const secs = parseFloat(match[3]);
      durationSec = hours * 3600 + mins * 60 + secs;
    }

    const t1 = (durationSec * 0.25).toFixed(2);
    const t2 = (durationSec * 0.55).toFixed(2);
    const t3 = (durationSec * 0.85).toFixed(2);

    const timestamps = [t1, t2, t3];
    timestamps.forEach((ts, idx) => {
      const frameNum = String(idx + 1).padStart(2, '0');
      const framePath = path.join(FRAMES_DIR, `${clipName}_${frameNum}.png`);
      execFileSync('ffmpeg', [
        '-y',
        '-ss',
        ts,
        '-i',
        clipPath,
        '-vframes',
        '1',
        framePath,
      ]);
      console.log(`  [Frame] ${clipName}_${frameNum}.png (at ${ts}s)`);
    });
  }
}

async function main() {
  console.log(`Gauntlet Footage Recorder`);
  console.log(`Target URL: ${DEMO_URL}`);
  console.log(`Output Directory: ${OUTPUT_DIR}`);
  console.log(`Resolution: ${VIEWPORT.width}x${VIEWPORT.height} @ zoom ${ZOOM_LEVEL}`);

  const browser = await chromium.launch();

  try {
    // ----------------------------------------------------
    // Clip a: drawer_open.webm
    // ----------------------------------------------------
    await recordClip(browser, 'drawer_open', async (page) => {
      await page.goto(`${DEMO_URL}/`, { waitUntil: 'networkidle' });
      await applyZoom(page);
      await page.waitForSelector('[data-range-square]');
      await pause();

      // Click unsafe email attack square: conf2_std_email_011
      const attackId = 'conf2_std_email_011';
      console.log(`Clicking attack square: ${attackId}`);
      await clickWithRipple(page, `[data-range-square="${attackId}"]`);

      // Let the drawer open and trace load
      await page.waitForSelector('[role="dialog"]');
      await page.waitForSelector('[role="feed"]');
      await pause();

      // Slowly scroll the trace in the drawer to the leaking tool call (#5 send_email())
      console.log('Scrolling trace to leaking tool call...');
      const drawerAside = 'aside[role="dialog"]';
      const scrollHeight = await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        return el ? el.scrollHeight - el.clientHeight : 1000;
      }, drawerAside);

      await smoothScrollElement(page, drawerAside, scrollHeight, 3000);

      // Hold 3s on the leaking tool call
      console.log('Holding 3s on leaking tool call...');
      await page.waitForTimeout(3200);
    });

    // ----------------------------------------------------
    // Clip b: conditions.webm
    // ----------------------------------------------------
    await recordClip(browser, 'conditions', async (page) => {
      await page.goto(`${DEMO_URL}/`, { waitUntil: 'networkidle' });
      await applyZoom(page);
      await page.waitForSelector('[data-range-square]');
      await pause();

      // 1. Unhardened: click button and hold 4s
      console.log('Setting condition: Unhardened (hold 4s)');
      await clickWithRipple(page, 'button:has-text("Unhardened")');
      await page.waitForTimeout(4000);
      await pause();

      // 2. Policy v1: click button and hold 4s
      console.log('Setting condition: Policy v1 (hold 4s)');
      await clickWithRipple(page, 'button:has-text("Policy v1")');
      await page.waitForTimeout(4000);
      await pause();

      // 3. Policy v2: click button and hold 4s
      console.log('Setting condition: Policy v2 (hold 4s)');
      await clickWithRipple(page, 'button:has-text("Policy v2")');
      await page.waitForTimeout(4000);
    });

    // ----------------------------------------------------
    // Clip c: results.webm
    // ----------------------------------------------------
    await recordClip(browser, 'results', async (page) => {
      await page.goto(`${DEMO_URL}/results/`, { waitUntil: 'networkidle' });
      await applyZoom(page);
      await page.waitForSelector('h1:has-text("Verification Results")');
      await pause();

      // Slowly scroll through headline table and interval plots
      console.log('Scrolling through headline table and plots...');
      await smoothScrollWindow(page, 450, 2500);
      await pause();

      // Slowly scroll further down to benign variance table
      console.log('Scrolling to benign task suite and repeat variance table...');
      await smoothScrollWindow(page, 950, 2500);
      await page.waitForTimeout(3200);
    });

    // ----------------------------------------------------
    // Clip d: policy.webm
    // ----------------------------------------------------
    await recordClip(browser, 'policy', async (page) => {
      await page.goto(`${DEMO_URL}/policy/`, { waitUntil: 'networkidle' });
      await applyZoom(page);
      const v2YamlBox = 'div[aria-label*="Policy v2 specification YAML"]';
      await page.waitForSelector(v2YamlBox);
      await pause();

      // Scroll page slightly to focus on policy boxes
      await smoothScrollWindow(page, 200, 1500);
      await pause();

      // Move cursor to v2 YAML container
      const box = await page.locator(v2YamlBox).first().boundingBox();
      if (box) {
        await smoothMoveTo(page, box.x + box.width / 2, box.y + 120, 20);
      }
      await pause();

      // Scroll the v2 YAML box
      console.log('Scrolling v2 YAML container...');
      const yamlScrollHeight = await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        return el ? el.scrollHeight - el.clientHeight : 800;
      }, v2YamlBox);

      await smoothScrollElement(page, v2YamlBox, yamlScrollHeight, 3800);
      await page.waitForTimeout(3200);
    });

    // ----------------------------------------------------
    // Clip e: report.webm
    // ----------------------------------------------------
    await recordClip(browser, 'report', async (page) => {
      await page.goto(`${DEMO_URL}/report/`, { waitUntil: 'networkidle' });
      await applyZoom(page);
      await page.waitForSelector('h1:has-text("AI Agent Hardening")');
      await pause();

      // Hold at top
      await page.waitForTimeout(1500);
      await pause();

      // Scroll top section smoothly
      console.log('Scrolling through report top section...');
      await smoothScrollWindow(page, 650, 3500);
      await page.waitForTimeout(3200);
    });

  } finally {
    await browser.close();

    // Clean up temporary directory
    if (fs.existsSync(TMP_DIR)) {
      fs.rmSync(TMP_DIR, { recursive: true, force: true });
    }
  }

  // ----------------------------------------------------
  // Extract 3 frames per clip using ffmpeg
  // ----------------------------------------------------
  console.log('\n========================================');
  console.log('Extracting frames from clips using ffmpeg');
  console.log('========================================');
  const clips = ['drawer_open', 'conditions', 'results', 'policy', 'report'];
  for (const c of clips) {
    extractFrames(c);
  }

  console.log('\nAll footage clips and frames extracted successfully.');
}

main().catch((err) => {
  console.error('Recording error:', err);
  process.exit(1);
});
