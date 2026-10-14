/**
 * scripts/record_live.ts
 *
 * Records a real 1920x1080 live run on http://localhost:3000/live into video/footage/live.webm:
 * - Target Mode: Realistic prompt (defensive baseline)
 * - Attacks: 8
 * - Policy v2: Enabled (checked)
 * - Records until the run completes (mini-Range filling, event log streaming, cost meter advancing)
 * - Extracts 4 representative frames into video/footage/frames/live_01.png .. live_04.png
 */

import { chromium } from 'playwright';
import type { Browser, BrowserContext, Page } from 'playwright';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const TARGET_URL = 'http://localhost:3000/live';
const OUTPUT_DIR = path.resolve('video/footage');
const FRAMES_DIR = path.join(OUTPUT_DIR, 'frames');
const TMP_DIR = path.join(OUTPUT_DIR, '.tmp_live_recordings');
const VIEWPORT = { width: 1920, height: 1080 };
const ZOOM_LEVEL = 1.02;

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(FRAMES_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

async function setupPageEnvironment(page: Page): Promise<void> {
  await page.addInitScript(() => {
    window.addEventListener('DOMContentLoaded', () => {
      // 1. Soft cursor
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

      // 3. Styles for hidden scrollbars & ripple
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

async function applyZoom(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `
      *::-webkit-scrollbar { display: none !important; }
      * { scrollbar-width: none !important; -ms-overflow-style: none !important; }
      html { zoom: ${ZOOM_LEVEL}; }
    `,
  });
}

async function smoothMoveTo(page: Page, targetX: number, targetY: number, steps: number = 25): Promise<void> {
  await page.mouse.move(targetX, targetY, { steps });
}

async function clickWithRipple(page: Page, selector: string): Promise<void> {
  const element = page.locator(selector).first();
  await element.scrollIntoViewIfNeeded();
  const box = await element.boundingBox();
  if (!box) {
    throw new Error(`Element not found for selector: ${selector}`);
  }
  const targetX = box.x + box.width / 2;
  const targetY = box.y + box.height / 2;

  await smoothMoveTo(page, targetX, targetY, 20);
  await page.waitForTimeout(200);
  await page.mouse.down();
  await page.waitForTimeout(100);
  await page.mouse.up();
  await page.waitForTimeout(300);
}

function extractFrames(clipPath: string, count: number = 4): string[] {
  if (!fs.existsSync(clipPath)) {
    console.error(`Clip not found: ${clipPath}`);
    return [];
  }

  // Get duration
  let durationSec = 60.0;
  try {
    execFileSync('ffmpeg', ['-i', clipPath], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err: unknown) {
    const stderr = (err as { stderr?: string }).stderr || '';
    const match = stderr.match(/Duration:\s*(\d+):(\d+):([\d.]+)/);
    if (match) {
      const hours = parseFloat(match[1]);
      const mins = parseFloat(match[2]);
      const secs = parseFloat(match[3]);
      durationSec = hours * 3600 + mins * 60 + secs;
    }
  }

  console.log(`Video duration: ${durationSec.toFixed(1)}s`);

  // Pick 4 evenly spaced timestamps:
  // 1. Initial configured / just started (~2.5s)
  // 2. ~30% duration (early stream, 2-3 attacks finished)
  // 3. ~65% duration (mid-late stream, 5-6 attacks finished)
  // 4. ~98% duration (completed run with summary banner and all 8 attacks)
  const t1 = Math.min(3.0, durationSec * 0.05).toFixed(2);
  const t2 = (durationSec * 0.32).toFixed(2);
  const t3 = (durationSec * 0.68).toFixed(2);
  const t4 = Math.max(durationSec - 2.5, durationSec * 0.95).toFixed(2);

  const timestamps = [t1, t2, t3, t4];
  const framePaths: string[] = [];

  timestamps.forEach((ts, idx) => {
    const frameNum = String(idx + 1).padStart(2, '0');
    const framePath = path.join(FRAMES_DIR, `live_${frameNum}.png`);
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
    console.log(`  [Frame] live_${frameNum}.png (at ${ts}s) -> ${framePath}`);
    framePaths.push(framePath);
  });

  return framePaths;
}

async function main() {
  console.log('='.repeat(70));
  console.log('GAUNTLET: PLAYWRIGHT LIVE RUN VIDEO RECORDER');
  console.log(`Target URL:  ${TARGET_URL}`);
  console.log(`Resolution:  ${VIEWPORT.width}x${VIEWPORT.height} (1080p)`);
  console.log(`Target Mode: Realistic prompt (defensive baseline)`);
  console.log(`Attacks:     8`);
  console.log(`Compare v2:  true`);
  console.log('='.repeat(70));

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: VIEWPORT,
    recordVideo: {
      dir: TMP_DIR,
      size: VIEWPORT,
    },
  });

  const page = await context.newPage();
  await setupPageEnvironment(page);

  const consoleLogs: string[] = [];
  page.on('console', (msg) => {
    consoleLogs.push(`[Browser] ${msg.text()}`);
  });

  try {
    console.log(`Navigating to ${TARGET_URL}...`);
    await page.goto(TARGET_URL, { waitUntil: 'networkidle' });
    await applyZoom(page);
    await page.waitForTimeout(1000);

    // Verify live runs are enabled
    const disabledWarning = page.locator('text=Live runs are off in this deployment');
    if ((await disabledWarning.count()) > 0 && (await disabledWarning.isVisible())) {
      throw new Error(
        'Live runs are disabled on the frontend! Check LIVE_RUNS_ENABLED on backend and health check.'
      );
    }

    // Initial mouse placement
    await page.mouse.move(960, 200, { steps: 15 });
    await page.waitForTimeout(600);

    // 1. Select Target Mode: "realistic"
    console.log('Selecting Target Mode: "realistic"...');
    const modeSelect = page.locator('#live-target-mode');
    await modeSelect.scrollIntoViewIfNeeded();
    const modeBox = await modeSelect.boundingBox();
    if (modeBox) {
      await smoothMoveTo(page, modeBox.x + modeBox.width / 2, modeBox.y + modeBox.height / 2, 20);
      await page.waitForTimeout(200);
      await modeSelect.selectOption('realistic');
      await page.waitForTimeout(400);
    }

    // 2. Set Attacks Slider to 8
    console.log('Setting Attacks Slider to 8...');
    const slider = page.locator('#live-n-attacks');
    await slider.scrollIntoViewIfNeeded();
    const sliderBox = await slider.boundingBox();
    if (sliderBox) {
      await smoothMoveTo(page, sliderBox.x + sliderBox.width * 0.9, sliderBox.y + sliderBox.height / 2, 20);
      await page.waitForTimeout(200);
      await slider.fill('8');
      await page.waitForTimeout(400);
    }

    // 3. Verify Policy v2 checkbox is checked
    console.log('Verifying Policy v2 checkbox...');
    const v2Checkbox = page.locator('#compareV2');
    const isChecked = await v2Checkbox.isChecked();
    if (!isChecked) {
      await clickWithRipple(page, '#compareV2');
    }
    await page.waitForTimeout(500);

    // 4. Click 'Start Live Run'
    console.log('Clicking "Start Live Run"...');
    await clickWithRipple(page, "button:has-text('Start Live Run')");

    // Move mouse smoothly to neutral observation position (e.g. above mini-range)
    await page.waitForTimeout(300);
    await smoothMoveTo(page, 960, 480, 25);

    // 5. Monitor run progress until completed
    console.log('Recording live attack stream...');
    const startTime = Date.now();
    const maxWaitMs = 180000; // 3 minutes timeout
    let completed = false;

    while (Date.now() - startTime < maxWaitMs) {
      await page.waitForTimeout(3000);

      const elapsedSec = Math.round((Date.now() - startTime) / 1000);
      const content = await page.content();

      // Check completion signals
      const isComplete =
        content.includes('Live Run Complete') ||
        content.includes('State: Completed') ||
        content.includes('State: completed') ||
        content.includes('Run complete') ||
        content.includes('Run finished:');

      // Extract current status from page
      const statusMatch = content.match(/State:\s*<\/span>\s*<span[^>]*>([^<]+)<\/span>/i);
      const stateStr = statusMatch ? statusMatch[1].trim() : 'running';

      const attacksMatch = content.match(/(\d+)\s+executed\s+\(batch limit:\s*(\d+)\)/);
      const executedStr = attacksMatch ? `${attacksMatch[1]}/${attacksMatch[2]}` : '?/8';

      const costMatch = content.match(/Cost:\s*<\/span>\s*<span[^>]*>(\$[0-9.]+)<\/span>/i);
      const costStr = costMatch ? costMatch[1].trim() : '$0.0000';

      console.log(
        `  [Live Progress] +${elapsedSec}s | State: ${stateStr} | Executed: ${executedStr} | Cost: ${costStr}`
      );

      if (isComplete) {
        console.log(`Live run completed successfully in ${elapsedSec}s!`);
        completed = true;
        break;
      }

      if (content.includes('Run encountered an error') || content.includes('Run rejected')) {
        throw new Error('Live run encountered an error in browser UI!');
      }
    }

    if (!completed) {
      throw new Error('Live run timed out before completion!');
    }

    // Hold on the completed screen for 4.5 seconds so final state is captured clearly
    console.log('Holding on completed state for final frames...');
    await page.waitForTimeout(4500);

  } finally {
    const video = page.video();
    await page.close();
    await context.close();
    await browser.close();

    if (video) {
      const finalWebmPath = path.join(OUTPUT_DIR, 'live.webm');
      await video.saveAs(finalWebmPath);
      const sizeMb = (fs.statSync(finalWebmPath).size / (1024 * 1024)).toFixed(2);
      console.log(`\n[SUCCESS] Saved live recording to: ${finalWebmPath} (${sizeMb} MB)`);

      // Extract 4 frames
      console.log('\nExtracting 4 representative frames with ffmpeg:');
      extractFrames(finalWebmPath, 4);
    } else {
      throw new Error('Playwright did not produce a video stream!');
    }
  }
}

main().catch((err) => {
  console.error('\n[FATAL ERROR]', err);
  process.exit(1);
});
