"""Generate 1200x630 OG image using Playwright from real Range screenshot + headline numbers."""

import functools
import http.server
import json
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "web" / "out"
PUBLIC_DIR = ROOT / "web" / "public"

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

handler = functools.partial(_QuietHandler, directory=str(OUT_DIR))
server = http.server.ThreadingHTTPServer(("127.0.0.1", 3160), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

try:
    with sync_playwright() as p:
        browser = p.chromium.launch()

        # 1. Capture real Range grid from the live running static build
        page = browser.new_page(viewport={"width": 1100, "height": 600})
        page.goto("http://127.0.0.1:3160/", wait_until="networkidle")
        page.wait_for_selector("[data-range-square]")

        # Capture the Range grid SVG directly
        grid_svg = page.locator("svg:has([data-range-square])").first
        grid_svg.wait_for(state="visible", timeout=10000)
        range_screenshot_path = ROOT / "runs" / "a11y" / "range_temp.png"
        range_screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        grid_svg.screenshot(path=str(range_screenshot_path))

        # Read summary data
        summary_path = PUBLIC_DIR / "data" / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        n_total = summary.get("n_total", 235)
        unh_rate = summary.get("realistic_mode", {}).get("unhardened", {}).get("unsafe", {}).get("rate_pct", 71.6)
        v2_rate = summary.get("realistic_mode", {}).get("policy_v2", {}).get("unsafe", {}).get("rate_pct", 0.0)

        # Read SVG logo
        logo_path = PUBLIC_DIR / "logo.svg"
        logo_svg = logo_path.read_text(encoding="utf-8")

        # Convert captured grid to data URL
        import base64
        grid_b64 = base64.b64encode(range_screenshot_path.read_bytes()).decode("utf-8")

        # 2. Render 1200x630 OG composition
        og_page = browser.new_page(viewport={"width": 1200, "height": 630})
        html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    width: 1200px;
    height: 630px;
    background: #0D161C;
    color: #EAEEF0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 48px 56px;
    overflow: hidden;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  .brand svg {{
    width: 36px;
    height: 36px;
    stroke: #EAEEF0;
  }}
  .brand-name {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #FFFFFF;
  }}
  .badge {{
    font-size: 13px;
    font-family: monospace;
    padding: 6px 14px;
    border-radius: 6px;
    background: #172A36;
    border: 1px solid #2A4354;
    color: #186959;
    font-weight: 600;
  }}
  .headline-section {{
    margin-top: 20px;
    margin-bottom: 24px;
  }}
  .headline {{
    font-size: 44px;
    font-weight: 800;
    letter-spacing: -1px;
    line-height: 1.15;
    color: #FFFFFF;
  }}
  .headline span.accent {{
    color: #186959;
  }}
  .subtitle {{
    font-size: 18px;
    color: #8C9EA8;
    margin-top: 10px;
    font-weight: 500;
  }}
  .grid-container {{
    flex: 1;
    background: #13232E;
    border: 1px solid #233B4B;
    border-radius: 8px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }}
  .grid-container img {{
    max-height: 250px;
    width: auto;
    object-fit: contain;
    border-radius: 4px;
  }}
  .footer {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 20px;
    font-size: 13px;
    color: #6C7F8B;
    font-family: monospace;
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="brand">
      {logo_svg}
      <div class="brand-name">Gauntlet</div>
    </div>
    <div class="badge">Deterministic Policy-as-Code Defense</div>
  </div>

  <div class="headline-section">
    <div class="headline">
      {n_total} Attacks Hardened &nbsp;|&nbsp; <span class="accent">{unh_rate:.1f}% &rarr; {v2_rate:.1f}%</span> Unsafe
    </div>
    <div class="subtitle">
      Automated AI agent hardening against prompt injection and tool misuse. Zero LLM judges.
    </div>
  </div>

  <div class="grid-container">
    <img src="data:image/png;base64,{grid_b64}" alt="The Range Grid">
  </div>

  <div class="footer">
    <div>Target: Meridian Assistant (inbox)</div>
    <div>Nebius Token Factory &bull; NVIDIA Nemotron 3</div>
  </div>
</body>
</html>"""
        og_page.set_content(html_content)
        og_page.wait_for_timeout(300)

        og_out_public = PUBLIC_DIR / "og.png"
        og_out_out = OUT_DIR / "og.png"
        og_page.screenshot(path=str(og_out_public))
        og_page.screenshot(path=str(og_out_out))
        print(f"Generated OG image: {og_out_public} (1200x630)")

        browser.close()
finally:
    server.shutdown()
