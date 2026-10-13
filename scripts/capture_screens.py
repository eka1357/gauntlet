"""Capture 1440px and 390px screenshots into docs/screens/."""

import functools
import http.server
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "web" / "out"
SCREENS_DIR = ROOT / "docs" / "screens"
SCREENS_DIR.mkdir(parents=True, exist_ok=True)

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

handler = functools.partial(_QuietHandler, directory=str(OUT_DIR))
server = http.server.ThreadingHTTPServer(("127.0.0.1", 3170), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

try:
    with sync_playwright() as p:
        browser = p.chromium.launch()

        viewports = [
            ("1440", {"width": 1440, "height": 900}),
            ("390", {"width": 390, "height": 844}),
        ]

        for suffix, vp in viewports:
            page = browser.new_page(viewport=vp)

            # 1. Range (Home)
            page.goto("http://127.0.0.1:3170/", wait_until="networkidle")
            page.wait_for_selector("[data-range-square]")
            page.wait_for_timeout(600)
            page.screenshot(path=str(SCREENS_DIR / f"range_{suffix}.png"), full_page=False)
            print(f"Captured range_{suffix}.png")

            # 2. Open Drawer
            square = page.locator("[data-range-square]").first
            square.click()
            page.wait_for_selector("[role=dialog]")
            page.wait_for_timeout(600)
            page.screenshot(path=str(SCREENS_DIR / f"drawer_{suffix}.png"), full_page=False)
            print(f"Captured drawer_{suffix}.png")
            page.close()

            # 3. Results
            page_res = browser.new_page(viewport=vp)
            page_res.goto("http://127.0.0.1:3170/results/", wait_until="networkidle")
            page_res.wait_for_timeout(600)
            page_res.screenshot(path=str(SCREENS_DIR / f"results_{suffix}.png"), full_page=False)
            print(f"Captured results_{suffix}.png")
            page_res.close()

            # 4. Report
            page_rep = browser.new_page(viewport=vp)
            page_rep.goto("http://127.0.0.1:3170/report/", wait_until="networkidle")
            page_rep.wait_for_timeout(600)
            page_rep.screenshot(path=str(SCREENS_DIR / f"report_{suffix}.png"), full_page=False)
            print(f"Captured report_{suffix}.png")
            page_rep.close()

        browser.close()
finally:
    server.shutdown()
