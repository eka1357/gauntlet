"""Capture screenshots at 1440px and 390px, verify zero console errors, and print /report to PDF."""

from __future__ import annotations

import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

SCREENS_DIR = Path("docs/screens")
SCREENS_DIR.mkdir(parents=True, exist_ok=True)

ROUTES = [
    ("home", "/"),
    ("results", "/results"),
    ("policy", "/policy"),
    ("live", "/live"),
    ("report", "/report"),
]

VIEWPORTS = [
    ("1440", {"width": 1440, "height": 900}),
    ("390", {"width": 390, "height": 844, "is_mobile": True}),
]


def main() -> None:
    errors_found: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()

        for name, route in ROUTES:
            for vp_name, vp_cfg in VIEWPORTS:
                context = browser.new_context(viewport=vp_cfg)
                page = context.new_page()

                console_errors: list[str] = []
                page.on("console", lambda msg: console_errors.append(f"[{msg.type}] {msg.text}") if msg.type in ("error", "warning") and "warn" not in msg.text.lower() else None)
                page.on("pageerror", lambda exc: console_errors.append(f"[pageerror] {exc}"))

                url = f"http://localhost:3000{route}"
                print(f"Navigating to {url} ({vp_name}px)...")
                try:
                    page.goto(url, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(1000)  # settle animations & client fetch
                except Exception as e:
                    print(f"Error navigating to {url}: {e}")
                    errors_found.append(f"{url} ({vp_name}): Navigation failed: {e}")
                    context.close()
                    continue

                # Take screenshot
                shot_path = SCREENS_DIR / f"{name}_{vp_name}.png"
                page.screenshot(path=str(shot_path), full_page=False)
                print(f"  Saved screenshot: {shot_path} ({shot_path.stat().st_size} bytes)")

                # If this is home, also duplicate to workspace for backward compatibility
                if name == "home":
                    ws_shot = SCREENS_DIR / f"workspace_{vp_name}.png"
                    page.screenshot(path=str(ws_shot), full_page=False)

                # Check console errors
                real_errors = [e for e in console_errors if "[error]" in e.lower() or "[pageerror]" in e.lower()]
                if real_errors:
                    print(f"  Console errors on {route} ({vp_name}px): {real_errors}")
                    errors_found.extend([f"{route} ({vp_name}): {err}" for err in real_errors])
                else:
                    print(f"  Clean: 0 console errors on {route} ({vp_name}px)")

                # If report route at 1440px, print to PDF
                if name == "report" and vp_name == "1440":
                    pdf_path = SCREENS_DIR / "report.pdf"
                    print(f"Printing /report to PDF at {pdf_path}...")
                    page.emulate_media(media="print")
                    page.pdf(
                        path=str(pdf_path),
                        format="A4",
                        print_background=True,
                        margin={"top": "15mm", "bottom": "15mm", "left": "15mm", "right": "15mm"},
                    )
                    print(f"  Saved PDF: {pdf_path} ({pdf_path.stat().st_size} bytes)")

                context.close()

        browser.close()

    print("=" * 60)
    if errors_found:
        print(f"FAILED: {len(errors_found)} console errors or failures detected:")
        for err in errors_found:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("SUCCESS: All routes verified at 1440px and 390px with ZERO console errors.")
        print(f"All screenshots and PDF successfully saved to {SCREENS_DIR}.")
        print("=" * 60)


if __name__ == "__main__":
    main()
