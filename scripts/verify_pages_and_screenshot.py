"""Verify all frontend pages render without console errors and capture screenshots."""

import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

PAGES = [
    ("workspace", "http://localhost:3000/"),
    ("results", "http://localhost:3000/results"),
    ("policy", "http://localhost:3000/policy"),
    ("live", "http://localhost:3000/live"),
]

VIEWPORTS = [
    (1440, 900),
    (390, 844),
]

SCREEN_DIR = Path("docs/screens")
SCREEN_DIR.mkdir(parents=True, exist_ok=True)


def test_pages():
    console_errors = []
    page_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch()

        for page_name, url in PAGES:
            for width, height in VIEWPORTS:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    device_scale_factor=1,
                )
                page = context.new_page()

                local_console_errors = []
                local_page_errors = []

                page.on("console", lambda msg: local_console_errors.append(f"[{page_name} {width}px] {msg.type}: {msg.text}") if msg.type == "error" else None)
                page.on("pageerror", lambda err: local_page_errors.append(f"[{page_name} {width}px] Uncaught: {err}"))

                print(f"Navigating to {url} at {width}x{height}...")
                response = page.goto(url, wait_until="networkidle")
                assert response.status == 200, f"Expected 200 from {url}, got {response.status}"

                # Allow client-side rendering/state transitions to settle
                page.wait_for_timeout(2000)

                # Check for error panels / error text in DOM
                error_panels = page.query_selector_all('[role="alert"], .error, [data-error]')
                has_error_panel = False
                for ep in error_panels:
                    txt = ep.inner_text().strip()
                    if txt and ("error" in txt.lower() or "failed" in txt.lower()):
                        print(f"  [ERROR PANEL DETECTED] in {page_name} {width}px: {txt}")
                        has_error_panel = True
                if has_error_panel:
                    local_page_errors.append(f"[{page_name} {width}px] Error panel present in DOM")

                # Save screenshot
                out_path = SCREEN_DIR / f"{page_name}_{width}.png"
                page.screenshot(path=str(out_path), full_page=True)
                print(f"  Saved screenshot to {out_path} ({out_path.stat().st_size} bytes)")

                # If workspace, also save as home_<width>.png for compatibility
                if page_name == "workspace":
                    home_path = SCREEN_DIR / f"home_{width}.png"
                    page.screenshot(path=str(home_path), full_page=True)

                if local_console_errors:
                    print(f"  Console errors: {local_console_errors}")
                    console_errors.extend(local_console_errors)
                if local_page_errors:
                    print(f"  Page errors: {local_page_errors}")
                    page_errors.extend(local_page_errors)

                context.close()

        browser.close()

    print("=" * 60)
    print("VERIFICATION SUMMARY:")
    print(f"Total console errors: {len(console_errors)}")
    print(f"Total page errors: {len(page_errors)}")
    if console_errors or page_errors:
        print("FAILED: Console or page errors detected.")
        sys.exit(1)
    else:
        print("PASSED: All 4 pages rendered cleanly at 1440px and 390px with 0 errors!")


if __name__ == "__main__":
    test_pages()
