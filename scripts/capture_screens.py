import asyncio
from pathlib import Path
from playwright.async_api import async_playwright


async def capture():
    out_dir = Path("docs/screens")
    out_dir.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch()

        # 1. Desktop 1440px - Workspace Unhardened
        page = await browser.new_page(viewport={"width": 1440, "height": 960})
        await page.goto("http://localhost:3000/", wait_until="networkidle")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=str(out_dir / "range_unhardened.png"), full_page=True)
        print("Captured docs/screens/range_unhardened.png")

        # 2. Desktop 1440px - Switch to Policy v1
        v1_button = page.locator("button:has-text('Policy v1')").first
        await v1_button.click()
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(out_dir / "range_v1.png"), full_page=True)
        print("Captured docs/screens/range_v1.png")

        # 3. Desktop 1440px - Switch to Policy v2 (checks wipe animation)
        # First switch back to unhardened so we can watch the wipe from unhardened -> v2
        unhardened_button = page.locator("button:has-text('Unhardened')").first
        await unhardened_button.click()
        await page.wait_for_timeout(500)

        v2_button = page.locator("button:has-text('Policy v2')").first
        await v2_button.click()
        # Wait 1.5s for the 900ms wipe animation to complete smoothly
        await page.wait_for_timeout(1500)
        await page.screenshot(path=str(out_dir / "range_v2.png"), full_page=True)
        print("Captured docs/screens/range_v2.png")

        # 4. Open Drawer by clicking a square that had been unsafe
        # Click on one of the squares in the SVG grid
        first_square = page.locator("svg[role='grid'] g[role='gridcell']").first
        await first_square.click()
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(out_dir / "range_drawer.png"), full_page=True)
        print("Captured docs/screens/range_drawer.png")

        # 5. Mobile 390px - Workspace
        page_mobile = await browser.new_page(viewport={"width": 390, "height": 844})
        await page_mobile.goto("http://localhost:3000/", wait_until="networkidle")
        await page_mobile.wait_for_timeout(1500)
        await page_mobile.screenshot(path=str(out_dir / "workspace_390.png"), full_page=True)
        print("Captured docs/screens/workspace_390.png")

        # 6. Desktop & Mobile Results page
        await page.goto("http://localhost:3000/results", wait_until="networkidle")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=str(out_dir / "results_1440.png"), full_page=True)
        print("Captured docs/screens/results_1440.png")

        await page_mobile.goto("http://localhost:3000/results", wait_until="networkidle")
        await page_mobile.wait_for_timeout(1500)
        await page_mobile.screenshot(path=str(out_dir / "results_390.png"), full_page=True)
        print("Captured docs/screens/results_390.png")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(capture())
