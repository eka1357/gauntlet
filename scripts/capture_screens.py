import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def capture():
    out_dir = Path("docs/screens")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        
        # 1440 px desktop viewport
        page = await browser.new_page(viewport={"width": 1440, "height": 900})
        await page.goto("http://localhost:3000/results", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(out_dir / "results_1440.png"), full_page=True)
        print("Captured docs/screens/results_1440.png")
        
        # 390 px mobile viewport (iPhone 12/13/14 width)
        page_mobile = await browser.new_page(viewport={"width": 390, "height": 844})
        await page_mobile.goto("http://localhost:3000/results", wait_until="networkidle")
        await page_mobile.wait_for_timeout(2000)
        await page_mobile.screenshot(path=str(out_dir / "results_390.png"), full_page=True)
        print("Captured docs/screens/results_390.png")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(capture())
