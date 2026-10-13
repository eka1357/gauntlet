"""Accessibility, keyboard and reduced-motion audit of the static export (web/out).

Serves web/out with a plain stdlib HTTP server (no Next server, no backend),
then uses Playwright + axe-core (loaded from web/node_modules/axe-core) to:

* run axe on /, /results, /policy, /report, /live at 1440px and 390px wide,
* verify keyboard-only use of the Range (Tab to a square, Enter opens the
  drawer, Escape closes it, focus returns to the same square),
* verify prefers-reduced-motion is honoured (no running CSS animations or
  transitions longer than 10ms on the home page under reduced motion),
* record failed requests, console errors and any request leaving the origin.

Usage: py scripts/a11y_audit.py [--out runs/a11y/<label>.json] [--port 3100]
Exit code is non-zero if any serious/critical axe violation is found or the
keyboard check fails.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import sys
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "web" / "out"
AXE_JS = ROOT / "web" / "node_modules" / "axe-core" / "axe.min.js"
ROUTES = ["/", "/results/", "/policy/", "/report/", "/live/"]
WIDTHS = [(1440, 900), (390, 844)]


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # noqa: D401 - silence
        return


def start_static_server(port: int) -> http.server.ThreadingHTTPServer:
    """Serve web/out on 127.0.0.1:<port> in a daemon thread and return the server."""
    if not (OUT_DIR / "index.html").exists():
        raise SystemExit(f"Static export missing: {OUT_DIR}/index.html. Run the static build first.")
    handler = functools.partial(_QuietHandler, directory=str(OUT_DIR))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_axe(page: Any) -> list[dict[str, Any]]:
    """Inject axe-core into the page and return the violations list."""
    page.add_script_tag(path=str(AXE_JS))
    result = page.evaluate(
        "async () => await axe.run(document, {resultTypes: ['violations']})"
    )
    return [
        {
            "id": v["id"],
            "impact": v["impact"],
            "help": v["help"],
            "nodes": len(v["nodes"]),
            "targets": [n["target"] for n in v["nodes"][:5]],
            "summaries": sorted({(n.get("failureSummary") or "").split("\n")[-1].strip() for n in v["nodes"]})[:12],
        }
        for v in result["violations"]
    ]


def keyboard_check(page: Any, base: str) -> dict[str, Any]:
    """Tab to a Range square, open with Enter, close with Escape, check focus return."""
    page.goto(base + "/", wait_until="networkidle")
    try:
        page.wait_for_selector("[data-range-square]", timeout=15000, state="attached")
    except Exception:
        return {"pass": False, "steps": ["No element with data-range-square found (squares are not focusable elements)"]}
    steps: list[str] = []
    focused_id = None
    for i in range(80):
        page.keyboard.press("Tab")
        focused_id = page.evaluate(
            "() => document.activeElement && document.activeElement.getAttribute('data-range-square')"
        )
        if focused_id:
            steps.append(f"Tab x{i + 1} reached square {focused_id}")
            break
    if not focused_id:
        return {"pass": False, "steps": steps + ["No Range square reachable with Tab in 80 presses"]}
    page.keyboard.press("ArrowRight")
    focused_id = page.evaluate("() => document.activeElement.getAttribute('data-range-square')")
    steps.append(f"ArrowRight moved focus to {focused_id}")
    page.keyboard.press("Enter")
    try:
        page.wait_for_selector("[role=dialog]", timeout=5000)
        steps.append("Enter opened the drawer (role=dialog visible)")
    except Exception:
        return {"pass": False, "steps": steps + ["Enter did not open a dialog"]}
    in_dialog = page.evaluate("() => !!document.activeElement.closest('[role=dialog]')")
    steps.append(f"Focus moved into dialog: {in_dialog}")
    page.keyboard.press("Escape")
    page.wait_for_selector("[role=dialog]", state="detached", timeout=5000)
    steps.append("Escape closed the drawer")
    page.wait_for_timeout(100)
    back = page.evaluate(
        "() => document.activeElement && document.activeElement.getAttribute('data-range-square')"
    )
    steps.append(f"Focus after close: {back}")
    return {"pass": bool(in_dialog) and back == focused_id, "steps": steps}


def reduced_motion_check(browser: Any, base: str) -> dict[str, Any]:
    """Load / with prefers-reduced-motion and flip the condition switch; report long animations."""
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, reduced_motion="reduce")
    page = ctx.new_page()
    page.goto(base + "/", wait_until="networkidle")
    page.wait_for_timeout(800)
    page.get_by_role("button", name="Policy v2", exact=True).first.click()
    page.wait_for_timeout(50)
    long_anims = page.evaluate(
        """() => document.getAnimations()
              .map(a => ({name: a.animationName || a.transitionProperty || a.constructor.name,
                          dur: a.effect && a.effect.getComputedTiming().duration}))
              .filter(a => typeof a.dur === 'number' && a.dur > 10)"""
    )
    matches = page.evaluate("() => matchMedia('(prefers-reduced-motion: reduce)').matches")
    ctx.close()
    return {"pass": matches and len(long_anims) == 0, "media_matches": matches, "long_animations": long_anims}


def main() -> int:
    """Run the audit and write a JSON report; print a human-readable summary."""
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "runs" / "a11y" / "report.json"))
    parser.add_argument("--port", type=int, default=3100)
    args = parser.parse_args()

    server = start_static_server(args.port)
    base = f"http://127.0.0.1:{args.port}"
    report: dict[str, Any] = {"pages": [], "keyboard": None, "reduced_motion": None}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for width, height in WIDTHS:
                ctx = browser.new_context(viewport={"width": width, "height": height})
                for route in ROUTES:
                    page = ctx.new_page()
                    failed: list[str] = []
                    console_errors: list[str] = []
                    offsite: list[str] = []
                    page.on("response", lambda r, f=failed: f.append(f"{r.status} {r.url}") if r.status >= 400 else None)
                    page.on("console", lambda m, c=console_errors: c.append(m.text) if m.type == "error" else None)
                    page.on("request", lambda r, o=offsite: o.append(r.url) if not r.url.startswith(base) and not r.url.startswith("data:") else None)
                    page.goto(base + route, wait_until="networkidle")
                    page.wait_for_timeout(600)
                    violations = run_axe(page)
                    body_text = page.evaluate("() => document.body.innerText.trim().length")
                    report["pages"].append({
                        "route": route, "width": width, "violations": violations,
                        "failed_requests": failed, "console_errors": console_errors,
                        "offsite_requests": offsite, "body_text_chars": body_text,
                    })
                    page.close()
                ctx.close()
            kctx = browser.new_context(viewport={"width": 1440, "height": 900})
            report["keyboard"] = keyboard_check(kctx.new_page(), base)
            kctx.close()
            report["reduced_motion"] = reduced_motion_check(browser, base)
            browser.close()
    finally:
        server.shutdown()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    serious = 0
    for pg in report["pages"]:
        sc = [v for v in pg["violations"] if v["impact"] in ("serious", "critical")]
        serious += len(sc)
        print(f"{pg['route']:<10} {pg['width']:>4}px  text={pg['body_text_chars']:>5}  "
              f"violations={len(pg['violations'])} serious/critical={len(sc)}  "
              f"failed_req={len(pg['failed_requests'])} console_err={len(pg['console_errors'])} "
              f"offsite={len(pg['offsite_requests'])}")
        for v in pg["violations"]:
            print(f"    [{v['impact']}] {v['id']} x{v['nodes']}: {v['help']}")
        for f in pg["failed_requests"]:
            print(f"    FAILED {f}")
    print("Keyboard:", "PASS" if report["keyboard"]["pass"] else "FAIL")
    for s in report["keyboard"]["steps"]:
        print("   ", s)
    rm = report["reduced_motion"]
    print("Reduced motion:", "PASS" if rm["pass"] else "FAIL", rm)
    print(f"Report written to {out}")
    return 1 if serious or not report["keyboard"]["pass"] else 0


if __name__ == "__main__":
    sys.exit(main())
