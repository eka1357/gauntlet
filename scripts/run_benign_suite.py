"""Run the benign task suite on the unhardened agent and report pass rate.

FR-4 requirement: pass rate must be at least 85%.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from dotenv import load_dotenv

from backend.eval_benign import run_benign_suite

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_benign_suite")


async def main() -> None:
    logger.info("Starting benign task suite execution on unhardened Inbox Assistant...")
    summary = await run_benign_suite(role="super")

    print("\n" + "=" * 70)
    print("BENIGN TASK SUITE EVALUATION RESULTS")
    print("=" * 70)
    print(f"Total tasks:   {summary['total']}")
    print(f"Passed:        {summary['passed']}")
    print(f"Failed:        {summary['failed']}")
    print(f"Pass rate:     {summary['pass_rate_pct']:.1f}%")
    print("-" * 70)

    for item in summary["results"]:
        status_str = "PASS" if item["passed"] else "FAIL"
        print(f"[{status_str}] {item['task_id']}: {item['title']}")
        if not item["passed"]:
            print(f"       Reason: {item['reason']}")

    print("=" * 70)

    # Save summary report
    out_path = (
        Path(__file__).resolve().parent.parent / "target" / "fixtures" / "benign_eval_report.json"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Saved evaluation report to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
