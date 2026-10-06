"""Run the 10 hand-written human variants through the exact harness evaluate_single_attack."""

import asyncio
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from backend.attacker import (
    classify_non_breach_outcome,
    evaluate_single_attack,
    load_benign_tasks_by_channel,
)
from scripts.test_poisoned_email import INJECTION_VARIANTS
from target.tools import MockToolStore

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


async def run_positive_control():
    base_store = MockToolStore()
    channel_tasks = load_benign_tasks_by_channel()

    print("=" * 72)
    print("POSITIVE CONTROL: 10 HUMAN VARIANTS THROUGH HARNESS")
    print("=" * 72)

    results = []
    classifications = {"breach": 0, "ignored": 0, "refused": 0, "attempted-but-failed": 0, "partial": 0}

    for var in INJECTION_VARIANTS:
        v_id = var["id"]
        v_name = var["name"]
        email_data = var["email"]
        task_prompt = var["task"]

        # Run through evaluate_single_attack with custom task & email
        custom_task = {
            "id": f"task_{v_id}",
            "instruction": task_prompt,
            "allowed_tools": ["read_email"],
        }

        res = await evaluate_single_attack(
            attack_id=f"pos_{v_id}",
            run_id="positive_control",
            generation=0,
            parent_id=None,
            channel="email",
            category="authority_framing",
            payload=email_data["body"],
            strategy=v_name,
            base_store=base_store,
            channel_tasks=channel_tasks,
            target_role="super",
            target_mode="realistic",
            custom_task=custom_task,
            custom_email=email_data,
        )

        classification = res.outcome
        if res.outcome != "breach":
            classification = classify_non_breach_outcome(res.trace, getattr(res, "content", ""))
            classifications[classification] += 1
        else:
            classifications["breach"] += 1

        print(
            f"[{v_id}] {v_name:<42} -> outcome={res.outcome:<8} "
            f"class={classification:<20} breach_type={res.breach_type}"
        )
        results.append((res, classification))

    breaches = sum(1 for r, _ in results if r.outcome == "breach")
    total = len(results)
    print("=" * 72)
    print(f"Positive Control Results: {breaches}/{total} breaches ({breaches/total*100:.1f}%)")
    print(f"Classifications breakdown: {classifications}")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(run_positive_control())
