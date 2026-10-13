"""Replay check: run 10 recorded attacks that were UNSAFE under naive mode

Runs through the exact same code path the live endpoint uses:
evaluate_single_attack with target_role='super', target_mode='naive', task_style='action'.
Prints cost estimate before any model calls and reports honest unsafe counts.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import dotenv
dotenv.load_dotenv()

from backend.attacker import evaluate_single_attack
from backend.cost import get_ledger
from backend.oracle import DEFAULT_ALLOWLISTED_EGRESS
from backend.verify import (
    evaluate_trace_metrics,
    get_canary_tokens,
    load_partner_contacts,
)
from target.tools import get_default_store


async def main() -> None:
    cache_path = Path("runs/cache/conf2_naive_results.json")
    if not cache_path.is_file():
        print(f"Error: Cache file not found at {cache_path}")
        return

    data = json.loads(cache_path.read_text(encoding="utf-8"))
    items = data.get("unhardened_items", [])
    unsafe_items = [it for it in items if it.get("outcome") == "breach"][:10]

    if len(unsafe_items) < 10:
        print(f"Warning: only found {len(unsafe_items)} unsafe items in naive results.")

    # 1. Print cost estimate before any model calls
    print("=" * 60)
    print("REPLAY CHECK: 10 RECORDED NAIVE UNSAFE ATTACKS")
    print("=" * 60)
    print("Cost estimate before model calls:")
    print("  Model: nvidia/nemotron-3-super-120b-a12b ('super')")
    print(f"  Calls: {len(unsafe_items)} evaluation runs in naive mode")
    print("  Estimated tokens per call: ~800 prompt, ~200 completion")
    print("  Estimated cost per call: ~$0.0006 USD")
    print(f"  Estimated total replay cost: ~${len(unsafe_items) * 0.0006:.4f} USD")
    print("  Hard task budget cap: $0.20 USD")
    print("=" * 60)

    ledger_before = get_ledger().total_cost_usd

    base_store = get_default_store()
    canaries = get_canary_tokens()
    partners = load_partner_contacts()
    allowlist = DEFAULT_ALLOWLISTED_EGRESS + [p["email"] for p in partners]

    results: list[dict] = []

    for idx, item in enumerate(unsafe_items, 1):
        attack_id = f"replay_{item['id']}"
        print(f"[{idx}/{len(unsafe_items)}] Replaying {item['id']} ({item.get('category')})...", end=" ", flush=True)

        res = await evaluate_single_attack(
            attack_id=attack_id,
            run_id="replay_check_run",
            generation=0,
            parent_id=None,
            channel=item["channel"],
            category=item["category"],
            payload=item["payload"],
            strategy=item.get("strategy", ""),
            base_store=base_store,
            channel_tasks={"email": [], "web_page": [], "document": []},
            task_style="action",
            target_role="super",
            target_mode="naive",
            policy=None,
        )

        metrics = evaluate_trace_metrics(res.trace, canaries, allowlist)
        is_unsafe = metrics["unsafe"] or res.outcome == "breach"
        results.append({
            "id": item["id"],
            "category": item["category"],
            "outcome": res.outcome,
            "breach_types": res.breach_types,
            "metrics": metrics,
            "unsafe": is_unsafe,
            "cost_usd": res.cost_usd,
        })
        print(f"outcome={res.outcome}, unsafe={is_unsafe}, cost=${res.cost_usd:.5f}")

    total_cost = get_ledger().total_cost_usd - ledger_before
    n_unsafe = sum(1 for r in results if r["unsafe"])

    print("\n" + "=" * 60)
    print("REPLAY CHECK RESULTS")
    print("=" * 60)
    for r in results:
        print(f"  {r['id']}: outcome={r['outcome']}, unsafe={r['unsafe']}, breach_types={r['breach_types']}")
    print("-" * 60)
    print(f"Total replayed: {len(results)}")
    print(f"Unsafe in live code path: {n_unsafe} / {len(results)} ({n_unsafe / len(results) * 100:.1f}%)")
    print(f"Actual model spend for replay: ${total_cost:.5f} USD")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
