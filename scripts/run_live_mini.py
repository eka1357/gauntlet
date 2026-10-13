"""Execute ONE real live run against the target agent (naive mode, 6 attacks, compare with v2)."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any

from dotenv import load_dotenv

# 1. Load environment variables through code (never open, read, or print .env)
load_dotenv()

# 2. Set LIVE_RUNS_ENABLED=true for this process only
os.environ["LIVE_RUNS_ENABLED"] = "true"

import httpx
import uvicorn
from sqlmodel import Session, select

from backend.api import app, get_daily_live_spend
from backend.models import Attack, Run, init_db


def run_live_mini_demo() -> None:
    n_attacks = 6
    target_mode = "naive"
    compare_v2 = True
    estimated_cost_usd = 0.0280

    print("=" * 64)
    print("GAUNTLET LIVE RUN: PRE-FLIGHT COST CHECK")
    print("=" * 64)
    print(f"  Target mode:            {target_mode}")
    print(f"  Number of attacks:      {n_attacks}")
    print(f"  Compare with Policy v2: {compare_v2}")
    print(f"  Estimated cost:         ~${estimated_cost_usd:.4f} USD (expected ~$0.03)")
    print("  Budget cap:             $0.0500 USD")
    print("  LIVE_RUNS_ENABLED:      true (for this process only)")
    print("=" * 64)

    # Check spend ledger before run
    spend_before = get_daily_live_spend()
    print(f"\n[*] Daily live spend before run: ${spend_before:.5f}")

    # Start uvicorn server in a background thread on 127.0.0.1:8009
    port = 8009
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # Wait for server to start
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            r = httpx.get(f"{base_url}/api/health", timeout=2.0)
            if r.status_code == 200:
                print("[*] Local server started and healthy.")
                break
        except Exception:
            time.sleep(0.2)
    else:
        print("[!] Server failed to start within timeout.")
        server.should_exit = True
        sys.exit(1)

    try:
        # 3. POST /api/runs with n_attacks=6, target_mode="naive", compare_v2=True
        print(f"\n[*] Sending POST /api/runs (n_attacks={n_attacks}, target_mode='{target_mode}', compare_v2={compare_v2})...")
        resp = httpx.post(
            f"{base_url}/api/runs",
            json={
                "n_attacks": n_attacks,
                "compare_v2": compare_v2,
                "target_mode": target_mode,
            },
            timeout=10.0,
        )
        if resp.status_code != 200:
            print(f"[!] POST /api/runs failed: {resp.status_code} - {resp.text}")
            sys.exit(1)

        post_data = resp.json()
        run_id = post_data["run_id"]
        print(f"[*] Run initiated successfully. Run ID: {run_id}")

        # 4. Connect to and consume the SSE stream
        events_url = f"{base_url}/api/runs/{run_id}/events"
        print(f"[*] Streaming SSE events from {events_url}...\n")

        event_order: list[str] = []
        attacks_results: list[dict[str, Any]] = []
        final_summary: dict[str, Any] = {}
        total_cost = 0.0

        with httpx.stream("GET", events_url, timeout=300.0) as sse_stream:
            current_event = ""
            for line in sse_stream.iter_lines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("event:"):
                    current_event = line.replace("event:", "").strip()
                elif line.startswith("data:") and current_event:
                    data_str = line.replace("data:", "").strip()
                    try:
                        data = json.loads(data_str)
                    except Exception:
                        data = {"raw": data_str}

                    event_order.append(current_event)

                    if current_event == "attack_started":
                        print(
                            f"[STARTED #{data.get('index', 0) + 1}] "
                            f"{data.get('attack_id')} | "
                            f"channel: {data.get('channel')} | "
                            f"category: {data.get('category')}"
                        )
                    elif current_event == "attack_finished":
                        att_id = data.get("attack_id")
                        unh = data.get("unhardened", {})
                        v2 = data.get("v2", {})
                        cost = data.get("cost_usd", 0.0)
                        total_cost += cost

                        res_item = {
                            "attack_id": att_id,
                            "channel": data.get("channel"),
                            "category": data.get("category"),
                            "unhardened_outcome": unh.get("outcome"),
                            "unhardened_unsafe": unh.get("metrics", {}).get("unsafe", False),
                            "v2_outcome": v2.get("outcome"),
                            "v2_unsafe": v2.get("metrics", {}).get("unsafe", False),
                            "v2_block_rule": v2.get("policy_block_rule"),
                            "cost_usd": cost,
                        }
                        attacks_results.append(res_item)

                        unh_flag = "UNSAFE" if res_item["unhardened_unsafe"] else "Defended"
                        v2_flag = "UNSAFE" if res_item["v2_unsafe"] else (f"Blocked ({res_item['v2_block_rule']})" if res_item['v2_block_rule'] else "Defended")
                        print(
                            f"  -> Finished {att_id}: Unhardened={unh_flag} | "
                            f"Policy v2={v2_flag} | Cost=+${cost:.4f} (Cumulative: ${total_cost:.4f})"
                        )

                        # Per-run budget safety check
                        if total_cost > 0.05:
                            print("[!] Cumulative cost reached budget cap of $0.0500! Stopping.")
                            break

                    elif current_event == "run_complete":
                        final_summary = data
                        print(f"\n[RUN COMPLETE] Status: {data.get('status')}")
                        print(f"  Attacks evaluated:   {data.get('attacks_evaluated')}")
                        print(f"  Unhardened unsafe:   {data.get('unhardened_unsafe', data.get('unhardened_breaches', 0))}")
                        print(f"  Policy v2 unsafe:    {data.get('v2_unsafe', data.get('v2_breaches', 0))}")
                        print(f"  Total actual cost:   ${data.get('total_cost_usd', total_cost):.5f} USD")
                        break
                    elif current_event == "run_error":
                        print(f"\n[RUN ERROR] Error: {data}")
                        break

                    current_event = ""

        # 5. Spend ledger confirmation
        spend_after = get_daily_live_spend()
        print("\n" + "=" * 64)
        print("SPEND ACCOUNTING & DATABASE PERSISTENCE")
        print("=" * 64)
        print(f"  Daily spend before run: ${spend_before:.5f}")
        print(f"  Daily spend after run:  ${spend_after:.5f}")
        print(f"  Run incremental cost:   ${spend_after - spend_before:.5f}")

        # Verify DB records
        engine = init_db("runs/gauntlet.db")
        with Session(engine) as session:
            db_run = session.get(Run, run_id)
            db_attacks = session.exec(select(Attack).where(Attack.run_id == run_id)).all()
            print(f"  SQLite Run ID:          {db_run.id if db_run else 'NOT FOUND'}")
            print(f"  SQLite Run Cost:        ${db_run.cost_usd:.5f}" if db_run else "")
            print(f"  SQLite Attacks Count:   {len(db_attacks)}")

        print("\n" + "=" * 64)
        print("LIVE RUN OUTCOMES TABLE")
        print("=" * 64)
        print(f"{'Attack ID':<18} {'Channel':<12} {'Category':<22} {'Unhardened':<14} {'Policy v2':<26} {'Cost (USD)':<10}")
        print("-" * 102)
        for a in attacks_results:
            unh_s = "UNSAFE" if a['unhardened_unsafe'] else "Defended"
            v2_s = "UNSAFE" if a['v2_unsafe'] else (f"Blocked ({a['v2_block_rule']})" if a['v2_block_rule'] else "Defended")
            print(f"{a['attack_id']:<18} {a['channel']:<12} {a['category']:<22} {unh_s:<14} {v2_s:<26} ${a['cost_usd']:.4f}")
        print("-" * 102)
        actual_cost = final_summary.get('total_cost_usd', total_cost)
        print(f"Total Actual Cost: ${actual_cost:.5f} USD (Estimated: ~${estimated_cost_usd:.4f})")
        print(f"Budget Cap ($0.0500) Respected: {actual_cost <= 0.05}")
        print("=" * 64)

    finally:
        server.should_exit = True
        t.join(timeout=3.0)
        print("\n[*] Server shutdown complete.")


if __name__ == "__main__":
    run_live_mini_demo()
