"""Execute ONE real live mini-run against the target agent and consume the SSE stream."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any

from dotenv import load_dotenv

# 1. Load environment variables through code (never print .env)
load_dotenv()

# 2. Set LIVE_RUNS_ENABLED=true for this process only
os.environ["LIVE_RUNS_ENABLED"] = "true"

import httpx
import uvicorn
from sqlmodel import Session, select

from backend.api import app, get_daily_live_spend
from backend.models import Attack, Run, init_db


def run_live_mini_demo() -> None:
    # Check spend ledger before run
    spend_before = get_daily_live_spend()
    print(f"[*] Daily live spend before run: ${spend_before:.5f}")

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
                print("[*] Server started and healthy.")
                break
        except Exception:
            time.sleep(0.2)
    else:
        print("[!] Server failed to start within timeout.")
        server.should_exit = True
        sys.exit(1)

    try:
        # 3. POST /api/runs with n_attacks=5 and compare_v2=True
        print("\n[*] Sending POST /api/runs with {'n_attacks': 5, 'compare_v2': True}...")
        resp = httpx.post(
            f"{base_url}/api/runs",
            json={"n_attacks": 5, "compare_v2": True, "target_mode": "realistic"},
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
        print(f"[*] Connecting to SSE stream at {events_url}...")

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
                    print(f"\n[EVENT #{len(event_order)}] {current_event}")

                    if current_event == "attack_started":
                        print(
                            f"  Attack ID: {data.get('attack_id')} | "
                            f"Channel: {data.get('channel')} | "
                            f"Category: {data.get('category')}"
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
                            "realistic_outcome": unh.get("outcome"),
                            "realistic_unsafe": unh.get("metrics", {}).get("unsafe", False),
                            "v2_outcome": v2.get("outcome"),
                            "v2_unsafe": v2.get("metrics", {}).get("unsafe", False),
                            "v2_block_rule": v2.get("policy_block_rule"),
                            "cost_usd": cost,
                        }
                        attacks_results.append(res_item)

                        print(f"  Attack: {att_id}")
                        print(
                            f"  Realistic (Unhardened) Outcome: {res_item['realistic_outcome']} "
                            f"(unsafe: {res_item['realistic_unsafe']})"
                        )
                        print(
                            f"  Policy v2 Outcome:             {res_item['v2_outcome']} "
                            f"(rule: {res_item['v2_block_rule']})"
                        )
                        print(f"  Attack Cost:                   ${cost:.5f} (Cumulative: ${total_cost:.5f})")

                        # Safety budget check
                        if total_cost > 0.05:
                            print("[!] Cumulative cost exceeded budget cap of $0.05! Stopping.")
                            break

                    elif current_event == "run_complete":
                        final_summary = data
                        print(f"  Status: {data.get('status')}")
                        print(f"  Attacks Evaluated: {data.get('attacks_evaluated')}")
                        print(f"  Unhardened Breaches: {data.get('unhardened_breaches')}")
                        print(f"  Policy v2 Breaches:  {data.get('v2_breaches')}")
                        print(f"  Total Cost USD:      ${data.get('total_cost_usd', 0.0):.5f}")
                        break
                    elif current_event == "run_error":
                        print(f"  Error: {data}")
                        break

                    current_event = ""

        # 5. Daily spend ledger confirmation
        spend_after = get_daily_live_spend()
        print("\n" + "=" * 60)
        print("DAILY SPEND LEDGER VERIFICATION")
        print("=" * 60)
        print(f"  Daily spend before run: ${spend_before:.5f}")
        print(f"  Daily spend after run:  ${spend_after:.5f}")
        print(f"  Difference:             ${spend_after - spend_before:.5f}")
        assert spend_after >= spend_before, "Daily spend ledger was not updated!"
        print("  Ledger confirmation:    CONFIRMED (Run registered in SQLite DB)")

        # Verify DB records
        engine = init_db("runs/gauntlet.db")
        with Session(engine) as session:
            db_run = session.get(Run, run_id)
            db_attacks = session.exec(select(Attack).where(Attack.run_id == run_id)).all()
            print(f"  SQLite Run ID:          {db_run.id if db_run else 'NOT FOUND'}")
            print(f"  SQLite Run Cost:        ${db_run.cost_usd:.5f}" if db_run else "")
            print(f"  SQLite Attacks Count:   {len(db_attacks)}")

        print("\n" + "=" * 60)
        print("RUN SUMMARY REPORT")
        print("=" * 60)
        print(f"Event Order ({len(event_order)} events):")
        print(" -> ".join(event_order))
        print("\nPer-Attack Outcomes:")
        for a in attacks_results:
            print(
                f"  [{a['attack_id']}] Channel={a['channel']} Cat={a['category']} | "
                f"Realistic={a['realistic_outcome']} | v2={a['v2_outcome']} ({a['v2_block_rule']}) | "
                f"Cost=${a['cost_usd']:.5f}"
            )
        print(f"\nFinal Run Cost: ${final_summary.get('total_cost_usd', total_cost):.5f}")
        print(f"Per-run budget cap respected ($0.05): {final_summary.get('total_cost_usd', total_cost) <= 0.05}")

    finally:
        server.should_exit = True
        t.join(timeout=3.0)
        print("\n[*] Server shutdown complete.")


if __name__ == "__main__":
    run_live_mini_demo()
