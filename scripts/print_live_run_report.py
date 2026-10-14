import json
import sqlite3
import sys
from backend.oracle import DEFAULT_ALLOWLISTED_EGRESS
from backend.orchestrator import extract_policy_block_rule
from backend.verify import evaluate_trace_metrics
from target.vault import get_canary_tokens


def main():
    db_path = "runs/gauntlet.db"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    target_run_id = sys.argv[1] if len(sys.argv) > 1 else None

    if target_run_id:
        c.execute(
            "SELECT id, status, config_json, cost_usd, created_at FROM run WHERE id = ?",
            (target_run_id,),
        )
    else:
        c.execute(
            "SELECT id, status, config_json, cost_usd, created_at FROM run ORDER BY rowid DESC LIMIT 1"
        )

    row = c.fetchone()
    if not row:
        print("No runs found in database.")
        sys.exit(1)

    run_id, status, config_json, cost_usd, created_at = row
    config = json.loads(config_json) if config_json else {}

    c.execute(
        "SELECT id, generation, channel, category, strategy, trace_json, latency_ms, cost_usd "
        "FROM attack WHERE run_id = ? ORDER BY rowid ASC",
        (run_id,),
    )
    attacks = c.fetchall()

    unh = [a for a in attacks if a[1] == 0]
    v2 = {a[0].replace("_v2", ""): a for a in attacks if a[1] == 1}

    canaries = get_canary_tokens()
    allowlist = DEFAULT_ALLOWLISTED_EGRESS

    # Estimate duration from attack latencies or trace timestamps
    total_latency_sec = sum(a[6] for a in attacks) / 1000.0

    print("=" * 95)
    print("GAUNTLET: LIVE RUN RESULTS AUDIT")
    print("=" * 95)
    print(f"Run ID:       {run_id}")
    print(f"Status:       {status}")
    print(f"Created At:   {created_at}")
    print(f"Target Mode:  {config.get('target_mode', 'realistic')}")
    print(f"Attacks:      {len(unh)} unhardened pairs ({len(attacks)} total executions)")
    print(f"Total Cost:   ${cost_usd:.4f} USD")
    print(f"Total Time:   {total_latency_sec:.1f}s (execution latency)")
    print("-" * 95)
    print(
        f"{'Attack ID':<22} | {'Category':<22} | {'Unhardened':<12} | {'Policy v2':<12} | {'V2 Block Rule'}"
    )
    print("-" * 95)

    all_v2_blocked = True
    unh_unsafe_count = 0
    v2_unsafe_count = 0

    for a in unh:
        att_id, _, ch, cat, strat, t_raw, lat, att_cost = a
        v2_rec = v2.get(att_id)
        t_unh = json.loads(t_raw) if t_raw else []
        m_unh = evaluate_trace_metrics(t_unh, canaries, allowlist)

        t_v2 = json.loads(v2_rec[5]) if v2_rec and v2_rec[5] else []
        m_v2 = evaluate_trace_metrics(t_v2, canaries, allowlist)
        rule = extract_policy_block_rule(t_v2) or "None"

        unh_lbl = "UNSAFE" if m_unh["unsafe"] else "DEFENDED"
        v2_lbl = "UNSAFE" if m_v2["unsafe"] else ("BLOCKED" if rule != "None" else "DEFENDED")

        if m_unh["unsafe"]:
            unh_unsafe_count += 1
        if m_v2["unsafe"]:
            v2_unsafe_count += 1

        print(f"{att_id:<22} | {cat:<22} | {unh_lbl:<12} | {v2_lbl:<12} | {rule}")

        if m_unh["unsafe"] and m_v2["unsafe"]:
            all_v2_blocked = False

    print("-" * 95)
    print(
        f"Summary: {unh_unsafe_count}/{len(unh)} unsafe unhardened; "
        f"{v2_unsafe_count}/{len(unh)} unsafe under Policy v2."
    )
    print(f"Policy v2 blocked 100% of unhardened unsafe attacks: {all_v2_blocked}")
    print("=" * 95)

    conn.close()


if __name__ == "__main__":
    main()
