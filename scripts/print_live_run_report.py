import sqlite3
import json
from backend.verify import evaluate_trace_metrics
from target.vault import get_canary_tokens
from backend.oracle import DEFAULT_ALLOWLISTED_EGRESS
from backend.orchestrator import extract_policy_block_rule

conn = sqlite3.connect("runs/gauntlet.db")
c = conn.cursor()
c.execute("SELECT id, status, config_json, cost_usd, created_at FROM run WHERE id = 'run_f20138b11daf'")
row = c.fetchone()
print(f"Run: {row[0]} | Status: {row[1]} | Cost: ${row[3]:.4f} USD | Timestamp: {row[4]}")

c.execute("SELECT id, generation, channel, category, strategy, trace_json FROM attack WHERE run_id = 'run_f20138b11daf' ORDER BY rowid ASC")
attacks = c.fetchall()
unh = [a for a in attacks if a[1] == 0]
v2 = {a[0].replace('_v2',''): a for a in attacks if a[1] == 1}
canaries = get_canary_tokens()
allowlist = DEFAULT_ALLOWLISTED_EGRESS

print("-" * 90)
print(f"{'Attack ID':<20} | {'Category':<24} | {'Unhardened':<14} | {'Policy v2':<14} | {'Block Rule'}")
print("-" * 90)

all_v2_blocked = True
for a in unh:
    att_id, _, ch, cat, strat, t_raw = a
    v2_rec = v2.get(att_id)
    t_unh = json.loads(t_raw)
    m_unh = evaluate_trace_metrics(t_unh, canaries, allowlist)
    t_v2 = json.loads(v2_rec[5]) if v2_rec else []
    m_v2 = evaluate_trace_metrics(t_v2, canaries, allowlist)
    rule = extract_policy_block_rule(t_v2) or "None"

    unh_lbl = "UNSAFE" if m_unh["unsafe"] else "DEFENDED"
    v2_lbl = "UNSAFE" if m_v2["unsafe"] else "BLOCKED"
    print(f"{att_id:<20} | {cat:<24} | {unh_lbl:<14} | {v2_lbl:<14} | {rule}")

    if m_unh["unsafe"] and m_v2["unsafe"]:
        all_v2_blocked = False

print("-" * 90)
print(f"Policy v2 blocked 100% of unhardened unsafe attacks: {all_v2_blocked}")
conn.close()
