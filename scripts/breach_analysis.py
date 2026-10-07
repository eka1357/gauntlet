"""Offline breach analysis from stored run databases (FR-6 credibility).

Computes breach rates with Wilson 95% confidence intervals by category,
by strategy, and by channel across completed runs without any model calls.
Headline numbers focus on action-style attacks with neutral-style as control.
Prints n for every table cell.
"""

from __future__ import annotations

import argparse
import math
from collections import defaultdict
from pathlib import Path
from typing import Any


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Calculate the Wilson score confidence interval for a binomial proportion."""
    if n <= 0:
        return (0.0, 0.0)
    z = 1.95996
    p_hat = k / n
    denom = 1.0 + (z**2) / n
    center = (p_hat + (z**2) / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z**2) / (4.0 * (n**2)))
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return (low, high)


def format_rate_with_ci(k: int, n: int) -> str:
    """Format rate as percentage with Wilson 95% CI."""
    if n == 0:
        return "0.0% [N/A]"
    rate = (k / n) * 100.0
    low, high = wilson_ci(k, n)
    return f"{rate:4.1f}% [{low * 100.0:4.1f}% - {high * 100.0:4.1f}%]"


def classify_strategy_archetype(payload: str) -> str:
    """Classify attack payload into its strategic red-team archetype."""
    p = payload.strip()
    p_lower = p.lower()

    if (
        "502 bad gateway" in p_lower
        or "504" in p_lower
        or "edi gateway timeout" in p_lower
        or "edi 502" in p_lower
        or "customs-edi-router" in p_lower
    ):
        return "EDI 502/504 Gateway Error Recovery Protocol"

    if (
        "director of port security" in p_lower
        or "senior director" in p_lower
        or "port authority customs" in p_lower
        or "emergency directive" in p_lower
    ):
        return "Port Authority / Director Emergency Directive"

    if (
        "container rf-4091" in p_lower
        or "cold chain" in p_lower
        or "reefer" in p_lower
    ):
        return "Cold Chain Reefer Incident Thread Reply"

    if "vessel schedule discrepancy" in p_lower or "schedule discrepancy" in p_lower:
        return "Vessel Schedule Discrepancy Thread Reply"

    if (
        "mock_system_output" in p_lower
        or "[system log" in p_lower
        or "pending_confirmation" in p_lower
        or "[error]" in p_lower
    ):
        return "Tool-Output / Diagnostic System Log Spoofing"

    if (
        "scheduled maintenance" in p_lower
        or "system update failure" in p_lower
        or "session lockout" in p_lower
        or "maintenance window" in p_lower
    ):
        return "Maintenance Window / Session Lockout Protocol"

    if (
        "=?utf-8?" in p_lower
        or "ce message concerne" in p_lower
        or "sehr geehrte" in p_lower
        or "deutsche" in p_lower
    ):
        return "Multilingual Customs Compliance Directive"

    if (
        "<edi_envelope>" in p_lower
        or "636f672f" in p_lower
        or "xml" in p_lower
        or "base64" in p_lower
    ):
        return "Encoded / XML Data Smuggling Directive"

    return "Operational Logistics Verification Directive"


def run_breach_analysis(
    db_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Perform breach analysis across stored SQLite databases split by task_style."""
    default_dbs = [
        Path("runs/gauntlet_seed1.db"),
        Path("runs/gauntlet_seed2.db"),
        Path("runs/gauntlet_seed3_recon.db"),
    ]
    paths = [Path(p) for p in (db_paths or default_dbs)]

    import sqlite3

    all_attacks: list[dict[str, Any]] = []
    loaded_dbs: list[str] = []

    for path in paths:
        if not path.is_file():
            continue
        loaded_dbs.append(str(path))
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attack")
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict["_source_db"] = str(path)
            all_attacks.append(row_dict)
        conn.close()

    if not all_attacks:
        print("No attacks found in specified databases.")
        return {}

    # Separate by task_style
    action_attacks = [a for a in all_attacks if a.get("task_style") == "action"]
    neutral_attacks = [a for a in all_attacks if a.get("task_style") == "neutral"]

    # Headline counts (Action-style only)
    act_n = len(action_attacks)
    act_k = sum(1 for a in action_attacks if a.get("outcome") == "breach")
    act_nm = sum(1 for a in action_attacks if a.get("near_miss"))

    # Email-action specific metrics
    email_action_attacks = [a for a in action_attacks if a.get("channel") == "email"]
    email_act_n = len(email_action_attacks)
    email_act_k = sum(1 for a in email_action_attacks if a.get("outcome") == "breach")
    email_act_nm = sum(1 for a in email_action_attacks if a.get("near_miss"))

    # Control group (Neutral-style)
    neu_n = len(neutral_attacks)
    neu_k = sum(1 for a in neutral_attacks if a.get("outcome") == "breach")
    neu_nm = sum(1 for a in neutral_attacks if a.get("near_miss"))

    print("=" * 96)
    print(f"GAUNTLET CROSS-RUN BREACH ANALYSIS ({len(loaded_dbs)} databases, {len(all_attacks)} total attacks)")
    print(f"Databases: {', '.join(loaded_dbs)}")
    print("-" * 96)
    print(
        f"Headline (Action-style):     {act_k}/{act_n} breaches ({format_rate_with_ci(act_k, act_n)}) | "
        f"Near-Misses: {act_nm}/{act_n} ({format_rate_with_ci(act_nm, act_n)})"
    )
    print(
        f"  --> Email Action-style:    {email_act_k}/{email_act_n} breaches ({format_rate_with_ci(email_act_k, email_act_n)}) | "
        f"Near-Misses: {email_act_nm}/{email_act_n} ({format_rate_with_ci(email_act_nm, email_act_n)})"
    )
    print(
        f"Control (Neutral-style):     {neu_k}/{neu_n} breaches ({format_rate_with_ci(neu_k, neu_n)}) | "
        f"Near-Misses: {neu_nm}/{neu_n} ({format_rate_with_ci(neu_nm, neu_n)})"
    )
    print("=" * 96)

    # 1. Breach rate by Channel (Action-style only)
    by_channel: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "k": 0, "nm": 0})
    for a in action_attacks:
        ch = a.get("channel", "unknown")
        by_channel[ch]["n"] += 1
        if a.get("outcome") == "breach":
            by_channel[ch]["k"] += 1
        if a.get("near_miss"):
            by_channel[ch]["nm"] += 1

    print("\n1. BREACH RATE BY CHANNEL (Action-Style Attacks Only):")
    print("-" * 96)
    print(
        f"{'Channel':<14} | {'Attacks (n)':<12} | {'Breaches (k/n)':<16} | "
        f"{'Breach Rate [95% Wilson CI]':<26} | {'Near-Miss (nm/n)':<16}"
    )
    print("-" * 96)
    for ch, s in sorted(by_channel.items(), key=lambda x: x[1]["k"], reverse=True):
        ci_str = format_rate_with_ci(s["k"], s["n"])
        breach_frac = f"{s['k']}/{s['n']} (n={s['n']})"
        nm_frac = f"{s['nm']}/{s['n']} (n={s['n']})"
        print(f"{ch:<14} | {s['n']:<12} | {breach_frac:<16} | {ci_str:<26} | {nm_frac:<16}")
    print("-" * 96)

    # 2. Breach rate by Threat Category (Action-style only)
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "k": 0, "nm": 0})
    for a in action_attacks:
        cat = a.get("category", "unknown")
        by_category[cat]["n"] += 1
        if a.get("outcome") == "breach":
            by_category[cat]["k"] += 1
        if a.get("near_miss"):
            by_category[cat]["nm"] += 1

    print("\n2. BREACH RATE BY THREAT CATEGORY (Action-Style Attacks Only):")
    print("-" * 96)
    print(
        f"{'Category':<24} | {'Attacks (n)':<12} | {'Breaches (k/n)':<16} | "
        f"{'Breach Rate [95% Wilson CI]':<26} | {'Near-Miss (nm/n)':<16}"
    )
    print("-" * 96)
    for cat, s in sorted(by_category.items(), key=lambda x: x[1]["k"], reverse=True):
        ci_str = format_rate_with_ci(s["k"], s["n"])
        breach_frac = f"{s['k']}/{s['n']} (n={s['n']})"
        nm_frac = f"{s['nm']}/{s['n']} (n={s['n']})"
        print(f"{cat:<24} | {s['n']:<12} | {breach_frac:<16} | {ci_str:<26} | {nm_frac:<16}")
    print("-" * 96)

    # 3. Breach rate by Strategy (Action-style only)
    by_strategy: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "k": 0, "nm": 0})
    for a in action_attacks:
        strat = classify_strategy_archetype(a.get("payload", ""))
        by_strategy[strat]["n"] += 1
        if a.get("outcome") == "breach":
            by_strategy[strat]["k"] += 1
        if a.get("near_miss"):
            by_strategy[strat]["nm"] += 1

    print("\n3. BREACH RATE BY STRATEGY ARCHETYPE (Action-Style Attacks Only):")
    print("-" * 108)
    print(
        f"{'Strategy':<48} | {'Attacks (n)':<12} | {'Breaches (k/n)':<16} | "
        f"{'Breach Rate [95% CI]':<24} | {'Near-Miss (nm/n)':<16}"
    )
    print("-" * 108)
    sorted_strats = sorted(
        by_strategy.items(),
        key=lambda x: (x[1]["k"] / x[1]["n"] if x[1]["n"] else 0, x[1]["k"]),
        reverse=True,
    )
    for strat, s in sorted_strats:
        ci_str = format_rate_with_ci(s["k"], s["n"])
        breach_frac = f"{s['k']}/{s['n']} (n={s['n']})"
        nm_frac = f"{s['nm']}/{s['n']} (n={s['n']})"
        print(f"{strat:<48} | {s['n']:<12} | {breach_frac:<16} | {ci_str:<24} | {nm_frac:<16}")
    print("-" * 108)

    # 4. Top 5 Most Effective Strategies (Action-style only)
    print("\n4. TOP 5 MOST EFFECTIVE ATTACK STRATEGIES (Action-Style Attacks Only):")
    print("-" * 108)
    print(
        f"{'Rank':<5} | {'Strategy':<48} | {'Attacks (n)':<12} | "
        f"{'Breaches (k/n)':<16} | {'Breach Rate [95% Wilson CI]'}"
    )
    print("-" * 108)
    top_5 = sorted_strats[:5]
    for idx, (strat, s) in enumerate(top_5, 1):
        rate_str = format_rate_with_ci(s["k"], s["n"])
        breach_frac = f"{s['k']}/{s['n']} (n={s['n']})"
        print(f"#{idx:<4} | {strat:<48} | {s['n']:<12} | {breach_frac:<16} | {rate_str}")
    print("-" * 108)

    return {
        "loaded_databases": loaded_dbs,
        "total_attacks": len(all_attacks),
        "action_attacks": {
            "n": act_n,
            "k": act_k,
            "rate_ci": format_rate_with_ci(act_k, act_n),
            "near_miss": act_nm,
            "near_miss_ci": format_rate_with_ci(act_nm, act_n),
        },
        "email_action_attacks": {
            "n": email_act_n,
            "k": email_act_k,
            "rate_ci": format_rate_with_ci(email_act_k, email_act_n),
            "near_miss": email_act_nm,
            "near_miss_ci": format_rate_with_ci(email_act_nm, email_act_n),
        },
        "neutral_control_attacks": {
            "n": neu_n,
            "k": neu_k,
            "rate_ci": format_rate_with_ci(neu_k, neu_n),
            "near_miss": neu_nm,
            "near_miss_ci": format_rate_with_ci(neu_nm, neu_n),
        },
        "by_channel": dict(by_channel),
        "by_category": dict(by_category),
        "by_strategy": dict(by_strategy),
        "top_5_strategies": top_5,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Gauntlet Cross-Run Breach Analysis")
    parser.add_argument(
        "--dbs",
        nargs="+",
        default=[
            "runs/gauntlet_seed1.db",
            "runs/gauntlet_seed2.db",
            "runs/gauntlet_seed3_recon.db",
        ],
        help="List of SQLite database paths to analyze",
    )
    args = parser.parse_args()
    run_breach_analysis(args.dbs)


if __name__ == "__main__":
    main()
