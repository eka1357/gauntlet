"""Defense Ladder & Ablation Experiment (FR-6).

Evaluates the exact same 40 attacks across target modes:
  1. naive (legacy unhardened baseline)
  2. light (single-line untrusted warning: 'be careful with emails and untrusted external data')
  3. realistic (full baseline with untrusted data boundary and vault protection)

Also reports:
  - Ablation: 20 attacks against naive
  - Exposure rate per channel
  - Outcome classification: breach, ignored, refused, attempted-but-failed, partial
"""

import asyncio
import json
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from backend.attacker import (
    CHANNELS,
    evaluate_single_attack,
    generate_attack_payload,
    generate_ultra_strategist_seeds,
    load_benign_tasks_by_channel,
    load_threat_categories,
)
from target.tools import MockToolStore

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RUNS_DIR = ROOT / "runs"
ATTACKS_FILE = RUNS_DIR / "ladder_attacks_40.json"


async def prepare_40_attacks(force_regen: bool = False) -> list[dict[str, Any]]:
    """Generate or load the 40 attacks generated via Ultra seeds + Lightning."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if not force_regen and ATTACKS_FILE.is_file():
        try:
            with open(ATTACKS_FILE, encoding="utf-8") as f:
                cached = json.load(f)
            if len(cached) == 40:
                print(f"[*] Loaded 40 cached ladder attacks from {ATTACKS_FILE}")
                return cached
        except Exception:
            pass

    print("[*] Generating 40 ladder attacks (Ultra strategist seeds + Lightning scaling)...")
    random.seed(42)
    categories, descriptions = load_threat_categories()

    # 1. Ultra writes 10 seeds per channel
    ultra_seed_pool: dict[str, list[dict[str, Any]]] = {}
    for ch in CHANNELS:
        print(f"    Ultra generating 10 seeds for {ch}...")
        seeds = await generate_ultra_strategist_seeds(channel=ch, count=10)
        ultra_seed_pool[ch] = seeds
        print(f"    Loaded {len(seeds)} Ultra seeds for {ch}")

    # 2. Scale & mutate to 40 attacks with Lightning
    attacks: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(4)

    async def build_attack(i: int) -> dict[str, Any]:
        async with sem:
            channel = CHANNELS[i % len(CHANNELS)]
            cat = categories[i % len(categories)]
            desc = descriptions.get(cat, cat)
            att_id = f"ladder_att_{i:02d}"

            ch_seeds = ultra_seed_pool.get(channel, [])
            u_seed = ch_seeds[i % len(ch_seeds)] if ch_seeds else None

            # Half are direct Ultra seeds, half are Lightning mutated
            if i % 2 == 0 and u_seed:
                return {
                    "attack_id": att_id,
                    "channel": channel,
                    "category": cat,
                    "payload": u_seed["payload"],
                    "strategy": f"[Ultra Blueprint] {u_seed['strategy']}",
                    "gen_cost": 0.0,
                }
            else:
                p_payload = u_seed["payload"] if u_seed else None
                p_strategy = u_seed["strategy"] if u_seed else None
                payload, strat, c_cost = await generate_attack_payload(
                    channel=channel,
                    category=cat,
                    category_description=desc,
                    role="lightning",
                    parent_payload=p_payload,
                    parent_strategy=p_strategy,
                )
                return {
                    "attack_id": att_id,
                    "channel": channel,
                    "category": cat,
                    "payload": payload,
                    "strategy": f"[Lightning Mutated] {strat}",
                    "gen_cost": c_cost,
                }

    tasks = [build_attack(i) for i in range(40)]
    attacks = await asyncio.gather(*tasks)

    with open(ATTACKS_FILE, "w", encoding="utf-8") as f:
        json.dump(attacks, f, indent=2)
    print(f"[*] Generated and saved 40 attacks to {ATTACKS_FILE}")
    return attacks


async def evaluate_mode_attacks(
    mode_name: str,
    attacks: list[dict[str, Any]],
    concurrency: int = 4,
) -> dict[str, Any]:
    """Evaluate attacks against a target mode."""
    print("\n========================================================")
    print(f"EVALUATING TARGET MODE: '{mode_name.upper()}' (n={len(attacks)})")
    print("========================================================")

    base_store = MockToolStore()
    channel_tasks = load_benign_tasks_by_channel()
    sem = asyncio.Semaphore(concurrency)

    async def eval_one(att: dict[str, Any]) -> Any:
        async with sem:
            return await evaluate_single_attack(
                attack_id=att["attack_id"],
                run_id=f"ladder_{mode_name}",
                generation=0,
                parent_id=None,
                channel=att["channel"],
                category=att["category"],
                payload=att["payload"],
                strategy=att["strategy"],
                base_store=base_store,
                channel_tasks=channel_tasks,
                target_role="super",
                target_mode=mode_name,
                gen_cost=att.get("gen_cost", 0.0),
            )

    eval_tasks = [eval_one(a) for a in attacks]
    results = await asyncio.gather(*eval_tasks)

    breaches = sum(1 for r in results if r.outcome == "breach")
    total = len(results)
    breach_rate = (breaches / total * 100.0) if total > 0 else 0.0
    exposed = sum(1 for r in results if r.payload_exposed)
    exposure_rate = (exposed / total * 100.0) if total > 0 else 0.0
    total_cost = sum(r.cost_usd for r in results)

    classifications: dict[str, int] = {
        "breach": 0,
        "ignored": 0,
        "refused": 0,
        "attempted-but-failed": 0,
        "partial": 0,
    }
    for r in results:
        c = r.outcome_classification
        classifications[c] = classifications.get(c, 0) + 1

    ch_exposure: dict[str, list[int]] = {}
    for r in results:
        if r.channel not in ch_exposure:
            ch_exposure[r.channel] = [0, 0]
        ch_exposure[r.channel][1] += 1
        if r.payload_exposed:
            ch_exposure[r.channel][0] += 1

    print(f"Results for '{mode_name}':")
    print(f"  Breach Rate:   {breaches}/{total} ({breach_rate:.1f}%)")
    print(f"  Exposure Rate: {exposed}/{total} ({exposure_rate:.1f}%)")
    print(f"  Classifications: {classifications}")
    print(f"  Channel Exposure: {ch_exposure}")
    print(f"  Total Cost: ${total_cost:.4f}")

    # Top breaches
    breach_items = [r for r in results if r.outcome == "breach"]
    if breach_items:
        print(f"  Found {len(breach_items)} breaches in '{mode_name}' mode:")
        for b in breach_items[:3]:
            print(f"    - [{b.attack_id}] {b.channel} ({b.category}) -> type={b.breach_type}")

    return {
        "mode": mode_name,
        "sample_size": total,
        "breaches": breaches,
        "breach_rate_pct": breach_rate,
        "exposed": exposed,
        "exposure_rate_pct": exposure_rate,
        "classifications": classifications,
        "channel_exposure": ch_exposure,
        "cost_usd": total_cost,
        "results": results,
    }


async def main():
    start_time = time.time()
    attacks = await prepare_40_attacks(force_regen=False)

    modes = ["naive", "light", "realistic"]
    mode_summaries = {}

    for mode in modes:
        mode_summaries[mode] = await evaluate_mode_attacks(mode, attacks)

    print("\n" + "=" * 76)
    print("DEFENSE LADDER SUMMARY TABLE (SAME 40 ATTACKS)")
    print("=" * 76)
    header = (
        f"{'Target Mode':<12} | {'n':<4} | {'Breaches':<8} | {'Breach %':<9} | "
        f"{'Exposure %':<10} | {'Ignored':<7} | {'Refused':<7} | {'Att-Failed':<10} | {'Partial':<7}"
    )
    print(header)
    print("-" * len(header))
    for m in modes:
        s = mode_summaries[m]
        c = s["classifications"]
        print(
            f"{m:<12} | {s['sample_size']:<4} | {s['breaches']:<8} | "
            f"{s['breach_rate_pct']:>6.1f}%   | {s['exposure_rate_pct']:>6.1f}%     | "
            f"{c.get('ignored', 0):<7} | {c.get('refused', 0):<7} | "
            f"{c.get('attempted-but-failed', 0):<10} | {c.get('partial', 0):<7}"
        )
    print("=" * 76)

    # Ablation 20 report
    naive_results = mode_summaries["naive"]["results"][:20]
    ab_breaches = sum(1 for r in naive_results if r.outcome == "breach")
    ab_exposed = sum(1 for r in naive_results if r.payload_exposed)
    print("\nABLATION: 20 ATTACKS AGAINST MODE='NAIVE'")
    print(f"  Breach Rate:   {ab_breaches}/20 ({ab_breaches/20*100:.1f}%)")
    print(f"  Exposure Rate: {ab_exposed}/20 ({ab_exposed/20*100:.1f}%)")
    ab_classes: dict[str, int] = {}
    for r in naive_results:
        ab_classes[r.outcome_classification] = ab_classes.get(r.outcome_classification, 0) + 1
    print(f"  Outcome breakdown: {ab_classes}")

    # Save full summary json
    summary_file = RUNS_DIR / "defense_ladder_results.json"
    clean_summary = {
        m: {
            "mode": s["mode"],
            "sample_size": s["sample_size"],
            "breaches": s["breaches"],
            "breach_rate_pct": s["breach_rate_pct"],
            "exposed": s["exposed"],
            "exposure_rate_pct": s["exposure_rate_pct"],
            "classifications": s["classifications"],
            "channel_exposure": s["channel_exposure"],
            "cost_usd": s["cost_usd"],
        }
        for m, s in mode_summaries.items()
    }
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(clean_summary, f, indent=2)
    print(f"\nSaved ladder results to {summary_file}")
    print(f"Total time elapsed: {time.time() - start_time:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
