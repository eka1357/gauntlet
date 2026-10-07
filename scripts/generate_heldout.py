"""Generate Held-Out Evaluation Dataset (FR-10).

Requirements:
- Fresh seed
- Recon on (real Tavily intelligence via Ultra)
- 300 email-action attacks, 40 web-action, 40 document-action (total 380)
- Upfront cost estimation check: stop if exceeds $4.00
- Save identical payloads to fixtures/heldout.json
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sys
from pathlib import Path
from typing import Any

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.attacker import (
    generate_attack_payload,
    generate_ultra_strategist_seeds,
    load_threat_categories,
)
from backend.cost import get_ledger
from backend.recon import run_recon

logger = logging.getLogger("gauntlet.heldout")

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
HELDOUT_PATH = FIXTURES_DIR / "heldout.json"


def estimate_heldout_generation_cost(
    n_email: int = 300,
    n_web: int = 40,
    n_doc: int = 40,
) -> dict[str, float]:
    """Estimate token and dollar cost for generating the held-out set.

    Pricing (Token Factory):
    - Ultra: $1.00 / 1M in, $3.00 / 1M out
    - Lightning: $0.06 / 1M in, $0.24 / 1M out
    """
    total_payloads = n_email + n_web + n_doc

    # Ultra Recon: ~1.5k in, 0.8k out
    recon_cost = (1500 / 1e6 * 1.00) + (800 / 1e6 * 3.00)

    # Ultra Seeds: 3 calls * ~1.5k in, 1k out
    seeds_cost = 3 * ((1500 / 1e6 * 1.00) + (1000 / 1e6 * 3.00))

    # Lightning Payloads: total_payloads * ~500 in, 200 out
    lightning_cost = total_payloads * ((500 / 1e6 * 0.06) + (200 / 1e6 * 0.24))

    total_est = recon_cost + seeds_cost + lightning_cost

    return {
        "recon_est_usd": recon_cost,
        "seeds_est_usd": seeds_cost,
        "lightning_est_usd": lightning_cost,
        "total_estimated_usd": total_est,
    }


async def generate_heldout_dataset(
    n_email: int = 300,
    n_web: int = 40,
    n_doc: int = 40,
    seed: int = 42,
    force_regenerate: bool = False,
) -> list[dict[str, Any]]:
    """Generate 380 held-out attacks and save to fixtures/heldout.json."""
    if HELDOUT_PATH.is_file() and not force_regenerate:
        try:
            data = json.loads(HELDOUT_PATH.read_text(encoding="utf-8"))
            if len(data) == (n_email + n_web + n_doc):
                print(f"[heldout] Loaded {len(data)} existing attacks from {HELDOUT_PATH}")
                return data
        except Exception:
            pass

    random.seed(seed)

    # 1. Cost estimation check
    estimates = estimate_heldout_generation_cost(n_email, n_web, n_doc)
    total_est = estimates["total_estimated_usd"]
    print("=" * 60)
    print("HELDOUT GENERATION COST ESTIMATION")
    print(f"  Recon (Ultra):     ${estimates['recon_est_usd']:.4f}")
    print(f"  Seeds (Ultra):     ${estimates['seeds_est_usd']:.4f}")
    print(f"  Payloads (Lightning, n={n_email+n_web+n_doc}): ${estimates['lightning_est_usd']:.4f}")
    print(f"  TOTAL ESTIMATED:   ${total_est:.4f}")
    print("=" * 60)

    if total_est > 4.00:
        raise RuntimeError(
            f"Cost estimate ${total_est:.2f} exceeds strict $4.00 budget limit! Aborting."
        )

    ledger_start = get_ledger().total_cost_usd

    # 2. Run Recon (real Tavily search + Ultra threat planning)
    print("\n[heldout] Running reconnaissance with live Tavily intelligence...")
    threat_plan, credits_used, live_calls = await run_recon()
    print(
        f"[heldout] Recon complete: {len(threat_plan.hypotheses)} hypotheses, "
        f"{live_calls} live Tavily queries ({credits_used} credits)."
    )

    # 3. Generate Ultra strategist seeds
    print("[heldout] Generating seed attacks with Ultra strategist...")
    seeds_email = await generate_ultra_strategist_seeds("email", count=10, threat_plan=threat_plan)
    seeds_web = await generate_ultra_strategist_seeds("web_page", count=5, threat_plan=threat_plan)
    seeds_doc = await generate_ultra_strategist_seeds("document", count=5, threat_plan=threat_plan)
    print(
        f"[heldout] Seeds ready: {len(seeds_email)} email, {len(seeds_web)} web, {len(seeds_doc)} doc."
    )

    # 4. Generate held-out attacks across categories
    categories, descriptions = load_threat_categories()
    tasks_to_generate: list[dict[str, Any]] = []

    # Distribution specification
    channel_counts = [
        ("email", n_email, seeds_email),
        ("web_page", n_web, seeds_web),
        ("document", n_doc, seeds_doc),
    ]

    attack_counter = 1
    for channel, count, seeds in channel_counts:
        for i in range(count):
            cat = categories[i % len(categories)]
            cat_desc = descriptions.get(cat, cat)
            parent_seed = seeds[i % len(seeds)] if seeds else None
            tasks_to_generate.append(
                {
                    "attack_id": f"heldout_{attack_counter:04d}",
                    "channel": channel,
                    "category": cat,
                    "category_description": cat_desc,
                    "parent_payload": parent_seed.get("payload") if parent_seed else None,
                    "parent_strategy": parent_seed.get("strategy") if parent_seed else None,
                }
            )
            attack_counter += 1

    print(f"\n[heldout] Generating {len(tasks_to_generate)} attack payloads via Lightning swarm...")
    sem = asyncio.Semaphore(10)

    async def _gen_one(spec: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            try:
                payload, strategy, _ = await generate_attack_payload(
                    channel=spec["channel"],
                    category=spec["category"],
                    category_description=spec["category_description"],
                    role="lightning",
                    parent_payload=spec["parent_payload"],
                    parent_strategy=spec["parent_strategy"],
                )
            except Exception as e:
                logger.warning("Generation error for %s: %s", spec["attack_id"], e)
                # Fallback to parent seed payload
                payload = spec["parent_payload"] or "Error payload"
                strategy = spec["parent_strategy"] or spec["category"]

            return {
                "id": spec["attack_id"],
                "channel": spec["channel"],
                "category": spec["category"],
                "strategy": strategy,
                "payload": payload,
                "task_style": "action",
            }

    results = await asyncio.gather(*[_gen_one(s) for s in tasks_to_generate])

    # Save to fixtures/heldout.json
    HELDOUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    HELDOUT_PATH.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    total_actual_cost = get_ledger().total_cost_usd - ledger_start
    print(f"[heldout] Successfully generated {len(results)} attacks.")
    print(f"[heldout] Saved to: {HELDOUT_PATH}")
    print(f"[heldout] Actual Generation Cost: ${total_actual_cost:.4f}\n")

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(generate_heldout_dataset(force_regenerate=True))
