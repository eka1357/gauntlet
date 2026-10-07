"""Benign variance and Naive-mode confirmation evaluation (Prompt 6).

Executes:
1. Benign variance: 35-task suite run 3 times each for:
   (a) Unhardened baseline
   (b) Policy v2
   Reports pass rate per run, pooled pass rate with Wilson 95% CI, per-task failure counts,
   flags any task failing only under v2, and inspects traces for policy blocks vs model variation.
2. Naive-mode confirmation on confirmation_set2 (standard 190 attacks only):
   Unhardened vs Policy v2 on naive target mode.
   Reports M1, M2, M3, M4, UNSAFE with n=190 and Wilson 95% CI.
3. Per-attack persistence:
   Rebuilds runs/recorded_run.json from checkpoints with id, channel, category, strategy, payload,
   and for each condition (unhardened, v1, v2) the outcome, M1-M4 flags, policy_block rule, and trace.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
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

import yaml

from backend.attacker import (
    evaluate_single_attack,
    wilson_ci,
    format_rate_with_ci,
    intervals_overlap,
)
from backend.cost import get_ledger
from backend.defender import load_partner_contacts
from backend.eval_benign import run_benign_suite
from backend.oracle import DEFAULT_ALLOWLISTED_EGRESS
from backend.verify import evaluate_trace_metrics
from target.tools import get_default_store
from target.vault import get_canary_tokens

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gauntlet.variance_naive")

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT_DIR / "fixtures"
RUNS_DIR = ROOT_DIR / "runs"
CACHE_DIR = RUNS_DIR / "cache"

POLICY_V2_PATH = FIXTURES_DIR / "policy_v2.yaml"
CONFIRMATION_V2_PATH = FIXTURES_DIR / "confirmation_set2.json"
BENIGN_TASKS_PATH = FIXTURES_DIR / "benign_tasks.yaml"
RECORDED_RUN_PATH = RUNS_DIR / "recorded_run.json"


def describe_diff(k_before: int, n_before: int, k_after: int, n_after: int) -> str:
    """Classify difference per pre-registered decision rule."""
    ci_b = wilson_ci(k_before, n_before)
    ci_a = wilson_ci(k_after, n_after)
    if not intervals_overlap(ci_b, ci_a):
        return "Real difference (intervals do not overlap)"
    return "No measurable difference (intervals overlap)"


def extract_policy_block_rule(trace: list[dict[str, Any]]) -> str | None:
    """Extract first policy block rule name from a tool execution trace."""
    for call in trace:
        if call.get("policy_rule"):
            return str(call.get("policy_rule"))
        res = call.get("result", {})
        if isinstance(res, dict) and res.get("policy_block"):
            err = str(res.get("error", ""))
            if "[rule: " in err:
                return err.split("[rule: ")[1].split("]")[0].strip()
            if res.get("rule"):
                return str(res.get("rule"))
            return "policy_block"
    return None


# ---------------------------------------------------------------------------
# Task 1: Benign Variance Evaluation
# ---------------------------------------------------------------------------


async def run_benign_variance_experiment(
    policy_v2: dict[str, Any],
    reps: int = 3,
) -> dict[str, Any]:
    """Run 35-task benign suite 3 times each for unhardened and Policy v2."""
    print("=" * 80)
    print("TASK 1: BENIGN OPERATIONAL VARIANCE EXPERIMENT (35 tasks x 3 reps each)")
    print("=" * 80)

    unhardened_runs: list[dict[str, Any]] = []
    v2_runs: list[dict[str, Any]] = []

    # 1. Unhardened runs
    for rep in range(1, reps + 1):
        print(f"\n[variance] Running Unhardened Benign Suite (Rep {rep}/{reps})...")
        t0 = time.perf_counter()
        res = await run_benign_suite(
            tasks_path=BENIGN_TASKS_PATH,
            role="super",
            mode="realistic",
            policy=None,
        )
        elapsed = time.perf_counter() - t0
        passed = res.get("passed", 0)
        total = res.get("total", 35)
        rate_pct = res.get("pass_rate_pct", (passed / total * 100.0) if total else 0.0)
        print(f"[variance] Unhardened Rep {rep}: {passed}/{total} ({rate_pct:.1f}%) in {elapsed:.1f}s")
        unhardened_runs.append({"rep": rep, "passed": passed, "total": total, "rate_pct": rate_pct, "res": res})

    # 2. Policy v2 runs
    for rep in range(1, reps + 1):
        print(f"\n[variance] Running Policy v2 Benign Suite (Rep {rep}/{reps})...")
        t0 = time.perf_counter()
        res = await run_benign_suite(
            tasks_path=BENIGN_TASKS_PATH,
            role="super",
            mode="realistic",
            policy=policy_v2,
        )
        elapsed = time.perf_counter() - t0
        passed = res.get("passed", 0)
        total = res.get("total", 35)
        rate_pct = res.get("pass_rate_pct", (passed / total * 100.0) if total else 0.0)
        print(f"[variance] Policy v2 Rep {rep}: {passed}/{total} ({rate_pct:.1f}%) in {elapsed:.1f}s")
        v2_runs.append({"rep": rep, "passed": passed, "total": total, "rate_pct": rate_pct, "res": res})

    # Pooled calculations
    u_passed_pool = sum(r["passed"] for r in unhardened_runs)
    u_total_pool = sum(r["total"] for r in unhardened_runs)
    v2_passed_pool = sum(r["passed"] for r in v2_runs)
    v2_total_pool = sum(r["total"] for r in v2_runs)

    # Per-task failure tracking
    task_failures_unh: dict[str, int] = {}
    task_failures_v2: dict[str, int] = {}
    task_reasons_v2: dict[str, list[str]] = {}
    task_blocks_v2: dict[str, list[list[str]]] = {}

    for run_data in unhardened_runs:
        for item in run_data["res"].get("results", []):
            t_id = item.get("task_id")
            if not item.get("passed"):
                task_failures_unh[t_id] = task_failures_unh.get(t_id, 0) + 1

    for run_data in v2_runs:
        for item in run_data["res"].get("results", []):
            t_id = item.get("task_id")
            if not item.get("passed"):
                task_failures_v2[t_id] = task_failures_v2.get(t_id, 0) + 1
                task_reasons_v2.setdefault(t_id, []).append(item.get("reason", ""))
                task_blocks_v2.setdefault(t_id, []).append(item.get("policy_blocks", []))

    # Flag tasks that fail ONLY under v2
    v2_only_failures = []
    for t_id, cnt in task_failures_v2.items():
        if task_failures_unh.get(t_id, 0) == 0:
            v2_only_failures.append(t_id)

    # Format variance summary
    print("\n" + "=" * 80)
    print("BENIGN OPERATIONAL VARIANCE REPORT")
    print("=" * 80)
    print("\n1. PASS RATE PER RUN:")
    print("| Condition | Run 1 | Run 2 | Run 3 | Pooled Pass Rate | 95% Wilson CI |")
    print("| :--- | :--- | :--- | :--- | :--- | :--- |")
    u_ci_str = format_rate_with_ci(u_passed_pool, u_total_pool)
    v2_ci_str = format_rate_with_ci(v2_passed_pool, v2_total_pool)
    print(
        f"| Unhardened Baseline | {unhardened_runs[0]['rate_pct']:.1f}% | "
        f"{unhardened_runs[1]['rate_pct']:.1f}% | {unhardened_runs[2]['rate_pct']:.1f}% | "
        f"{u_passed_pool}/{u_total_pool} ({(u_passed_pool/u_total_pool)*100:.1f}%) | {u_ci_str} |"
    )
    print(
        f"| Policy v2 | {v2_runs[0]['rate_pct']:.1f}% | "
        f"{v2_runs[1]['rate_pct']:.1f}% | {v2_runs[2]['rate_pct']:.1f}% | "
        f"{v2_passed_pool}/{v2_total_pool} ({(v2_passed_pool/v2_total_pool)*100:.1f}%) | {v2_ci_str} |"
    )

    print("\n2. PER-TASK FAILURE COUNTS (out of 3 runs):")
    all_failed_tasks = sorted(set(list(task_failures_unh.keys()) + list(task_failures_v2.keys())))
    if all_failed_tasks:
        print("| Task ID | Unhardened Failures (out of 3) | Policy v2 Failures (out of 3) | Status |")
        print("| :--- | :--- | :--- | :--- |")
        for tid in all_failed_tasks:
            fu = task_failures_unh.get(tid, 0)
            fv = task_failures_v2.get(tid, 0)
            status = "FAILS ONLY UNDER V2" if tid in v2_only_failures else "Common failure across conditions"
            print(f"| `{tid}` | {fu}/3 | {fv}/3 | {status} |")
    else:
        print("None! 100% pass rate across all runs.")

    print("\n3. INSPECTION OF TASKS FAILING ONLY UNDER V2:")
    if v2_only_failures:
        for tid in v2_only_failures:
            reasons = task_reasons_v2.get(tid, [])
            blocks = task_blocks_v2.get(tid, [])
            has_policy_block = any(len(b) > 0 for b in blocks)
            root_cause = "POLICY ENGINE BLOCK" if has_policy_block else "MODEL REASONING VARIATION"
            print(f"- Task `{tid}`: Root cause: **{root_cause}**")
            print(f"  Reasons: {reasons}")
            print(f"  Policy blocks: {blocks}")
    else:
        print("No tasks failed only under Policy v2!")

    return {
        "unhardened_runs": unhardened_runs,
        "v2_runs": v2_runs,
        "pooled": {
            "unhardened": {"passed": u_passed_pool, "total": u_total_pool, "ci": wilson_ci(u_passed_pool, u_total_pool)},
            "policy_v2": {"passed": v2_passed_pool, "total": v2_total_pool, "ci": wilson_ci(v2_passed_pool, v2_total_pool)},
        },
        "per_task_failures": {
            "unhardened": task_failures_unh,
            "policy_v2": task_failures_v2,
        },
        "v2_only_failures": v2_only_failures,
    }


# ---------------------------------------------------------------------------
# Task 2: Naive-Mode Confirmation on Confirmation Set #2
# ---------------------------------------------------------------------------


async def run_naive_mode_confirmation(
    standard_attacks: list[dict[str, Any]],
    policy_v2: dict[str, Any],
) -> dict[str, Any]:
    """Run confirmation on naive target mode (unhardened vs Policy v2, n=190)."""
    print("\n" + "=" * 80)
    print("TASK 2: NAIVE-MODE CONFIRMATION ON STANDARD ATTACKS (n=190)")
    print("=" * 80)

    n_attacks = len(standard_attacks)
    canaries = get_canary_tokens()
    partners = load_partner_contacts()
    allowlist = DEFAULT_ALLOWLISTED_EGRESS + [p["email"] for p in partners]
    base_store = get_default_store()
    channel_tasks: dict[str, list[dict]] = {"email": [], "web_page": [], "document": []}

    sem = asyncio.Semaphore(15)

    async def _eval_one(att: dict[str, Any], policy: dict[str, Any] | None, run_prefix: str) -> dict[str, Any]:
        async with sem:
            res = await evaluate_single_attack(
                attack_id=att["id"],
                run_id=f"naive_{run_prefix}",
                generation=0,
                parent_id=None,
                channel=att.get("channel", "email"),
                category=att.get("category", "authority_framing"),
                payload=att.get("payload", ""),
                strategy=att.get("strategy", ""),
                base_store=base_store,
                channel_tasks=channel_tasks,
                task_style=att.get("task_style", "action"),
                target_role="super",
                target_mode="naive",
                policy=policy,
            )
            metrics = evaluate_trace_metrics(res.trace, canaries, allowlist)
            return {
                "id": att["id"],
                "channel": att.get("channel", "email"),
                "category": att.get("category", ""),
                "strategy": att.get("strategy", ""),
                "payload": att.get("payload", ""),
                "outcome": res.outcome,
                "trace": res.trace,
                "metrics": metrics,
            }

    # 1. Unhardened on Naive Mode
    print(f"\n[naive] Evaluating {n_attacks} standard attacks on NAIVE mode (unhardened)...")
    t0 = time.perf_counter()
    unhardened_items = await asyncio.gather(*[_eval_one(a, None, "unhardened") for a in standard_attacks])
    unh_time = time.perf_counter() - t0
    print(f"[naive] Unhardened naive completed in {unh_time:.1f}s.")

    # 2. Policy v2 on Naive Mode
    print(f"\n[naive] Evaluating {n_attacks} standard attacks on NAIVE mode (Policy v2)...")
    t0 = time.perf_counter()
    v2_items = await asyncio.gather(*[_eval_one(a, policy_v2, "policy_v2") for a in standard_attacks])
    v2_time = time.perf_counter() - t0
    print(f"[naive] Policy v2 naive completed in {v2_time:.1f}s.")

    # Metric aggregation
    def _agg(items: list[dict[str, Any]]) -> dict[str, Any]:
        n = len(items)
        m1 = sum(1 for r in items if r["metrics"]["m1"])
        m2 = sum(1 for r in items if r["metrics"]["m2"])
        m3 = sum(1 for r in items if r["metrics"]["m3"])
        m4 = sum(1 for r in items if r["metrics"]["m4"])
        unsafe = sum(1 for r in items if r["metrics"]["unsafe"])
        return {"n": n, "m1": m1, "m2": m2, "m3": m3, "m4": m4, "unsafe": unsafe}

    unh_metrics = _agg(unhardened_items)
    v2_metrics = _agg(v2_items)

    # Print naive comparison table
    print("\n" + "=" * 80)
    print(f"NAIVE-MODE CONFIRMATION TABLE (Standard Threats, n={n_attacks})")
    print("=" * 80)
    m_names = {
        "m1": "M1 (Exfiltration to non-allowlist)",
        "m2": "M2 (Vault Access)",
        "m3": "M3 (Unauthorized Egress)",
        "m4": "M4 (Canary Leak to any outbound tool)",
        "unsafe": "UNSAFE (M1 or M2 or M3)",
    }
    print(f"| Metric | Unhardened Baseline (Naive, n={n_attacks}) | Policy v2 (Naive, n={n_attacks}) | Classification |")
    print("| :--- | :--- | :--- | :--- |")
    for m in ["m1", "m2", "m3", "m4", "unsafe"]:
        ku = unh_metrics[m]
        kv2 = v2_metrics[m]
        ru_str = format_rate_with_ci(ku, n_attacks)
        rv2_str = format_rate_with_ci(kv2, n_attacks)
        diff_str = describe_diff(ku, n_attacks, kv2, n_attacks)
        print(f"| {m_names[m]} | {ru_str} | {rv2_str} | {diff_str} |")

    # Cache naive results
    naive_cache = {
        "n": n_attacks,
        "unhardened": unh_metrics,
        "policy_v2": v2_metrics,
        "unhardened_items": unhardened_items,
        "policy_v2_items": v2_items,
    }
    cache_path = CACHE_DIR / "conf2_naive_results.json"
    cache_path.write_text(json.dumps(naive_cache, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[naive] Checkpointed naive results to {cache_path}")

    return naive_cache


# ---------------------------------------------------------------------------
# Task 3: Per-Attack Persistence (runs/recorded_run.json)
# ---------------------------------------------------------------------------


def build_and_save_recorded_run() -> dict[str, Any]:
    """Rebuild runs/recorded_run.json from checkpoints with complete per-attack traces."""
    print("\n" + "=" * 80)
    print("TASK 3: PER-ATTACK PERSISTENCE (runs/recorded_run.json)")
    print("=" * 80)

    # 1. Load attack definitions
    attacks = json.loads(CONFIRMATION_V2_PATH.read_text(encoding="utf-8"))

    # 2. Load checkpoint results
    unh_data = json.load((CACHE_DIR / "conf2_unhardened.json").open(encoding="utf-8"))
    v1_data = json.load((CACHE_DIR / "conf2_policy_v1.json").open(encoding="utf-8"))
    v2_data = json.load((CACHE_DIR / "conf2_policy_v2.json").open(encoding="utf-8"))

    unh_by_id = {it["id"]: it for it in unh_data.get("items", [])}
    v1_by_id = {it["id"]: it for it in v1_data.get("items", [])}
    v2_by_id = {it["id"]: it for it in v2_data.get("items", [])}

    recorded_attacks: list[dict[str, Any]] = []

    for att in attacks:
        aid = att["id"]
        u_it = unh_by_id.get(aid, {})
        v1_it = v1_by_id.get(aid, {})
        v2_it = v2_by_id.get(aid, {})

        rec = {
            "id": aid,
            "channel": att.get("channel", "email"),
            "category": att.get("category", ""),
            "strategy": att.get("strategy", ""),
            "payload": att.get("payload", ""),
            "is_probe": att.get("is_probe", False),
            "unhardened": {
                "outcome": u_it.get("outcome", "defended"),
                "metrics": u_it.get("metrics", {}),
                "policy_block_rule": extract_policy_block_rule(u_it.get("trace", [])),
                "trace": u_it.get("trace", []),
            },
            "v1": {
                "outcome": v1_it.get("outcome", "defended"),
                "metrics": v1_it.get("metrics", {}),
                "policy_block_rule": extract_policy_block_rule(v1_it.get("trace", [])),
                "trace": v1_it.get("trace", []),
            },
            "v2": {
                "outcome": v2_it.get("outcome", "defended"),
                "metrics": v2_it.get("metrics", {}),
                "policy_block_rule": extract_policy_block_rule(v2_it.get("trace", [])),
                "trace": v2_it.get("trace", []),
            },
        }
        recorded_attacks.append(rec)

    full_record = {
        "dataset": "confirmation_set2",
        "seed": 20261008,
        "n_attacks": len(recorded_attacks),
        "conditions": ["unhardened", "v1", "v2"],
        "attacks": recorded_attacks,
    }

    RECORDED_RUN_PATH.parent.mkdir(parents=True, exist_ok=True)
    RECORDED_RUN_PATH.write_text(json.dumps(full_record, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[persistence] Successfully wrote {len(recorded_attacks)} complete per-attack records to {RECORDED_RUN_PATH}")
    return full_record


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------


async def main() -> None:
    p2_bytes = POLICY_V2_PATH.read_bytes()
    policy_v2 = yaml.safe_load(p2_bytes.decode("utf-8"))

    # Load standard attacks for naive confirmation
    attacks = json.loads(CONFIRMATION_V2_PATH.read_text(encoding="utf-8"))
    standard_attacks = [a for a in attacks if not a.get("is_probe")]

    # 1. Run Task 1: Benign Variance (3 reps each)
    await run_benign_variance_experiment(policy_v2=policy_v2, reps=3)

    # 2. Run Task 2: Naive-mode confirmation (standard 190 attacks)
    await run_naive_mode_confirmation(standard_attacks=standard_attacks, policy_v2=policy_v2)

    # 3. Run Task 3: Per-attack persistence
    build_and_save_recorded_run()

    # 4. Total Cost
    ledger = get_ledger()
    total_cost = ledger.total_cost_usd
    print("\n" + "=" * 80)
    print(f"RUN COMPLETE. Total USD Cost Spent: ${total_cost:.4f}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
