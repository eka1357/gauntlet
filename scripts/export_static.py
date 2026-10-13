"""Static data exporter for Gauntlet frontend (FR-14).

Exports all recorded API endpoint responses as static JSON files into
web/public/data/ so the frontend can function completely standalone with
zero backend process and zero model calls.

Generated artifacts:
  - web/public/data/summary.json
  - web/public/data/attacks.json
  - web/public/data/attacks_limit_250.json
  - web/public/data/attacks_page_1_limit_150.json
  - web/public/data/attacks_page_2_limit_150.json
  - web/public/data/attacks_page_1_limit_50.json
  - web/public/data/attacks_page_2_limit_50.json
  - web/public/data/attacks_page_3_limit_50.json
  - web/public/data/attacks_page_4_limit_50.json
  - web/public/data/attacks_page_5_limit_50.json
  - web/public/data/policy_v1.json
  - web/public/data/policy_v2.json
  - web/public/data/model_roles.json
  - web/public/data/benign.json
  - web/public/data/report.json
  - web/public/data/project_facts.json
  - web/public/data/health.json
  - web/public/data/traces/{attack_id}_{condition}.json (705 files)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.api import (  # noqa: E402
    get_attack_trace,
    get_policy_yaml,
    get_project_facts,
    get_recorded_attacks,
    get_recorded_model_roles,
    get_recorded_summary,
    load_recorded_run_data,
)
from backend.verify import get_cached_verify_results  # noqa: E402

DEFAULT_OUTPUT_DIR = ROOT_DIR / "web" / "public" / "data"

SENSITIVE_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"tvly-[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"nvid-[a-zA-Z0-9]{20,}", re.IGNORECASE),
]


def assert_no_secrets(content_str: str, file_name: str) -> None:
    """Verify that no sensitive API keys or environment secrets leak into static output."""
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(content_str):
            raise ValueError(f"Secret detected in exported file {file_name} matching {pattern}")

    for env_var in ("NEBIUS_API_KEY", "TAVILY_API_KEY"):
        val = os.environ.get(env_var, "").strip()
        if val and len(val) >= 8 and val in content_str:
            raise ValueError(f"Environment secret from {env_var} leaked into {file_name}")


def write_json_safely(file_path: Path, data: Any) -> None:
    """Serialize and write JSON with UTF-8 encoding and secret checks."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2, ensure_ascii=False)
    assert_no_secrets(serialized, file_path.name)
    file_path.write_text(serialized, encoding="utf-8")


async def export_static(output_dir: Path | None = None) -> dict[str, int]:
    """Export all recorded endpoint responses to static JSON.

    Fails loudly if any required values are missing or invalid.
    Returns counts of exported files.
    """
    out_dir = output_dir or DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    traces_dir = out_dir / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {"endpoints": 0, "attacks_paged": 0, "traces": 0}

    # Compute derived metrics from stored attacks in recorded_run.json
    raw_run_data = load_recorded_run_data()
    raw_attacks = raw_run_data.get("attacks", [])
    standard_attacks = [a for a in raw_attacks if not a.get("is_probe")]
    email_standard_attacks = [a for a in standard_attacks if a.get("channel") == "email"]
    n_email = len(email_standard_attacks)

    # Compute and verify that web-page and document attacks produced none
    web_doc_standard = [a for a in standard_attacks if a.get("channel") in ("web_page", "document")]
    web_doc_unsafe_unhardened = [
        a for a in web_doc_standard
        if a.get("unhardened", {}).get("unsafe")
        or a.get("unhardened", {}).get("m1")
        or a.get("unhardened", {}).get("m2")
        or a.get("unhardened", {}).get("m3")
    ]
    web_doc_unsafe_count = len(web_doc_unsafe_unhardened)
    if web_doc_unsafe_count != 0:
        raise ValueError(
            f"Expected 0 unsafe web/doc attacks in realistic mode, found {web_doc_unsafe_count}"
        )

    # 1. Summary
    summary = await get_recorded_summary()
    if "realistic_mode" in summary:
        summary["realistic_mode"]["n_email"] = n_email
        summary["realistic_mode"]["web_doc_unsafe_count"] = web_doc_unsafe_count
    required_summary_keys = (
        "naive_mode",
        "realistic_mode",
        "probe_set",
        "benign_suite",
        "policy_hashes",
        "costs",
        "limitations",
        "model_roles",
        "project_facts",
        "n_total",
        "n_standard",
        "n_probe",
    )
    for k in required_summary_keys:
        if k not in summary or summary[k] is None:
            raise ValueError(f"Missing required summary key: '{k}'")
    write_json_safely(out_dir / "summary.json", summary)
    counts["endpoints"] += 1

    # 2. Project facts
    facts = get_project_facts()
    for k in ("total_project_usage_usd", "formatted_project_usage", "source"):
        if k not in facts:
            raise ValueError(f"Missing project_facts key: '{k}'")
    write_json_safely(out_dir / "project_facts.json", facts)
    counts["endpoints"] += 1

    # 3. Model roles
    model_roles = get_recorded_model_roles()
    if not model_roles or len(model_roles) < 3:
        raise ValueError(f"Expected at least 3 active model roles, found {len(model_roles)}")
    write_json_safely(out_dir / "model_roles.json", model_roles)
    counts["endpoints"] += 1

    # 4. Policies v1 & v2 with hashes
    p1 = await get_policy_yaml("v1")
    for k in ("version", "sha256", "yaml", "policy", "rationale"):
        if k not in p1 or not p1[k]:
            raise ValueError(f"Missing policy v1 field: '{k}'")
    expected_p1_hash = "f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265"
    if p1["sha256"] != expected_p1_hash:
        raise ValueError(f"Unexpected policy v1 hash: {p1['sha256']} != {expected_p1_hash}")
    write_json_safely(out_dir / "policy_v1.json", p1)
    counts["endpoints"] += 1

    p2 = await get_policy_yaml("v2")
    for k in ("version", "sha256", "yaml", "policy", "rationale"):
        if k not in p2 or not p2[k]:
            raise ValueError(f"Missing policy v2 field: '{k}'")
    expected_p2_hash = "31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e"
    if p2["sha256"] != expected_p2_hash:
        raise ValueError(f"Unexpected policy v2 hash: {p2['sha256']} != {expected_p2_hash}")
    write_json_safely(out_dir / "policy_v2.json", p2)
    counts["endpoints"] += 1

    # 5. Benign results
    verify_res = get_cached_verify_results()
    if not verify_res or "benign_suite" not in verify_res:
        raise ValueError("Missing benign_suite in verify results")
    benign_data = verify_res["benign_suite"]
    for k in ("repeats", "tasks_per_repeat", "unhardened", "policy_v2"):
        if k not in benign_data:
            raise ValueError(f"Missing benign_suite field: '{k}'")
    write_json_safely(out_dir / "benign.json", benign_data)
    counts["endpoints"] += 1

    # 6. Report data
    report_data = {
        **verify_res,
        "model_roles": model_roles,
        "project_facts": facts,
    }
    if "realistic_mode" in report_data:
        report_data["realistic_mode"]["n_email"] = n_email
        report_data["realistic_mode"]["web_doc_unsafe_count"] = web_doc_unsafe_count
    write_json_safely(out_dir / "report.json", report_data)
    counts["endpoints"] += 1

    # 7. Health response (static mode)
    health_data = {
        "status": "ok",
        "live_runs_enabled": False,
        "static_mode": True,
        "token_factory": {
            "configured": False,
            "reachable": False,
        },
        "tavily": {
            "configured": False,
            "reachable": False,
        },
    }
    write_json_safely(out_dir / "health.json", health_data)
    counts["endpoints"] += 1

    # 8. All attacks (full 235 list)
    all_attacks_resp = await get_recorded_attacks(page=1, limit=250)
    if all_attacks_resp.get("total") != 235:
        raise ValueError(f"Expected 235 total attacks, got {all_attacks_resp.get('total')}")
    if len(all_attacks_resp.get("attacks", [])) != 235:
        raise ValueError(f"Expected 235 attack items, got {len(all_attacks_resp.get('attacks', []))}")
    write_json_safely(out_dir / "attacks.json", all_attacks_resp)
    counts["endpoints"] += 1

    # 9. Paginated attack shapes exactly as UI requests them
    # Workspace requests: limit=250
    att_limit_250 = await get_recorded_attacks(page=1, limit=250)
    write_json_safely(out_dir / "attacks_limit_250.json", att_limit_250)
    counts["attacks_paged"] += 1

    # Policy page requests: page=1 limit=150, page=2 limit=150
    p1_l150 = await get_recorded_attacks(page=1, limit=150)
    if len(p1_l150.get("attacks", [])) != 150:
        raise ValueError(f"Expected 150 attacks on page 1, got {len(p1_l150.get('attacks', []))}")
    write_json_safely(out_dir / "attacks_page_1_limit_150.json", p1_l150)
    counts["attacks_paged"] += 1

    p2_l150 = await get_recorded_attacks(page=2, limit=150)
    if len(p2_l150.get("attacks", [])) != 85:
        raise ValueError(f"Expected 85 attacks on page 2, got {len(p2_l150.get('attacks', []))}")
    write_json_safely(out_dir / "attacks_page_2_limit_150.json", p2_l150)
    counts["attacks_paged"] += 1

    # Standard default 50-item pages (pages 1 to 5)
    for p_num in range(1, 6):
        p_res = await get_recorded_attacks(page=p_num, limit=50)
        write_json_safely(out_dir / f"attacks_page_{p_num}_limit_50.json", p_res)
        counts["attacks_paged"] += 1

    # 10. Traces for all 235 attacks across all 3 conditions (235 * 3 = 705 files)
    raw_run_data = load_recorded_run_data()
    raw_attacks = raw_run_data.get("attacks", [])
    if len(raw_attacks) != 235:
        raise ValueError(f"Expected 235 attacks in raw run data, found {len(raw_attacks)}")

    for att in raw_attacks:
        att_id = att["id"]
        for condition in ("unhardened", "v1", "v2"):
            trace_resp = await get_attack_trace(id=att_id, condition=condition)
            if "trace" not in trace_resp or not isinstance(trace_resp["trace"], list):
                raise ValueError(f"Invalid trace response for {att_id} [{condition}]")
            if "outcome" not in trace_resp:
                raise ValueError(f"Missing outcome in trace response for {att_id} [{condition}]")
            trace_path = traces_dir / f"{att_id}_{condition}.json"
            write_json_safely(trace_path, trace_resp)
            counts["traces"] += 1

    if counts["traces"] != 235 * 3:
        raise ValueError(f"Expected 705 trace files, got {counts['traces']}")

    return counts


def main() -> None:
    """CLI entrypoint for static export script."""
    print("=" * 60)
    print("Gauntlet Static Data Exporter")
    print("Exporting in-process recorded verification data to web/public/data/...")
    print("=" * 60)

    try:
        counts = asyncio.run(export_static())
        print("Export successful!")
        print(f"  - Core endpoint files: {counts['endpoints']}")
        print(f"  - Paginated attack files: {counts['attacks_paged']}")
        print(f"  - Execution trace files: {counts['traces']}")
        print(f"  - Total files written: {sum(counts.values())}")
        print(f"Target directory: {DEFAULT_OUTPUT_DIR}")
    except Exception as e:
        print(f"CRITICAL ERROR exporting static data: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
