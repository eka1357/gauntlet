"""Tests for static data export and integrity (FR-14).

Verifies that:
  1. scripts/export_static.py builds all static data cleanly without model calls.
  2. Every file the frontend references exists and parses as valid JSON.
  3. No secrets or environment values are leaked into any static JSON file.
  4. Core schemas and pagination invariants (235 attacks, 705 traces) hold.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.export_static import export_static

ROOT_DIR = Path(__file__).resolve().parent.parent
PUBLIC_DATA_DIR = ROOT_DIR / "web" / "public" / "data"


@pytest.mark.asyncio
async def test_build_static_data_in_temp_dir(tmp_path: Path) -> None:
    """Build static data into a clean temporary directory and verify every file."""
    counts = await export_static(output_dir=tmp_path)
    assert counts["endpoints"] >= 8
    assert counts["attacks_paged"] >= 8
    assert counts["traces"] == 235 * 3

    # Check core files exist
    expected_core_files = [
        "summary.json",
        "project_facts.json",
        "model_roles.json",
        "policy_v1.json",
        "policy_v2.json",
        "benign.json",
        "report.json",
        "health.json",
        "attacks.json",
        "attacks_limit_250.json",
        "attacks_page_1_limit_150.json",
        "attacks_page_2_limit_150.json",
        "attacks_page_1_limit_50.json",
        "attacks_page_2_limit_50.json",
        "attacks_page_3_limit_50.json",
        "attacks_page_4_limit_50.json",
        "attacks_page_5_limit_50.json",
    ]

    for fname in expected_core_files:
        file_path = tmp_path / fname
        assert file_path.is_file(), f"Missing expected static file: {fname}"
        content = file_path.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert parsed is not None

    # Check traces directory
    traces_dir = tmp_path / "traces"
    assert traces_dir.is_dir()
    trace_files = list(traces_dir.glob("*.json"))
    assert len(trace_files) == 235 * 3, f"Expected 705 trace files, got {len(trace_files)}"

    for tf in trace_files[:20]:  # sample test first 20
        parsed_trace = json.loads(tf.read_text(encoding="utf-8"))
        assert "id" in parsed_trace
        assert "condition" in parsed_trace
        assert "outcome" in parsed_trace
        assert "trace" in parsed_trace
        assert isinstance(parsed_trace["trace"], list)


def test_public_data_directory_contents_and_schemas() -> None:
    """Verify that web/public/data/ contains all required JSON files with valid schemas."""
    assert PUBLIC_DATA_DIR.is_dir(), "web/public/data must exist"

    # 1. Summary
    summary_path = PUBLIC_DATA_DIR / "summary.json"
    assert summary_path.is_file()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    required_keys = (
        "naive_mode",
        "realistic_mode",
        "probe_set",
        "benign_suite",
        "policy_hashes",
        "costs",
    )
    for req in required_keys:
        assert req in summary

    # 2. Project facts
    facts_path = PUBLIC_DATA_DIR / "project_facts.json"
    assert facts_path.is_file()
    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    assert "total_project_usage_usd" in facts
    assert facts["total_project_usage_usd"] == 12.40

    # 3. Model roles
    roles_path = PUBLIC_DATA_DIR / "model_roles.json"
    assert roles_path.is_file()
    roles = json.loads(roles_path.read_text(encoding="utf-8"))
    assert len(roles) >= 3

    # 4. Policies
    p1 = json.loads((PUBLIC_DATA_DIR / "policy_v1.json").read_text(encoding="utf-8"))
    assert p1["version"] == 1
    assert p1["sha256"] == "f27decd5411325c234cdb36f7ff168033c6442a797d317dc1f4cbf25dc4ef265"

    p2 = json.loads((PUBLIC_DATA_DIR / "policy_v2.json").read_text(encoding="utf-8"))
    assert p2["version"] == 2
    assert p2["sha256"] == "31dc77b565c2aed4c424699fbc2b41568f7275705034e6040cd0baf35004e05e"

    # 5. Attacks and pagination
    all_att = json.loads((PUBLIC_DATA_DIR / "attacks.json").read_text(encoding="utf-8"))
    assert all_att["total"] == 235
    assert len(all_att["attacks"]) == 235

    p1_150_path = PUBLIC_DATA_DIR / "attacks_page_1_limit_150.json"
    p2_150_path = PUBLIC_DATA_DIR / "attacks_page_2_limit_150.json"
    p1_150 = json.loads(p1_150_path.read_text(encoding="utf-8"))
    p2_150 = json.loads(p2_150_path.read_text(encoding="utf-8"))
    assert len(p1_150["attacks"]) == 150
    assert len(p2_150["attacks"]) == 85

    # 6. Health
    health = json.loads((PUBLIC_DATA_DIR / "health.json").read_text(encoding="utf-8"))
    assert health["status"] == "ok"
    assert health["live_runs_enabled"] is False
    assert health["static_mode"] is True

    # 7. Traces
    traces_dir = PUBLIC_DATA_DIR / "traces"
    assert traces_dir.is_dir()
    traces = list(traces_dir.glob("*.json"))
    assert len(traces) == 235 * 3


def test_zero_secrets_in_public_data() -> None:
    """Ensure no secret tokens, API keys or environment variables leak into any file."""
    for json_file in PUBLIC_DATA_DIR.rglob("*.json"):
        text = json_file.read_text(encoding="utf-8")
        assert "sk-" not in text
        assert "tvly-" not in text
        assert "nvid-" not in text
        assert "NEBIUS_API_KEY" not in text
        assert "TAVILY_API_KEY" not in text
