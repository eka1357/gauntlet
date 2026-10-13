"""Tests for scripts/audit_numbers.py verifying empirical claims match data or fail loudly."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "audit_numbers.py"


def test_audit_numbers_clean() -> None:
    """Audit passes cleanly with exit code 0 on the active codebase."""
    res = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    import re

    assert res.returncode == 0, f"audit_numbers failed: {res.stdout}\n{res.stderr}"
    assert re.search(r"Unmatched:\s+0", res.stdout) is not None, (
        f"Expected 0 unmatched: {res.stdout}"
    )


def test_audit_numbers_fails_on_unmatched_claim() -> None:
    """Audit detects fabricated numbers not in data or allowlist and exits non-zero."""
    fake_doc = ROOT / "docs" / "_temp_audit_probe.md"
    try:
        fake_doc.write_text(
            "# Temporary Claim\n"
            "This model achieved a 99.999% unverifiable defense rate with $999.99 total cost.",
            encoding="utf-8",
        )
        res = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        assert res.returncode != 0, "audit_numbers should have failed on unmatched claims"
        assert "UNMATCHED CLAIMS DETECTED" in res.stdout
        assert "99.999%" in res.stdout or "$999.99" in res.stdout
    finally:
        if fake_doc.exists():
            fake_doc.unlink()


def test_audit_numbers_fails_on_wrong_percentage_matching_unrelated_count() -> None:
    """Audit fails when a percentage claim equals an unrelated count (e.g. 49%)."""
    fake_doc = ROOT / "docs" / "_temp_audit_probe_percentage.md"
    try:
        # 49 is a real count in summary.json (realistic_mode.unhardened.unsafe.count),
        # but 49% is NOT a real percentage in the data.
        fake_doc.write_text(
            "# Wrong Percentage Probe\n"
            "The system reported a 49% rate of failure.",
            encoding="utf-8",
        )
        res = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        assert res.returncode != 0, "audit_numbers should fail on 49% (count, not pct)"
        assert "UNMATCHED CLAIMS DETECTED" in res.stdout
        assert "49%" in res.stdout
    finally:
        if fake_doc.exists():
            fake_doc.unlink()


def test_audit_numbers_fails_on_unpaired_ratio() -> None:
    """Audit fails when a ratio claim has no data object with count and n (e.g. 3 of 150)."""
    fake_doc = ROOT / "docs" / "_temp_audit_probe_ratio.md"
    try:
        fake_doc.write_text(
            "# Unpaired Ratio Probe\n"
            "The system reported 3 of 150 attacks succeeded.",
            encoding="utf-8",
        )
        res = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        assert res.returncode != 0, "audit_numbers should fail on 3 of 150"
        assert "UNMATCHED CLAIMS DETECTED" in res.stdout
        assert "3 of 150" in res.stdout
    finally:
        if fake_doc.exists():
            fake_doc.unlink()

