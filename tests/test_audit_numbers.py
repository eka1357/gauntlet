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
    assert res.returncode == 0, f"audit_numbers failed: {res.stdout}\n{res.stderr}"
    assert "Unmatched:   0" in res.stdout


def test_audit_numbers_fails_on_unmatched_claim(tmp_path: Path) -> None:
    """Audit detects fabricated numbers not in data or allowlist and exits non-zero."""
    # Create a fake markdown claim file
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
