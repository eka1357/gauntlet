"""Audit empirical claims (percentages, counts, dollar amounts) across documentation and rendered HTML.

Verifies that all numerical claims in README.md, docs/*.md, FEEDBACK.md, and rendered HTML
match numbers derivable from web/public/data/*.json or are documented in docs/audit_allowlist.txt.

Usage: py scripts/audit_numbers.py [--allowlist docs/audit_allowlist.txt]
Exit code: 0 if all claims match or are allowlisted; non-zero if unmatched claims exist.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "web" / "public" / "data"
ALLOWLIST_FILE = ROOT / "docs" / "audit_allowlist.txt"


def collect_derivable_values() -> tuple[set[str], set[float]]:
    """Extract all derivable numbers, percentages, and dollar amounts from web/public/data/*.json."""
    raw_strings: set[str] = set()
    raw_numbers: set[float] = set()

    for path in DATA_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        def recurse(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    recurse(v)
            elif isinstance(node, list):
                for item in node:
                    recurse(item)
            elif isinstance(node, (int, float)):
                val = float(node)
                raw_numbers.add(val)
                raw_strings.add(str(node))
                if isinstance(node, int) or node.is_integer():
                    raw_strings.add(str(int(val)))
                # Derivations
                raw_strings.add(f"{val:.1f}")
                raw_strings.add(f"{val:.2f}")
                raw_strings.add(f"{val:.4f}")
                raw_strings.add(f"{val:.1f}%")
                raw_strings.add(f"{val:.2f}%")
                raw_strings.add(f"${val:.2f}")
                raw_strings.add(f"${val:.4f}")
            elif isinstance(node, str):
                raw_strings.add(node.strip())
                # If string contains numbers or currency
                m = re.findall(r"\$?\d+(?:\.\d+)?%?", node)
                for item in m:
                    raw_strings.add(item)

        recurse(data)

    # Add project facts if present
    facts_file = ROOT / "docs" / "project_facts.json"
    if facts_file.exists():
        try:
            facts = json.loads(facts_file.read_text(encoding="utf-8"))
            for v in facts.values():
                if isinstance(v, (int, float)):
                    raw_numbers.add(float(v))
                    raw_strings.add(str(v))
                    raw_strings.add(f"${v:.2f}")
                elif isinstance(v, str):
                    raw_strings.add(v)
        except Exception:
            pass

    return raw_strings, raw_numbers


def parse_allowlist(allowlist_path: Path) -> dict[str, str]:
    """Parse allowlist file mapping tokens or file:token to rationale."""
    allowlist: dict[str, str] = {}
    if not allowlist_path.exists():
        return allowlist

    for line in allowlist_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            token_part, rationale = line.split("|", 1)
            token = token_part.strip()
            allowlist[token] = rationale.strip()
        else:
            allowlist[line] = "Explicitly allowlisted"
    return allowlist


def extract_claims_from_text(text: str, filename: str) -> list[dict[str, Any]]:
    """Extract claims (dollar amounts, percentages, and metrics counts) from text."""
    claims: list[dict[str, Any]] = []

    # Strip code blocks with code syntax / shell commands to avoid arbitrary flags/ports
    text_clean = re.sub(r"```[a-zA-Z0-9_-]*\n.*?```", "", text, flags=re.DOTALL)
    text_clean = re.sub(r"`[^`\n]+`", " ", text_clean)  # inline code
    text_clean = re.sub(r"<style>.*?</style>", "", text_clean, flags=re.DOTALL)
    text_clean = re.sub(r"<script.*?</script>", "", text_clean, flags=re.DOTALL)
    text_clean = re.sub(r"<!--.*?-->", "", text_clean, flags=re.DOTALL)

    # 1. Dollar amounts: e.g. $4.17, $12.40, $0.08
    for m in re.finditer(r"(\$[0-9]+(?:\.[0-9]+)?)", text_clean):
        claims.append({
            "token": m.group(1),
            "type": "dollar",
            "file": filename,
            "raw": m.group(1),
        })

    # 2. Percentages: e.g. 71.6%, 25.8%, 0.0%
    for m in re.finditer(r"\b([0-9]+(?:\.[0-9]+)?%)", text_clean):
        claims.append({
            "token": m.group(1),
            "type": "percentage",
            "file": filename,
            "raw": m.group(1),
        })

    # 3. Substantive counts (integers followed by context or in tables/metrics)
    # Examples: "190 attacks", "49 unsafe", "0 breached", "235 total", "45 probes"
    for m in re.finditer(r"\b([0-9]+)\s+(?:attacks|unsafe|breached|probes|evaluations|tasks|rules|iterations|tokens|matches|lines|runs)\b", text_clean, flags=re.IGNORECASE):
        claims.append({
            "token": m.group(1),
            "type": "count",
            "file": filename,
            "raw": m.group(0),
        })

    # 4. Fractional counts: "49 of 190", "0/190"
    for m in re.finditer(r"\b([0-9]+)\s*(?:of|/)\s*([0-9]+)\b", text_clean, flags=re.IGNORECASE):
        claims.append({
            "token": m.group(1),
            "type": "numerator",
            "file": filename,
            "raw": m.group(0),
        })
        claims.append({
            "token": m.group(2),
            "type": "denominator",
            "file": filename,
            "raw": m.group(0),
        })

    return claims


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit numbers in docs, feedback, and rendered HTML")
    parser.add_argument("--allowlist", default=str(ALLOWLIST_FILE))
    parser.add_argument("--html-dir", default=str(ROOT / "web" / "out"))
    args = parser.parse_args()

    allowlist_path = Path(args.allowlist)
    allowlist = parse_allowlist(allowlist_path)

    derivable_strings, derivable_numbers = collect_derivable_values()

    # Targets to inspect
    target_files: list[Path] = []

    # Root markdown
    for fn in ["README.md", "FEEDBACK.md"]:
        p = ROOT / fn
        if p.exists():
            target_files.append(p)

    # docs/*.md
    for p in (ROOT / "docs").glob("*.md"):
        target_files.append(p)

    # Rendered HTML from web/out
    html_dir = Path(args.html_dir)
    if html_dir.exists():
        for p in [html_dir / "index.html", html_dir / "results" / "index.html", html_dir / "policy" / "index.html", html_dir / "report" / "index.html"]:
            if p.exists():
                target_files.append(p)

    all_claims: list[dict[str, Any]] = []
    for tf in target_files:
        rel_name = tf.relative_to(ROOT).as_posix()
        content = tf.read_text(encoding="utf-8", errors="ignore")
        claims = extract_claims_from_text(content, rel_name)
        all_claims.extend(claims)

    matched: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []

    for c in all_claims:
        tok = c["token"]
        file_key = f"{c['file']}:{tok}"

        # Check direct match or numerical match
        is_matched = False
        if tok in derivable_strings:
            is_matched = True
        else:
            # Check if stripped number matches
            num_clean = tok.replace("$", "").replace("%", "")
            try:
                num_val = float(num_clean)
                if num_val in derivable_numbers or f"{num_val:.1f}" in derivable_strings or str(int(num_val)) in derivable_strings:
                    is_matched = True
            except ValueError:
                pass

        if is_matched:
            c["status"] = "MATCHED"
            c["rationale"] = "Derivable from web/public/data"
            matched.append(c)
        elif file_key in allowlist:
            c["status"] = "ALLOWLISTED"
            c["rationale"] = allowlist[file_key]
            allowlisted.append(c)
        elif tok in allowlist:
            c["status"] = "ALLOWLISTED"
            c["rationale"] = allowlist[tok]
            allowlisted.append(c)
        else:
            c["status"] = "UNMATCHED"
            c["rationale"] = "Not matched in data or allowlist"
            unmatched.append(c)

    # Print Report Table
    print("\n" + "=" * 90)
    print(f"{'FILE':<35} {'TOKEN':<12} {'TYPE':<12} {'STATUS':<12} {'NOTE'}")
    print("-" * 90)
    for c in matched[:20]:  # sample matched
        print(f"{c['file'][:34]:<35} {c['token']:<12} {c['type']:<12} {c['status']:<12} {c['rationale'][:30]}")
    if len(matched) > 20:
        print(f"... and {len(matched) - 20} more MATCHED claims.")

    for c in allowlisted:
        print(f"{c['file'][:34]:<35} {c['token']:<12} {c['type']:<12} {c['status']:<12} {c['rationale'][:30]}")

    if unmatched:
        print("\n" + "!" * 90)
        print(f"UNMATCHED CLAIMS DETECTED ({len(unmatched)} items):")
        print("!" * 90)
        for c in unmatched:
            print(f"{c['file']:<35} {c['token']:<12} {c['type']:<12} {c['raw']:<20} {c['rationale']}")

    print("\nSUMMARY:")
    print(f"  Matched:     {len(matched)}")
    print(f"  Allowlisted: {len(allowlisted)}")
    print(f"  Unmatched:   {len(unmatched)}")
    print("=" * 90 + "\n")

    if unmatched:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
