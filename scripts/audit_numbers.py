"""Audit empirical claims (percentages, counts, dollar amounts) across documentation and rendered HTML.

Verifies that every numerical claim in README.md, docs/*.md, FEEDBACK.md, and rendered HTML
strictly matches a specific named field in web/public/data/*.json or is documented in docs/audit_allowlist.txt.

A number that merely equals an unrelated value of another type (e.g. 49% when only count 49 exists)
fails as UNMATCHED.

Usage: py scripts/audit_numbers.py [--allowlist docs/audit_allowlist.txt]
Exit code: 0 if all claims match by field or are allowlisted; non-zero if unmatched claims exist.
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


def build_typed_field_index(data_dir: Path) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Build exact typed mappings: token -> named field path in data JSON files.

    Returns:
        (dollar_fields, percentage_fields, count_fields)
    """
    dollar_fields: dict[str, str] = {}
    percentage_fields: dict[str, str] = {}
    count_fields: dict[str, str] = {}

    for path in sorted(data_dir.glob("*.json")):
        if "limit_" in path.name or "page_" in path.name:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        def recurse(node: Any, p: list[str]) -> None:
            field_name = p[-1] if p else ""
            field_path = f"{path.name}:{'.'.join(p)}"
            fn_lower = field_name.lower()
            p_lower = ".".join(p).lower()

            if isinstance(node, dict):
                for k, v in node.items():
                    recurse(v, p + [k])
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    recurse(item, p + [str(idx)])
            elif isinstance(node, (int, float)):
                val = float(node)
                is_int = isinstance(node, int) or node.is_integer()

                # 1. Dollar amounts
                if any(kw in fn_lower or kw in p_lower for kw in ("usd", "cost", "spend", "price", "cap")):
                    dollar_fields[f"${val:.2f}"] = field_path
                    dollar_fields[f"${val:.4f}"] = field_path
                    if is_int:
                        dollar_fields[f"${int(val)}"] = field_path

                # 2. Percentages (only from explicit pct fields or rate fields)
                elif any(kw in fn_lower for kw in ("pct", "percentage")) or "ci_pct" in p_lower or "rate_pct" in p_lower:
                    percentage_fields[f"{val:.1f}%"] = field_path
                    percentage_fields[f"{val:.2f}%"] = field_path
                    percentage_fields[f"{val:.0f}%"] = field_path
                    if is_int:
                        percentage_fields[f"{int(val)}%"] = field_path

                elif any(kw in fn_lower for kw in ("rate",)) and 0.0 <= val <= 1.0:
                    pct_val = val * 100.0
                    percentage_fields[f"{pct_val:.1f}%"] = field_path
                    percentage_fields[f"{pct_val:.2f}%"] = field_path
                    percentage_fields[f"{pct_val:.0f}%"] = field_path

                # 3. Counts / integer quantities
                else:
                    if is_int:
                        str_int = str(int(val))
                        # Prefer summary.json paths for clarity
                        if str_int not in count_fields or "summary.json" in field_path:
                            count_fields[str_int] = field_path

            elif isinstance(node, str):
                s = node.strip()
                if s.startswith("$"):
                    dollar_fields[s] = field_path
                elif s.endswith("%"):
                    percentage_fields[s] = field_path

        recurse(data, [])

    # Project facts
    facts_file = ROOT / "docs" / "project_facts.json"
    if facts_file.exists():
        try:
            facts = json.loads(facts_file.read_text(encoding="utf-8"))
            for k, v in facts.items():
                fp = f"project_facts.json:{k}"
                if isinstance(v, (int, float)):
                    dollar_fields[f"${float(v):.2f}"] = fp
                    count_fields[str(int(v))] = fp
                elif isinstance(v, str) and v.startswith("$"):
                    dollar_fields[v] = fp
        except Exception:
            pass

    return dollar_fields, percentage_fields, count_fields


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
    for m in re.finditer(r"\b([0-9]+)\s+(?:attacks|unsafe|breached|probes|evaluations|tasks|rules|iterations|tokens|matches|lines|runs)\b", text_clean, flags=re.IGNORECASE):
        claims.append({
            "token": m.group(1),
            "type": "count",
            "file": filename,
            "raw": m.group(0),
        })

    # 4. Fractional counts: "49 of 150", "0/150"
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

    dollar_fields, percentage_fields, count_fields = build_typed_field_index(DATA_DIR)

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
        for p in [html_dir / "index.html", html_dir / "results" / "index.html", html_dir / "policy" / "index.html", html_dir / "report" / "index.html", html_dir / "live" / "index.html"]:
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
        c_type = c["type"]
        file_key = f"{c['file']}:{tok}"
        matched_field: str | None = None

        if c_type == "dollar":
            matched_field = dollar_fields.get(tok)
        elif c_type == "percentage":
            matched_field = percentage_fields.get(tok)
        elif c_type in ("count", "numerator", "denominator"):
            matched_field = count_fields.get(tok)

        if matched_field:
            c["status"] = "MATCHED"
            c["field_path"] = matched_field
            matched.append(c)
        elif file_key in allowlist:
            c["status"] = "ALLOWLISTED"
            c["field_path"] = allowlist[file_key]
            allowlisted.append(c)
        elif tok in allowlist:
            c["status"] = "ALLOWLISTED"
            c["field_path"] = allowlist[tok]
            allowlisted.append(c)
        else:
            c["status"] = "UNMATCHED"
            c["field_path"] = "UNMATCHED"
            unmatched.append(c)

    # Print Report Table
    print("\n" + "=" * 105)
    print(f"{'FILE':<32} {'TOKEN':<12} {'TYPE':<12} {'STATUS':<14} {'FIELD PATH / NOTE'}")
    print("-" * 105)
    for c in matched[:20]:
        print(f"{c['file'][:31]:<32} {c['token']:<12} {c['type']:<12} {c['status']:<14} {c['field_path'][:45]}")
    if len(matched) > 20:
        print(f"... and {len(matched) - 20} more MATCHED-BY-FIELD claims.")

    for c in allowlisted:
        print(f"{c['file'][:31]:<32} {c['token']:<12} {c['type']:<12} {c['status']:<14} {c['field_path'][:45]}")

    if unmatched:
        print("\n" + "!" * 105)
        print(f"UNMATCHED CLAIMS DETECTED ({len(unmatched)} items):")
        print("!" * 105)
        for c in unmatched:
            print(f"{c['file'][:31]:<32} {c['token']:<12} {c['type']:<12} {c['raw']:<16} {c['field_path']}")

    print("\nSUMMARY:")
    print(f"  Matched-by-field: {len(matched)}")
    print(f"  Allowlisted:      {len(allowlisted)}")
    print(f"  Unmatched:        {len(unmatched)}")
    print("=" * 105 + "\n")

    if unmatched:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
