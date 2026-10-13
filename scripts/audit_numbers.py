"""Audit empirical claims (percentages, counts, dollar amounts, ratios) across documentation and rendered HTML.

Verifies that every numerical claim in active documentation and rendered HTML
strictly matches a specific named field or block in web/public/data/*.json or is documented in docs/audit_allowlist.txt.

Historical documents are excluded at file level with a visible banner.
Ratio claims (X of Y and X/Y) require (X, Y) to appear together in the same data object.
Bare integers without ratio or noun context are reported separately as informational.

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
sys.path.insert(0, str(ROOT))

from backend.verify import wilson_ci  # noqa: E402

DATA_DIR = ROOT / "web" / "public" / "data"
ALLOWLIST_FILE = ROOT / "docs" / "audit_allowlist.txt"

# Historical documents excluded from empirical claims audit at file level
EXCLUDED_FILES: dict[str, str] = {
    "docs/verification_report.md": (
        "Historical record from an earlier evaluation. Superseded by the confirmation runs; not current results."
    ),
    "docs/confirmation_report.md": (
        "Historical record from an earlier evaluation. Superseded by the confirmation runs; not current results."
    ),
}


def build_typed_field_index(
    data_dir: Path,
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[tuple[int, int], str]]:
    """Build exact typed mappings: token -> named field path in data JSON files.

    Returns:
        (dollar_fields, percentage_fields, count_fields, ratio_pairs)
    """
    dollar_fields: dict[str, str] = {}
    percentage_fields: dict[str, str] = {}
    count_fields: dict[str, str] = {}
    ratio_pairs: dict[tuple[int, int], str] = {}

    for path in sorted(data_dir.glob("*.json")):
        if any(skip in path.name for skip in ("limit_", "page_", "traces")):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # 1. Recurse for typed single fields (dollar, percentage, count)
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
                        if str_int not in count_fields or "summary.json" in field_path:
                            count_fields[str_int] = field_path

            elif isinstance(node, str):
                s = node.strip()
                if s.startswith("$"):
                    dollar_fields[s] = field_path
                elif s.endswith("%"):
                    percentage_fields[s] = field_path

        recurse(data, [])

        # 2. Block inspection for ratio pairs (count and n in the same data object/block)
        def process_block(block: dict, block_path: str, parent_denoms: set[int] | None = None) -> None:
            if not isinstance(block, dict):
                return

            denoms = set(parent_denoms or set())
            for k in (
                "n", "n_email", "n_standard", "n_probe", "total", "pooled_total",
                "repeats", "tasks_per_repeat", "total_evaluations_per_condition",
            ):
                v = block.get(k)
                if isinstance(v, int):
                    denoms.add(v)

            counts = set()
            for k, v in block.items():
                if isinstance(v, int) and k in (
                    "count", "passed", "failed", "pooled_passed", "m1", "m2", "m3", "m4", "unsafe"
                ):
                    counts.add(v)
                elif isinstance(v, dict):
                    c = v.get("count")
                    if isinstance(c, int):
                        counts.add(c)

            for c in counts:
                for d in denoms:
                    ratio_pairs[(c, d)] = f"{path.name}:{block_path}"
                    if d > 0:
                        low_ci, high_ci = wilson_ci(c, d)
                        percentage_fields[f"{low_ci * 100:.1f}%"] = f"{path.name}:{block_path}:wilson_ci"
                        percentage_fields[f"{high_ci * 100:.1f}%"] = f"{path.name}:{block_path}:wilson_ci"
                        percentage_fields[f"{low_ci * 100:.2f}%"] = f"{path.name}:{block_path}:wilson_ci"
                        percentage_fields[f"{high_ci * 100:.2f}%"] = f"{path.name}:{block_path}:wilson_ci"
                        percentage_fields[f"{low_ci * 100:.0f}%"] = f"{path.name}:{block_path}:wilson_ci"
                        percentage_fields[f"{high_ci * 100:.0f}%"] = f"{path.name}:{block_path}:wilson_ci"

            for k, v in block.items():
                if isinstance(v, dict):
                    p_denoms = denoms if block_path else None
                    child_path = f"{block_path}.{k}" if block_path else k
                    process_block(v, child_path, p_denoms)
                elif isinstance(v, list):
                    for idx, item in enumerate(v):
                        if isinstance(item, dict):
                            p_denoms = denoms if block_path else None
                            child_path = f"{block_path}.{k}[{idx}]" if block_path else f"{k}[{idx}]"
                            process_block(item, child_path, p_denoms)

        process_block(data, "")

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

    # Model pricing
    pricing_file = ROOT / "config" / "pricing.json"
    if pricing_file.exists():
        try:
            pricing = json.loads(pricing_file.read_text(encoding="utf-8"))
            for model, pdata in pricing.get("models", {}).items():
                for k, v in pdata.items():
                    fp = f"pricing.json:{model}.{k}"
                    if isinstance(v, (int, float)):
                        val = float(v)
                        dollar_fields[f"${val:.2f}"] = fp
                        dollar_fields[f"${val:.4f}"] = fp
                        if val.is_integer() or isinstance(v, int):
                            dollar_fields[f"${int(val)}"] = fp
        except Exception:
            pass

    return dollar_fields, percentage_fields, count_fields, ratio_pairs


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


def strip_historical_markers(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Find and strip blocks enclosed between <!-- audit:historical-start --> and <!-- audit:historical-end -->.

    Returns:
        (cleaned_text, list_of_line_ranges) where line ranges are (start_line, end_line) 1-indexed.
    """
    pattern = re.compile(
        r"<!--\s*audit:historical-start\s*-->.*?<!--\s*audit:historical-end\s*-->",
        flags=re.DOTALL,
    )
    ranges: list[tuple[int, int]] = []

    def repl(m: re.Match[str]) -> str:
        start_idx = m.start()
        end_idx = m.end()
        start_line = text.count("\n", 0, start_idx) + 1
        end_line = text.count("\n", 0, end_idx) + 1
        ranges.append((start_line, end_line))
        num_newlines = m.group(0).count("\n")
        return "\n" * num_newlines

    cleaned = pattern.sub(repl, text)
    return cleaned, ranges


def extract_claims_from_text(text: str, filename: str) -> list[dict[str, Any]]:
    """Extract claims (dollar amounts, percentages, ratios, and context counts) from text."""
    claims: list[dict[str, Any]] = []

    # Strip code blocks with code syntax / shell commands to avoid arbitrary flags/ports
    text_clean = re.sub(r"```[a-zA-Z0-9_-]*\n.*?```", "", text, flags=re.DOTALL)
    text_clean = re.sub(r"`[^`\n]+`", " ", text_clean)  # inline code
    text_clean = re.sub(r"<style>.*?</style>", "", text_clean, flags=re.DOTALL)
    text_clean = re.sub(r"<script.*?</script>", "", text_clean, flags=re.DOTALL)
    text_clean = re.sub(r"<!--.*?-->", "", text_clean, flags=re.DOTALL)

    covered_spans: list[tuple[int, int]] = []

    def covers(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in covered_spans)

    # 1. Dollar amounts: e.g. $4.17, $12.40, $0.08
    for m in re.finditer(r"(\$[0-9]+(?:\.[0-9]+)?)", text_clean):
        covered_spans.append(m.span())
        claims.append({
            "token": m.group(1),
            "type": "dollar",
            "file": filename,
            "raw": m.group(1),
        })

    # 2. Percentages: e.g. 71.6%, 25.8%, 0.0%
    for m in re.finditer(r"\b([0-9]+(?:\.[0-9]+)?%)", text_clean):
        covered_spans.append(m.span())
        claims.append({
            "token": m.group(1),
            "type": "percentage",
            "file": filename,
            "raw": m.group(1),
        })

    # 3. Ratio claims: e.g. "49 of 150", "0/150", "8 of 45"
    for m in re.finditer(r"\b([0-9]+)\s*(?:of|/)\s*([0-9]+)\b", text_clean, flags=re.IGNORECASE):
        covered_spans.append(m.span())
        c_val = int(m.group(1))
        d_val = int(m.group(2))
        claims.append({
            "token": f"{c_val} of {d_val}",
            "type": "ratio",
            "pair": (c_val, d_val),
            "file": filename,
            "raw": m.group(0),
        })

    # 4. Counts with substantive noun context
    for m in re.finditer(
        r"\b([0-9]+)\s+(?:attacks|unsafe|breached|probes|evaluations|tasks|rules|iterations|tokens|matches|lines|runs)\b",
        text_clean,
        flags=re.IGNORECASE,
    ):
        if not covers(m.start(1), m.end(1)):
            covered_spans.append(m.span())
            claims.append({
                "token": m.group(1),
                "type": "count",
                "file": filename,
                "raw": m.group(0),
            })

    # 5. Bare integers with no ratio and no noun context
    for m in re.finditer(r"\b([0-9]+)\b", text_clean):
        if not covers(m.start(), m.end()):
            claims.append({
                "token": m.group(1),
                "type": "bare_integer",
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

    dollar_fields, percentage_fields, count_fields, ratio_pairs = build_typed_field_index(DATA_DIR)

    # Collect targets and enforce file-level exclusions
    target_files: list[Path] = []
    excluded_files_found: list[tuple[str, str]] = []

    candidates: list[Path] = []
    # Root markdown
    for fn in ["README.md", "FEEDBACK.md"]:
        p = ROOT / fn
        if p.exists():
            candidates.append(p)

    # docs/*.md
    for p in (ROOT / "docs").glob("*.md"):
        candidates.append(p)

    # Rendered HTML from web/out
    html_dir = Path(args.html_dir)
    if html_dir.exists():
        for p in [
            html_dir / "index.html",
            html_dir / "results" / "index.html",
            html_dir / "policy" / "index.html",
            html_dir / "report" / "index.html",
            html_dir / "live" / "index.html",
        ]:
            if p.exists():
                candidates.append(p)

    for cand in candidates:
        rel_posix = cand.relative_to(ROOT).as_posix()
        if rel_posix in EXCLUDED_FILES:
            excluded_files_found.append((rel_posix, EXCLUDED_FILES[rel_posix]))
        else:
            target_files.append(cand)

    all_claims: list[dict[str, Any]] = []
    excluded_ranges_by_file: dict[str, list[tuple[int, int]]] = {}
    for tf in target_files:
        rel_name = tf.relative_to(ROOT).as_posix()
        content = tf.read_text(encoding="utf-8", errors="ignore")
        cleaned_content, ex_ranges = strip_historical_markers(content)
        if ex_ranges:
            excluded_ranges_by_file[rel_name] = ex_ranges
        claims = extract_claims_from_text(cleaned_content, rel_name)
        all_claims.extend(claims)

    matched: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    bare_integers: list[dict[str, Any]] = []

    for c in all_claims:
        tok = c["token"]
        c_type = c["type"]
        file_key = f"{c['file']}:{tok}"
        matched_field: str | None = None

        if c_type == "bare_integer":
            c["status"] = "INFORMATIONAL"
            c["field_path"] = "Bare integer (informational, not matched)"
            bare_integers.append(c)
            continue

        if c_type == "dollar":
            matched_field = dollar_fields.get(tok)
        elif c_type == "percentage":
            matched_field = percentage_fields.get(tok)
        elif c_type == "count":
            matched_field = count_fields.get(tok)
        elif c_type == "ratio":
            matched_field = ratio_pairs.get(c["pair"])

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
    print("GAUNTLET EMPIRICAL CLAIMS AUDIT REPORT")
    print("=" * 105)

    print("\nFILES EXCLUDED (file-level exclusions):")
    for fn, reason in excluded_files_found:
        print(f"  - {fn}: {reason}")

    if excluded_ranges_by_file:
        print("\nHISTORICAL SECTION EXCLUSIONS (in-file markers):")
        for fn, rngs in excluded_ranges_by_file.items():
            print(f"  {fn}:")
            for s, e in rngs:
                print(f"    - Lines {s}–{e}")

    print("\nALLOWLISTED TOKENS BY FILE:")
    if not allowlisted:
        print("  None (all claims passed by matching)")
    else:
        allowlisted_by_file: dict[str, list[dict[str, Any]]] = {}
        for c in allowlisted:
            allowlisted_by_file.setdefault(c["file"], []).append(c)
        for fn, items in allowlisted_by_file.items():
            print(f"  {fn}:")
            for it in items:
                print(f"    - '{it['token']}': {it['field_path']}")

    print("\n" + "-" * 105)
    print(f"{'FILE':<32} {'TOKEN':<16} {'TYPE':<14} {'STATUS':<14} {'FIELD PATH / NOTE'}")
    print("-" * 105)
    for c in matched[:20]:
        print(f"{c['file'][:31]:<32} {c['token'][:15]:<16} {c['type']:<14} {c['status']:<14} {c['field_path'][:45]}")
    if len(matched) > 20:
        print(f"... and {len(matched) - 20} more MATCHED-BY-FIELD claims.")

    if unmatched:
        print("\n" + "!" * 105)
        print(f"UNMATCHED CLAIMS DETECTED ({len(unmatched)} items):")
        print("!" * 105)
        for c in unmatched:
            print(f"{c['file'][:31]:<32} {c['token'][:15]:<16} {c['type']:<14} {c['raw']:<16} {c['field_path']}")

    print("\nSUMMARY:")
    print(f"  Files excluded:               {len(excluded_files_found)}")
    print(f"  Historical blocks excluded:   {sum(len(r) for r in excluded_ranges_by_file.values())}")
    print(f"  Matched-by-field:             {len(matched)}")
    print(f"  Allowlisted:                  {len(allowlisted)}")
    print(f"  Unmatched:                    {len(unmatched)}")
    print(f"  Bare integers (informational): {len(bare_integers)}")
    print("=" * 105 + "\n")

    if unmatched:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
