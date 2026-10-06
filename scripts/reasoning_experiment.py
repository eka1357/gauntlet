"""Reasoning-control experiment for Nemotron models on Token Factory.

For each role (lightning, nano, super) and each variant, call the model via
call_model() with a tiny JSON task and record where the answer appeared,
whether it parsed as valid JSON, completion tokens, finish reason and
latency. Results are written to docs/experiments/ so findings trace back
to stored data. Never prints the API key.

Variants:
    a_default            max_tokens=1024, no reasoning controls
    b_enable_thinking    + extra_body chat_template_kwargs.enable_thinking=False
    c_effort_none        + reasoning_effort="none"   (documented request param)
    c_effort_low         + reasoning_effort="low"
    d_system_prompt      + system prompt asking for no reasoning

Usage: python scripts/reasoning_experiment.py [--reps N]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

TASK = 'Return only JSON: {"channel": "email", "subject": "<a short fake invoice subject>"}'
NO_REASONING_SYSTEM = (
    "Answer directly. Do not reason, think step by step, or explain. Output only the final answer."
)
ROLES = ["lightning", "nano", "super"]

# Every variant sets or clears every reasoning control explicitly, so
# role request_defaults in models.yaml cannot leak into the comparison.
_CLEAR = {"reasoning_effort": None, "extra_body": None, "system_prompt": None}
VARIANTS: dict[str, dict] = {
    "a_default": {**_CLEAR, "max_tokens": 1024},
    "b_enable_thinking": {
        **_CLEAR,
        "max_tokens": 1024,
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
    },
    "c_effort_none": {**_CLEAR, "max_tokens": 1024, "reasoning_effort": "none"},
    "c_effort_low": {**_CLEAR, "max_tokens": 1024, "reasoning_effort": "low"},
    "d_system_prompt": {
        **_CLEAR,
        "max_tokens": 1024,
        "system_prompt": NO_REASONING_SYSTEM,
    },
}

OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "experiments"


class InvoiceSubject(BaseModel):
    """Expected shape of the task's JSON answer."""

    channel: Literal["email"]
    subject: str = Field(min_length=1)


async def run_one(role: str, variant: str, params: dict) -> dict:
    """Run a single call and return a result row."""
    from backend.cost import get_ledger
    from backend.llm import call_model, get_model_id, validate_json

    row: dict = {"role": role, "model": get_model_id(role), "variant": variant}
    n_before = len(get_ledger().records)
    start = time.perf_counter()
    try:
        text = await call_model(
            role=role,
            messages=[{"role": "user", "content": TASK}],
            params=params,
        )
    except Exception as e:  # report exact error, never substitute output
        row.update(
            ok=False,
            error=f"{type(e).__name__}: {e}",
            latency_ms=round((time.perf_counter() - start) * 1000),
        )
        return row

    rec = get_ledger().records[n_before]
    strict_json = True
    try:
        json.loads(text)
    except json.JSONDecodeError:
        strict_json = False
    try:
        validate_json(text, InvoiceSubject)
        valid = True
    except Exception:
        valid = False

    row.update(
        ok=True,
        source=rec.source,
        reasoning_field_present=rec.reasoning_present,
        finish_reason=rec.finish_reason,
        valid_json=valid,
        strict_json=strict_json,
        prompt_tokens=rec.prompt_tokens,
        completion_tokens=rec.completion_tokens,
        latency_ms=round(rec.latency_ms),
        answer=text,
    )
    return row


def _fmt(row: dict) -> str:
    if not row["ok"]:
        return (
            f"{row['role']:<10}{row['variant']:<19}ERROR {row['latency_ms']:>6}ms  "
            f"{row['error'][:110]}"
        )
    preview = row["answer"].replace("\n", " ")[:46]
    return (
        f"{row['role']:<10}{row['variant']:<19}"
        f"{row['source']:<18}{'yes' if row['reasoning_field_present'] else 'no':<6}"
        f"{'yes' if row['valid_json'] else 'NO':<6}{'yes' if row['strict_json'] else 'no':<7}"
        f"{str(row['finish_reason']):<8}{row['completion_tokens']:>6}"
        f"{row['latency_ms']:>8}  {preview}"
    )


async def main() -> None:
    """Run the experiment grid sequentially and save results."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=2)
    args = parser.parse_args()

    from backend.cost import get_ledger

    print(
        f"{'role':<10}{'variant':<19}{'source':<18}{'rfld':<6}{'json':<6}"
        f"{'strict':<7}{'finish':<8}{'c_tok':>6}{'ms':>8}  answer"
    )
    rows: list[dict] = []
    for role in ROLES:
        for variant, params in VARIANTS.items():
            for rep in range(args.reps):
                row = await run_one(role, variant, params)
                row["rep"] = rep
                rows.append(row)
                print(_fmt(row), flush=True)

    ledger = get_ledger()
    print(
        f"\nCalls: {len(ledger.records)}  tokens: {ledger.total_prompt_tokens} in + "
        f"{ledger.total_completion_tokens} out"
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = OUT_DIR / f"reasoning_{stamp}.json"
    out.write_text(
        json.dumps(
            {
                "task": TASK,
                "system_prompt_variant_d": NO_REASONING_SYSTEM,
                "variants": VARIANTS,
                "reps": args.reps,
                "rows": rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Saved: {out.relative_to(OUT_DIR.parent.parent)}")
    if any(not r["ok"] for r in rows):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
