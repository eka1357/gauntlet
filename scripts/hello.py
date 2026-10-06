"""Hello script — smoke-test all model roles against real Token Factory.

Calls ultra, super, lightning and nano once each with a tiny prompt.
Prints role, model ID, latency, tokens, content source, and first 80 chars.
Never prints the API key.
"""

from __future__ import annotations

import asyncio
import sys
import time

from dotenv import load_dotenv

load_dotenv()


async def main() -> None:
    """Run a single call to each role and print diagnostics."""
    # Import after dotenv so env is loaded
    from backend.cost import format_cost, get_ledger
    from backend.llm import call_model, get_model_id

    roles = ["ultra", "super", "lightning", "nano"]
    prompt = "Reply with the single word: ready"
    messages = [{"role": "user", "content": prompt}]

    print("=" * 80)
    print("Gauntlet - Model Smoke Test")
    print("=" * 80)
    print()

    overall_start = time.monotonic()
    errors: list[str] = []

    for role in roles:
        model_id = get_model_id(role)
        print(f"--- {role} ({model_id}) ---", flush=True)

        start = time.monotonic()
        try:
            result = await call_model(
                role=role,
                messages=messages,
                max_tokens=32,
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            # Get last recorded call from ledger
            ledger = get_ledger()
            rec = ledger.records[-1]

            answer = str(result).replace("\n", " ")
            cost_str = format_cost(rec)

            print(f"  model:       {model_id}")
            print(f"  latency:     {elapsed_ms:.0f} ms")
            print(f"  prompt_tok:  {rec.prompt_tokens}")
            print(f"  compl_tok:   {rec.completion_tokens}")
            print(f"  source:      {rec.source}")
            print(f"  cost:        {cost_str}")
            print(f"  answer:      {answer[:80]}", flush=True)
            print()

        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            error_msg = f"{role}: {type(e).__name__}: {e}"
            errors.append(error_msg)
            print(f"  ERROR:       {error_msg}")
            print(f"  latency:     {elapsed_ms:.0f} ms")
            print()

    total_time = time.monotonic() - overall_start
    ledger = get_ledger()

    print("=" * 80)
    print(f"Total time:    {total_time:.1f}s")
    print(f"Total calls:   {len(ledger.records)}")
    print(f"Total tokens:  {ledger.total_prompt_tokens} in + "
          f"{ledger.total_completion_tokens} out")
    total_cost_str = (
        "price not set"
        if all(not r.price_set for r in ledger.records)
        else f"${ledger.total_cost_usd:.6f}"
    )
    print(f"Total cost:    {total_cost_str}")

    if errors:
        print()
        print("ERRORS:")
        for err in errors:
            print(f"  - {err}")

    print("=" * 80)

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
