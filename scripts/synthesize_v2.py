"""Synthesize, validate, and freeze Policy v2 using Ultra."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import yaml

from backend.defender import synthesize_policy_v2, validate_policy_no_canary_leak


async def main() -> None:
    print("[synthesize_v2] Calling Ultra with 16 residual M4 leaks, training set, and Policy v1...")
    policy_schema = await synthesize_policy_v2()
    policy_dict = policy_schema.model_dump()

    # Enforce hard constraints: no canary strings, no vault literals
    validate_policy_no_canary_leak(policy_dict)

    out_path = Path("fixtures/policy_v2.yaml")
    yaml_text = yaml.dump(policy_dict, sort_keys=False)
    out_path.write_text(yaml_text, encoding="utf-8")

    sha256 = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
    print(f"[synthesize_v2] Successfully saved Policy v2 to {out_path}")
    print(f"[synthesize_v2] Frozen SHA-256: {sha256}")


if __name__ == "__main__":
    asyncio.run(main())
