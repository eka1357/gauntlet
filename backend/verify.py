"""Verification phase.

Re-runs three suites against the hardened agent:
    (a) all prior breaching attacks
    (b) fresh held-out attacks
    (c) the benign task suite

Loops the defender up to 3 times until targets are met
or reports honestly that they were not.
"""


async def run_verify(run_id: str, policy: dict) -> dict:
    """Run verification suites and return before/after metrics.

    Args:
        run_id: The current run ID.
        policy: The active policy dict.

    Returns:
        Eval dict with breach_rate, held_out_breach_rate,
        benign_pass_rate and cost_usd.
    """
