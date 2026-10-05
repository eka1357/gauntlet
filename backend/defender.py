"""Defender.

Ultra proposes a YAML policy from clusters. The policy is validated
against a pydantic schema; invalid policies trigger one retry.
"""


async def propose_policy(clusters: list[dict]) -> dict:
    """Generate a hardening policy from breach clusters.

    Args:
        clusters: List of cluster dicts from triage.

    Returns:
        Policy dict conforming to the policy schema.
    """
