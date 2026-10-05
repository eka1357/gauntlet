"""Triage and clustering.

Ultra clusters breaches by root cause, assigns severity,
writes a plain-language explanation, and selects a minimal
reproduction attack for each cluster.
"""


async def cluster_breaches(breaches: list[dict]) -> list[dict]:
    """Cluster breaches by root cause.

    Args:
        breaches: List of breach dicts with traces.

    Returns:
        List of cluster dicts with title, severity, root_cause,
        attack_ids and repro_attack_id.
    """
