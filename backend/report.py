"""Report generation.

Produces the hardening report as structured data and
downloadable HTML/Markdown. Includes summary, clusters,
policy, before/after metrics, cost and source citations.
"""


async def generate_report(run_id: str) -> dict:
    """Generate the hardening report for a completed run.

    Args:
        run_id: The run to report on.

    Returns:
        Report dict with all sections.
    """
