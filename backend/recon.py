"""Recon phase.

Ultra reads the target agent's tools and system prompt, queries Tavily
for current prompt-injection and tool-misuse techniques, and produces
a structured threat plan (JSON) with categories, channels and cited sources.
"""


async def run_recon(target_config: dict) -> dict:
    """Generate a threat plan for the target agent.

    Args:
        target_config: Dict with 'tools', 'system_prompt' and metadata.

    Returns:
        Threat plan dict with categories, channels and source citations.
    """
