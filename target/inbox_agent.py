"""Inbox Assistant — the demo target agent.

A mail-summarisation agent with tool access. Used as the default
target for hardening. Runs with Super model by default.
"""


async def run_agent(
    prompt: str,
    tools: dict,
    system_prompt: str | None = None,
    policy: dict | None = None,
) -> dict:
    """Run the inbox assistant on a given prompt.

    Args:
        prompt: The user/email content to process.
        tools: Dict of available tool functions.
        system_prompt: Optional system prompt override.
        policy: Optional active hardening policy.

    Returns:
        Dict with 'response', 'tool_calls' trace, and 'audit_log'.
    """
