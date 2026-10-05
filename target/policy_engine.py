"""Policy engine.

Enforces YAML hardening policies at the tool layer.
Deterministic checks — no model calls during enforcement.

Policy schema (from REQUIREMENTS.md):
    version: 1
    egress: { allow: [...] }
    tools:
      send_email: { allow_recipients: [...], require_approval_if: [...] }
      http_post: { deny: true }
      read_file: { deny_paths: [...] }
    untrusted_content: { label: true, strip_tool_instructions: true }
"""


def enforce(tool_name: str, args: dict, policy: dict) -> dict:
    """Check a tool call against the active policy.

    Args:
        tool_name: Name of the tool being called.
        args: Arguments to the tool call.
        policy: The active policy dict.

    Returns:
        Dict with 'allowed' bool and 'reason' if blocked.
    """
