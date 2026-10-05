"""Run orchestrator.

Coordinates the full hardening loop:
    recon → attack → triage → defend → verify → report.

Manages run lifecycle, emits SSE events, and stores results.
"""


async def run_hardening_loop(run_id: str) -> None:
    """Execute the complete hardening loop for a given run."""
