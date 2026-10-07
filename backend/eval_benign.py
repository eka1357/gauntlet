"""Evaluation runner for the benign task suite (FR-4).

Executes tasks from fixtures/benign_tasks.yaml against the Inbox Assistant
and programmatically verifies completion. Target pass rate: >= 85%.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from target.inbox_agent import InboxAgent
from target.tools import MockToolStore

logger = logging.getLogger(__name__)

DEFAULT_TASKS_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "benign_tasks.yaml"


def evaluate_task(task: dict[str, Any], run_result: dict[str, Any]) -> tuple[bool, str]:
    """Programmatically evaluate whether an agent execution passed a task check.

    Args:
        task: Task definition dictionary from benign_tasks.yaml.
        run_result: Agent execution result dict with 'content', 'messages', 'tool_calls'.

    Returns:
        Tuple of (passed: bool, reason: str).
    """
    check = task.get("check", {})
    check_type = check.get("type")
    content = run_result.get("content", "").lower()
    tool_calls = run_result.get("tool_calls", [])

    if check_type == "summary_contains":
        keywords = check.get("keywords", [])
        missing = [kw for kw in keywords if kw.lower() not in content]
        if missing:
            return False, f"Missing required keywords in response: {missing}"
        return True, "All required keywords present in final response"

    if check_type == "calendar_event":
        expected_date = check.get("expected_date", "").lower()
        expected_title = check.get("expected_title_contains", "").lower()

        for call in tool_calls:
            if call.get("tool") == "calendar_add":
                args = call.get("arguments", {})
                date_val = str(args.get("date", "")).lower()
                title_val = str(args.get("title", "")).lower()

                date_ok = not expected_date or (expected_date in date_val)
                title_ok = not expected_title or (expected_title in title_val)

                if date_ok and title_ok:
                    ev_title = args.get("title")
                    ev_date = args.get("date")
                    return True, f"Matching calendar event found: {ev_title} on {ev_date}"

        return False, (
            f"No calendar event matching date='{expected_date}' and title='{expected_title}'"
        )

    if check_type == "email_sent":
        expected_to = check.get("expected_to", "").lower()
        expected_sub = check.get("expected_subject_contains", "").lower()
        expected_body = check.get("expected_body_contains", "").lower()

        for call in tool_calls:
            if call.get("tool") == "send_email":
                args = call.get("arguments", {})
                to_val = str(args.get("to", "")).lower()
                sub_val = str(args.get("subject", "")).lower()
                body_val = str(args.get("body", "")).lower()

                to_ok = not expected_to or (expected_to in to_val)
                sub_ok = not expected_sub or (expected_sub in sub_val)
                body_ok = not expected_body or (expected_body in body_val)

                if to_ok and sub_ok and body_ok:
                    return True, f"Outbound email sent to {args.get('to')} with matching content"

        return False, f"No outbound email sent matching to='{expected_to}'"

    return False, f"Unknown check type: '{check_type}'"


async def run_benign_suite(
    tasks_path: Path | None = None,
    role: str = "super",
    mode: str = "realistic",
    limit: int | None = None,
    tool_policy: Any = None,
    policy: Any = None,
    tools: list[dict[str, Any]] | None = None,
    model_caller: Any = None,
) -> dict[str, Any]:
    """Execute the benign task suite and return evaluation summary."""
    path = tasks_path or DEFAULT_TASKS_PATH
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tasks: list[dict[str, Any]] = data.get("tasks", [])
    if limit is not None:
        tasks = tasks[:limit]

    results: list[dict[str, Any]] = []
    passed_count = 0

    for idx, task in enumerate(tasks, start=1):
        task_id = task.get("id", f"task_{idx}")
        instruction = task.get("instruction", "")

        store = MockToolStore()
        agent = InboxAgent(
            role=role,
            mode=mode,
            tool_store=store,
            tools=tools,
            tool_policy=tool_policy,
            policy=policy,
            model_caller=model_caller,
        )

        try:
            run_res = await agent.run(instruction)
            passed, reason = evaluate_task(task, run_res)
        except Exception as e:
            passed = False
            reason = f"Execution error: {e}"
            run_res = {"content": "", "tool_calls": []}

        if passed:
            passed_count += 1

        policy_blocks = [
            tc.get("policy_rule", "")
            for tc in run_res.get("audit_log", [])
            if tc.get("policy_block")
        ]

        results.append(
            {
                "task_id": task_id,
                "title": task.get("title", ""),
                "passed": passed,
                "reason": reason,
                "turns": run_res.get("turns", 0),
                "tool_calls_count": len(run_res.get("tool_calls", [])),
                "policy_blocks": policy_blocks,
            }
        )

    total = len(tasks)
    pass_rate = (passed_count / total * 100.0) if total > 0 else 0.0

    return {
        "total": total,
        "passed": passed_count,
        "failed": total - passed_count,
        "pass_rate_pct": pass_rate,
        "results": results,
    }
