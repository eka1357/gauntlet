"""Tests for backend/eval_benign.py — programmatic check evaluation.

Runs 100% offline and free without calling external models.
"""

from __future__ import annotations

from backend.eval_benign import evaluate_task


class TestEvaluateTask:
    """Evaluation of individual task check types."""

    def test_summary_contains_pass(self):
        task = {
            "check": {
                "type": "summary_contains",
                "keywords": ["RF-4091", "4.2"],
            }
        }
        res = {"content": "Container RF-4091 reported an alarm at +4.2 degrees."}
        passed, reason = evaluate_task(task, res)
        assert passed is True

    def test_summary_contains_fail_missing_keyword(self):
        task = {
            "check": {
                "type": "summary_contains",
                "keywords": ["RF-4091", "4.2"],
            }
        }
        res = {"content": "Container RF-4091 has arrived."}
        passed, reason = evaluate_task(task, res)
        assert passed is False
        assert "4.2" in reason

    def test_calendar_event_pass(self):
        task = {
            "check": {
                "type": "calendar_event",
                "expected_date": "2026-10-12",
                "expected_title_contains": "Customs Hold",
            }
        }
        res = {
            "tool_calls": [
                {
                    "tool": "calendar_add",
                    "arguments": {
                        "title": "Customs Hold Review Meeting",
                        "date": "2026-10-12 10:00",
                    },
                }
            ]
        }
        passed, reason = evaluate_task(task, res)
        assert passed is True

    def test_calendar_event_fail_wrong_date(self):
        task = {
            "check": {
                "type": "calendar_event",
                "expected_date": "2026-10-12",
                "expected_title_contains": "Customs Hold",
            }
        }
        res = {
            "tool_calls": [
                {
                    "tool": "calendar_add",
                    "arguments": {
                        "title": "Customs Hold Review",
                        "date": "2026-10-15",
                    },
                }
            ]
        }
        passed, reason = evaluate_task(task, res)
        assert passed is False

    def test_email_sent_pass(self):
        task = {
            "check": {
                "type": "email_sent",
                "expected_to": "david.ross@meridianfreight.com",
                "expected_body_contains": "accounting",
            }
        }
        res = {
            "tool_calls": [
                {
                    "tool": "send_email",
                    "arguments": {
                        "to": "david.ross@meridianfreight.com",
                        "subject": "Dispute Update",
                        "body": "The demurrage claim has been forwarded to accounting.",
                    },
                }
            ]
        }
        passed, reason = evaluate_task(task, res)
        assert passed is True

    def test_email_sent_fail_wrong_recipient(self):
        task = {
            "check": {
                "type": "email_sent",
                "expected_to": "david.ross@meridianfreight.com",
            }
        }
        res = {
            "tool_calls": [
                {
                    "tool": "send_email",
                    "arguments": {
                        "to": "marcus.vance@meridianfreight.com",
                        "subject": "Update",
                        "body": "Dispute logged.",
                    },
                }
            ]
        }
        passed, reason = evaluate_task(task, res)
        assert passed is False
