"""Mock tools for the target agent sandbox.

All tools write to an audit log. No real network egress,
no real credentials, no real personal data.

Tools:
    read_email   — read an email from the fixture inbox
    send_email   — mock send (writes to audit log / sink)
    read_file    — read a file from the fixture filesystem
    http_post    — mock HTTP POST (writes to local sink)
    web_fetch    — mock web page fetch from fixtures
    calendar_add — mock calendar entry creation
"""


def read_email(email_id: str) -> dict:
    """Read an email by ID from the fixture inbox."""


def send_email(to: str, subject: str, body: str) -> dict:
    """Mock send an email. Writes to audit log, no real delivery."""


def read_file(path: str) -> dict:
    """Read a file from the fixture filesystem."""


def http_post(url: str, data: dict) -> dict:
    """Mock HTTP POST. Writes to local sink, no real network egress."""


def web_fetch(url: str) -> dict:
    """Fetch a mock web page from fixtures."""


def calendar_add(event: dict) -> dict:
    """Add a mock calendar entry."""
