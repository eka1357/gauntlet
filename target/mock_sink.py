"""Local sink for mock network egress (send_email and http_post).

Guarantees 0% network egress by capturing all outbound payloads to a local file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

DEFAULT_SINK_PATH = Path(__file__).resolve().parent / "mock_sink.json"


def get_sink_path(override: Path | str | None = None) -> Path:
    """Return the active sink path."""
    if override is not None:
        return Path(override)
    return DEFAULT_SINK_PATH


def record_to_sink(entry: dict[str, Any], sink_path: Path | str | None = None) -> None:
    """Append a record to the mock sink file."""
    path = get_sink_path(sink_path)
    records: list[dict[str, Any]] = []
    if path.is_file():
        try:
            with open(path, encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []

    record_item = {
        **entry,
        "timestamp": time.time(),
    }
    records.append(record_item)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def read_sink(sink_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Read all entries from the mock sink file."""
    path = get_sink_path(sink_path)
    if not path.is_file():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def clear_sink(sink_path: Path | str | None = None) -> None:
    """Clear all records from the mock sink file."""
    path = get_sink_path(sink_path)
    if path.is_file():
        with open(path, "w", encoding="utf-8") as f:
            json.dump([], f)
