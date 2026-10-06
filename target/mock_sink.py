"""Local sink for mock network egress (send_email and http_post).

Guarantees 0% network egress by capturing all outbound payloads to an in-memory
store (or optional isolated local file). Thread-safe and concurrency-isolated.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_SINK_PATH = Path(__file__).resolve().parent / "mock_sink.json"


class MockSink:
    """In-memory or file-backed sink for capturing outbound network payloads."""

    def __init__(self, disk_path: Path | str | None = None) -> None:
        """Initialize mock sink.

        Args:
            disk_path: Optional path to write sink records on disk.
                       If None, operates purely in memory with zero disk I/O.
        """
        self.disk_path = Path(disk_path) if disk_path is not None else None
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.disk_path is not None and self.disk_path.is_file():
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        if self.disk_path is not None and self.disk_path.is_file():
            try:
                with open(self.disk_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self._entries = data
            except Exception:
                self._entries = []

    def record(self, entry: dict[str, Any]) -> None:
        """Record an outbound payload into the sink."""
        record_item = {
            **entry,
            "timestamp": time.time(),
        }
        with self._lock:
            self._entries.append(record_item)
            if self.disk_path is not None:
                self.disk_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.disk_path, "w", encoding="utf-8") as f:
                    json.dump(self._entries, f, indent=2)

    def read(self) -> list[dict[str, Any]]:
        """Return all recorded payloads."""
        with self._lock:
            if self.disk_path is not None and self.disk_path.is_file():
                self._load_from_disk()
            return [dict(e) for e in self._entries]

    def clear(self) -> None:
        """Clear all records from the sink."""
        with self._lock:
            self._entries.clear()
            if self.disk_path is not None and self.disk_path.is_file():
                with open(self.disk_path, "w", encoding="utf-8") as f:
                    json.dump([], f)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# Default global sink instance (in-memory by default)
_global_sink = MockSink()


def get_default_sink() -> MockSink:
    """Return default global in-memory sink."""
    return _global_sink


def record_to_sink(entry: dict[str, Any], sink_path: Path | str | None = None) -> None:
    """Append a record to the mock sink (file-backed if sink_path specified, else global)."""
    if sink_path is not None:
        sink = MockSink(disk_path=sink_path)
        sink.record(entry)
    else:
        _global_sink.record(entry)


def read_sink(sink_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Read all entries from the mock sink."""
    if sink_path is not None:
        sink = MockSink(disk_path=sink_path)
        return sink.read()
    return _global_sink.read()


def clear_sink(sink_path: Path | str | None = None) -> None:
    """Clear all records from the mock sink."""
    if sink_path is not None:
        sink = MockSink(disk_path=sink_path)
        sink.clear()
    else:
        _global_sink.clear()
