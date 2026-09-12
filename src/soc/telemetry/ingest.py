"""Telemetry ingestion.

Accepts raw records from any source, normalizes them into TelemetryEvent
objects, and attaches them to a Case. This module is purely mechanical:
no AI, no detection decisions.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional

from ..models import Case, TelemetryEvent


class TelemetryIngestor:
    def __init__(self):
        self._recv_count = 0

    def ingest(
        self,
        case: Case,
        raw_events: Iterable[Dict[str, Any]],
        source: str = "unknown",
    ) -> List[TelemetryEvent]:
        """Normalize raw events and attach to the case."""
        normalized: List[TelemetryEvent] = []
        for raw in raw_events:
            ev = TelemetryEvent(
                source=raw.get("source", source),
                host=raw.get("host"),
                src_ip=raw.get("src_ip"),
                dst_ip=raw.get("dst_ip"),
                user=raw.get("user"),
                process=raw.get("process"),
                command_line=raw.get("command_line"),
                raw=raw,
                labels=raw.get("labels", {}),
            )
            case.events.append(ev)
            normalized.append(ev)
            self._recv_count += 1
        return normalized

    @property
    def received(self) -> int:
        return self._recv_count
