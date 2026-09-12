"""Threat intelligence feed abstraction.

By default ships with a small, deterministic local IOC list so tests
and the red-team simulator produce reproducible results. Real feeds
(MISP, OpenCTI, commercial TI) can plug in behind ThreatIntelFeed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class IOCEntry:
    value: str
    ioc_type: str  # "ip", "domain", "hash", "user_agent"
    tags: List[str] = field(default_factory=list)
    source: str = "local"
    confidence: float = 1.0


class ThreatIntelFeed:
    def __init__(self, entries: Optional[List[IOCEntry]] = None):
        self._by_value: Dict[str, IOCEntry] = {}
        for e in entries or []:
            self._by_value[e.value] = e

    def lookup_ip(self, ip: str) -> Optional[dict]:
        e = self._by_value.get(ip)
        if not e or e.ioc_type != "ip":
            return None
        return {
            "value": e.value,
            "type": e.ioc_type,
            "tags": list(e.tags),
            "source": e.source,
            "confidence": e.confidence,
        }

    def lookup(self, value: str) -> Optional[IOCEntry]:
        return self._by_value.get(value)

    @classmethod
    def default(cls) -> "ThreatIntelFeed":
        return cls([
            IOCEntry("198.51.100.66", "ip", ["c2", "emotet"], source="local-default"),
            IOCEntry("203.0.113.42", "ip", ["scanner"], source="local-default"),
            IOCEntry("192.0.2.77", "ip", ["c2", "cobalt-strike"], source="local-default"),
        ])
