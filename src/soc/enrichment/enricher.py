"""Deterministic enrichment.

Adds context to alerts: geo IP, local asset criticality, threat intel
IOC lookups, historical context. All enrichments become Evidence records
that AI MAY cite, but enrichment itself is deterministic.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Case, Evidence, EvidenceSource
from ..threat_intel.iocs import ThreatIntelFeed


class Enricher:
    def __init__(self, ti_feed: Optional[ThreatIntelFeed] = None):
        self.ti = ti_feed or ThreatIntelFeed.default()

    def enrich(self, case: Case) -> List[Evidence]:
        out: List[Evidence] = []
        for alert in case.alerts:
            # TI enrichment on any IP entities
            for key in ("src_ip", "dst_ip"):
                ip = alert.entities.get(key)
                if not ip:
                    continue
                hit = self.ti.lookup_ip(ip)
                if hit:
                    out.append(Evidence(
                        source=EvidenceSource.THREAT_INTEL,
                        reference=ip,
                        description=f"TI hit on {key} {ip}",
                        data=hit,
                    ))
            # Asset criticality stub
            host = alert.entities.get("host")
            if host:
                crit = _ASSET_CRITICALITY.get(host, "low")
                out.append(Evidence(
                    source=EvidenceSource.ENRICHMENT,
                    reference=host,
                    description=f"Asset criticality for {host}",
                    data={"host": host, "criticality": crit},
                ))
        case.enrichments.extend(out)
        return out


# Deterministic asset inventory stub — replace with CMDB feed.
_ASSET_CRITICALITY: Dict[str, str] = {
    "dc01.corp.local": "critical",
    "jump01.corp.local": "high",
    "web02.corp.local": "medium",
    "wkstn-42.corp.local": "low",
}
