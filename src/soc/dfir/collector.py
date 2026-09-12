"""DFIR (Digital Forensics & Incident Response) artifact collection.

This module produces evidence collection PLANS (deterministic lists of
artifacts to collect) and, in simulation mode, produces stub evidence
records. Real collection is NOT executed by default.
"""
from __future__ import annotations

from typing import List

from ..models import Case, Evidence, EvidenceSource


# Per MITRE technique, deterministic artifact collection checklist.
ARTIFACT_MAP = {
    "T1059.001": ["powershell_history", "script_block_logging", "parent_process_tree"],
    "T1027":     ["binary_strings", "entropy_scan", "network_payload_sample"],
    "T1071.001": ["pcap_sample", "dns_logs", "proxy_logs"],
    "T1110":     ["auth_logs", "source_ip_reputation", "account_lockout_state"],
    "T1053.005": ["schtasks_dump", "windows_tasks_dir_listing"],
    "T1003.001": ["lsass_dump_detection", "memory_image", "recent_creds_access"],
}


class DFIRCollector:
    def plan(self, case: Case) -> List[dict]:
        """Return a deterministic list of artifacts to collect."""
        out: List[dict] = []
        techniques = {t for a in case.alerts for t in a.mitre_techniques}
        for t in sorted(techniques):
            for artifact in ARTIFACT_MAP.get(t, []):
                out.append({"technique": t, "artifact": artifact})
        return out

    def simulate_collect(self, case: Case) -> List[Evidence]:
        """Produce simulated collected-artifact Evidence records.

        In a real deployment this would be wired to Velociraptor / DFIR
        agents. We only simulate here, and mark the source as ENRICHMENT
        (stub) so AI doesn't treat it as real telemetry.
        """
        records: List[Evidence] = []
        for item in self.plan(case):
            records.append(Evidence(
                source=EvidenceSource.ENRICHMENT,
                reference=f"{item['technique']}:{item['artifact']}",
                description=f"[simulated] DFIR collection plan item: {item['artifact']} for {item['technique']}",
                data={"simulated": True, **item},
            ))
        case.enrichments.extend(records)
        return records
