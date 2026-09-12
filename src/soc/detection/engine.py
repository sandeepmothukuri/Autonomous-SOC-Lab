"""Deterministic detection engine.

Detections are authoritative. Rules are simple, testable, stateless
Python functions or declarative YAML signatures. AI never produces a
DetectionAlert directly; it can only consume alerts and advise.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..models import (
    DetectionAlert,
    Evidence,
    EvidenceSource,
    Severity,
    TelemetryEvent,
    Case,
)

RuleFn = Callable[[TelemetryEvent], Optional[DetectionAlert]]


@dataclass
class Rule:
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_techniques: List[str]
    match_fn: Callable[[TelemetryEvent], bool]
    description: str = ""


class DetectionEngine:
    """Runs all registered rules over each event."""

    def __init__(self):
        self._rules: List[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def run(self, case: Case) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        for ev in case.events:
            t0 = time.perf_counter()
            for rule in self._rules:
                if rule.match_fn(ev):
                    alert = self._build_alert(ev, rule, t0)
                    case.alerts.append(alert)
                    alerts.append(alert)
        return alerts

    @staticmethod
    def _build_alert(ev: TelemetryEvent, rule: Rule, t0: float) -> DetectionAlert:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        evidence = Evidence(
            source=EvidenceSource.DETECTION_RULE,
            reference=ev.event_id,
            description=f"Event matched rule {rule.rule_id} ({rule.rule_name})",
            data={"event": ev.model_dump(mode="json")},
        )
        entities = {
            "host": ev.host,
            "src_ip": ev.src_ip,
            "dst_ip": ev.dst_ip,
            "user": ev.user,
            "process": ev.process,
        }
        entities = {k: v for k, v in entities.items() if v is not None}
        return DetectionAlert(
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            severity=rule.severity,
            mitre_techniques=list(rule.mitre_techniques),
            entities=entities,
            evidence=[evidence],
            detection_latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Built-in rule library (illustrative, deterministic)
# ---------------------------------------------------------------------------

def default_rules() -> List[Rule]:
    return [
        Rule(
            rule_id="DET-001",
            rule_name="Suspicious PowerShell Encoded Command",
            severity=Severity.HIGH,
            mitre_techniques=["T1059.001", "T1027"],
            description="Detects PowerShell invocations with -EncodedCommand",
            match_fn=lambda e: bool(
                e.process
                and "powershell" in e.process.lower()
                and e.command_line
                and "-encodedcommand" in e.command_line.lower()
            ),
        ),
        Rule(
            rule_id="DET-002",
            rule_name="Outbound Connection to Known Bad IP",
            severity=Severity.HIGH,
            mitre_techniques=["T1071.001"],
            description="Detects flows to known malicious IPs (deterministic IOC match).",
            match_fn=lambda e: bool(e.dst_ip and e.dst_ip in _MALICIOUS_IPS),
        ),
        Rule(
            rule_id="DET-003",
            rule_name="Failed Brute Force Authentication Threshold",
            severity=Severity.MEDIUM,
            mitre_techniques=["T1110"],
            description="Detects >5 failed auth events in a window for the same user (flagged in raw).",
            match_fn=lambda e: bool(
                e.process == "sshd"
                and e.raw.get("auth_result") == "fail"
                and int(e.raw.get("fail_count", 0)) >= 5
            ),
        ),
        Rule(
            rule_id="DET-004",
            rule_name="Scheduled Task Creation via schtasks",
            severity=Severity.MEDIUM,
            mitre_techniques=["T1053.005"],
            match_fn=lambda e: bool(
                e.process
                and "schtasks" in e.process.lower()
                and e.command_line
                and ("/create" in e.command_line.lower())
            ),
        ),
        Rule(
            rule_id="DET-005",
            rule_name="Mimikatz-like Process Memory Access",
            severity=Severity.CRITICAL,
            mitre_techniques=["T1003.001"],
            description="Known-bad process name or command line pattern.",
            match_fn=lambda e: bool(
                e.command_line and ("mimikatz" in e.command_line.lower())
            ) or bool(e.process and "mimikatz" in e.process.lower()),
        ),
    ]


# Deterministic, locally-loaded IOC list. In production feed from TI.
_MALICIOUS_IPS = {
    "198.51.100.66",
    "203.0.113.42",
    "192.0.2.77",
}
