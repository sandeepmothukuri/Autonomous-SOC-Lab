"""Safe adversary simulation scenarios.

Scenarios generate synthetic telemetry that exercises the pipeline
end-to-end: attack -> telemetry -> detection -> AI triage -> policy ->
response -> verification. Every scenario is deterministic and
documented.

Scenarios do NOT execute real attacks or even shell commands; they
emit TelemetryEvent-shaped records.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Callable

from ..models import TelemetryEvent


@dataclass
class Scenario:
    scenario_id: str
    name: str
    description: str
    mitre_techniques: List[str]
    expected_detections: List[str]     # rule_ids expected to fire
    expected_policy_outcome: str       # DecisionOutcome.value
    events: List[TelemetryEvent]


def _evt(**kw: Any) -> TelemetryEvent:
    return TelemetryEvent(**kw)


def scenario_powershell_encoded() -> Scenario:
    """T1059.001: Encoded PowerShell command on a workstation."""
    events = [
        _evt(
            source="edr",
            host="wkstn-42.corp.local",
            user="alice",
            process="powershell.exe",
            command_line="powershell.exe -EncodedCommand JABzAD0AJwBo...",
            raw={"parent_process": "winword.exe"},
        ),
    ]
    return Scenario(
        scenario_id="RT-001",
        name="Encoded PowerShell from Office parent",
        description="Simulates a user opening a malicious document that spawns encoded PowerShell.",
        mitre_techniques=["T1059.001", "T1027"],
        expected_detections=["DET-001"],
        expected_policy_outcome="recommend",
        events=events,
    )


def scenario_c2_callback() -> Scenario:
    """T1071.001: Outbound connection to a known-bad C2 IP."""
    events = [
        _evt(
            source="netflow",
            host="wkstn-42.corp.local",
            src_ip="10.0.0.42",
            dst_ip="198.51.100.66",
            process="svchost.exe",
            raw={"bytes_out": 12840, "bytes_in": 98322},
        ),
    ]
    return Scenario(
        scenario_id="RT-002",
        name="Outbound C2 callback to known IOC",
        description="Simulates a beaconing session to a known malicious IP.",
        mitre_techniques=["T1071.001"],
        expected_detections=["DET-002"],
        expected_policy_outcome="auto_contain",
        events=events,
    )


def scenario_brute_force() -> Scenario:
    """T1110: SSH brute force threshold."""
    events = [
        _evt(
            source="syslog",
            host="jump01.corp.local",
            src_ip="203.0.113.42",
            user="root",
            process="sshd",
            command_line=None,
            raw={"auth_result": "fail", "fail_count": 7},
        ),
    ]
    return Scenario(
        scenario_id="RT-003",
        name="SSH brute force threshold exceeded",
        description="Simulates repeated failed SSH logins exceeding the threshold.",
        mitre_techniques=["T1110"],
        expected_detections=["DET-003"],
        expected_policy_outcome="enrich_and_recommend",
        events=events,
    )


def scenario_mimikatz() -> Scenario:
    """T1003.001: Credential dumping via mimikatz."""
    events = [
        _evt(
            source="edr",
            host="dc01.corp.local",
            user="SYSTEM",
            process="mimikatz.exe",
            command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            raw={"parent_process": "cmd.exe"},
        ),
    ]
    return Scenario(
        scenario_id="RT-004",
        name="Mimikatz credential dump on DC",
        description="Critical: mimikatz execution on a domain controller.",
        mitre_techniques=["T1003.001"],
        expected_detections=["DET-005"],
        expected_policy_outcome="auto_contain",
        events=events,
    )


def scenario_benign_activity() -> Scenario:
    """Benign baseline; should produce no alerts (noise test)."""
    events = [
        _evt(
            source="edr",
            host="wkstn-42.corp.local",
            user="alice",
            process="chrome.exe",
            command_line=None,
            raw={"navigate_to": "https://corp.example.com"},
        ),
        _evt(
            source="syslog",
            host="jump01.corp.local",
            src_ip="10.0.0.5",
            user="bob",
            process="sshd",
            raw={"auth_result": "success"},
        ),
    ]
    return Scenario(
        scenario_id="RT-005",
        name="Benign activity",
        description="Baseline noise; should NOT produce any alerts.",
        mitre_techniques=[],
        expected_detections=[],
        expected_policy_outcome="block",  # no alerts -> block (no action)
        events=events,
    )


def all_scenarios() -> List[Scenario]:
    return [
        scenario_powershell_encoded(),
        scenario_c2_callback(),
        scenario_brute_force(),
        scenario_mimikatz(),
        scenario_benign_activity(),
    ]
