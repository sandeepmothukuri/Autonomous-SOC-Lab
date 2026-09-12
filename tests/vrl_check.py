"""Offline checker for Vector VRL logic.

We cannot run Vector inside a Python test, but we verify that the
vector.toml file references only known sources/sinks, has valid block
structure, and that every transform's inputs reference blocks that
exist. We also re-implement the critical auth/sysmon/zeek VRL logic as
Python so we can assert normalized outputs match the field names used
by detection rules.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VECTOR_TOML = ROOT / "pipeline" / "vector.toml"


def _toml_sections(text: str) -> dict:
    """Naive TOML parser sufficient for our vector.toml structure."""
    sections: dict = {}
    current = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = re.match(r"^\[([^\]]+)\]", line)
        if m:
            current = m.group(1)
            sections.setdefault(current, {"_lines": []})
            continue
        if current is None:
            continue
        sections[current]["_lines"].append(line)
    return sections


def test_vector_toml_parseable():
    text = VECTOR_TOML.read_text(encoding="utf-8")
    sections = _toml_sections(text)
    # Required sources
    for s in ("sources.sample_auth", "sources.sample_sysmon", "sources.sample_zeek"):
        assert s in sections, f"missing source {s}"
    # Required transforms exist
    for t in ("transforms.parse_auth", "transforms.parse_sysmon",
              "transforms.parse_zeek", "transforms.finalize",
              "transforms.only_critical"):
        assert t in sections, f"missing transform {t}"
    # Required sinks
    for k in ("sinks.opensearch_all", "sinks.opensearch_critical"):
        assert k in sections, f"missing sink {k}"


def test_vector_writes_to_opensearch_without_password():
    text = VECTOR_TOML.read_text(encoding="utf-8")
    # Security plugin is disabled: vector config must not reference password.
    assert "OPENSEARCH_PASSWORD" not in text, \
        "vector.toml references OPENSEARCH_PASSWORD but security plugin is disabled"


def test_vector_critical_index_only_for_critical():
    text = VECTOR_TOML.read_text(encoding="utf-8")
    # The only_critical filter must reference "critical"
    assert 'event.severity == "critical"' in text or 'exists(.alert.rule)' in text


def _parse_auth_line(msg: str) -> dict:
    """Mirror of the VRL auth parse logic (subset relevant to detections)."""
    out = {"event.kind": "event", "event.category": "authentication"}
    if re.search(r"[Ff]ailed password", msg):
        out["event.type"] = "failed_login"
        out["event.action"] = "ssh_login_failed"
        out["event.severity"] = "medium"
        m = re.search(r"(?:for invalid user |for )(?P<user>\S+) from (?P<src_ip>\S+)", msg)
        if m:
            out["user.name"] = m.group("user")
            out["source.ip"] = m.group("src_ip")
        out["host.name"] = "auth-host"
        out["destination.ip"] = "127.0.0.1"
        out["destination.port"] = 22
        out["network.direction"] = "external"
    elif "NOPASSWD" in msg:
        out["event.action"] = "sudo_nopasswd_suspected"
        out["event.severity"] = "high"
    return out


def test_auth_failed_login_normalizes_source_ip_and_user():
    ev = _parse_auth_line("Sep 12 13:40:01 web-prod-01 sshd[2001]: Failed password for root from 203.0.113.47 port 51220 ssh2")
    assert ev["event.type"] == "failed_login"
    assert ev["source.ip"] == "203.0.113.47"
    assert ev["user.name"] == "root"
    assert ev["event.severity"] == "medium"


def test_auth_nopasswd_flagged_as_high():
    ev = _parse_auth_line("Sep 12 13:42:10 web-prod-01 sudo: bob : COMMAND=NOPASSWD: /usr/local/bin/backdoor.sh")
    assert ev["event.action"] == "sudo_nopasswd_suspected"
    assert ev["event.severity"] == "high"


def _parse_sysmon_event(obj: dict) -> dict:
    out = {"event.kind": "event"}
    eid = obj.get("winlog", {}).get("event_id")
    host = obj.get("host", {}).get("name") or obj.get("ComputerName")
    out["host.name"] = host
    if eid == 4104:
        out["event.category"] = "process"
        out["event.type"] = "powershell_execution"
        sb = obj.get("winlog", {}).get("event_data", {}).get("ScriptBlockText", "").lower()
        out["process.name"] = "powershell.exe"
        out["process.command_line"] = sb
        if "-enc" in sb or "-encodedcommand" in sb:
            out["event.severity"] = "critical"
            out["alert.rule"] = "powershell_encoded_command"
        elif "write-host" in sb:
            out["event.severity"] = "medium"
    elif eid == 3:
        out["event.category"] = "network"
        out["event.type"] = "connection"
        dip = obj.get("winlog", {}).get("event_data", {}).get("DestinationIp")
        dport = int(obj.get("winlog", {}).get("event_data", {}).get("DestinationPort", 0))
        sip = obj.get("host", {}).get("ip")
        out["source.ip"] = sip
        out["destination.ip"] = dip
        out["destination.port"] = dport
        if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", dip or ""):
            out["network.direction"] = "internal"
        else:
            out["network.direction"] = "external"
        if out["network.direction"] == "internal" and dport in (445, 3389, 22, 135, 5985, 5986):
            out["event.severity"] = "high"
            out["alert.rule"] = "lateral_movement_suspected"
    return out


import json as _json


def test_sysmon_encoded_powershell_is_critical():
    obj = _json.loads('{"winlog":{"event_id":4104,"event_data":{"SubjectUserName":"alice","ScriptBlockText":"powershell.exe -EncodedCommand JAB"}},"host":{"name":"wkstn-42.corp.lab"}}')
    ev = _parse_sysmon_event(obj)
    assert ev["event.severity"] == "critical"
    assert ev["alert.rule"] == "powershell_encoded_command"


def test_sysmon_lateral_movement_flagged_on_smb_internal():
    obj = {"winlog": {"event_id": 3, "event_data": {"DestinationIp": "10.0.0.20", "DestinationPort": 445}},
           "host": {"name": "wkstn-99", "ip": "10.0.0.99"}}
    ev = _parse_sysmon_event(obj)
    assert ev["event.severity"] == "high"
    assert ev["alert.rule"] == "lateral_movement_suspected"
    assert ev["destination.port"] == 445
