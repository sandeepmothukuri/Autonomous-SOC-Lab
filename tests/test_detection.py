"""Deterministic detection engine tests."""
from soc.detection.engine import DetectionEngine, default_rules
from soc.models import Case, TelemetryEvent


def _engine():
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    return de


def test_powershell_encoded_detected():
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JABzAD0A",
    ))
    alerts = _engine().run(case)
    assert any(a.rule_id == "DET-001" for a in alerts)


def test_c2_ip_detected():
    case = Case()
    case.events.append(TelemetryEvent(
        source="netflow", host="wkstn-42", src_ip="10.0.0.1", dst_ip="198.51.100.66",
    ))
    alerts = _engine().run(case)
    assert any(a.rule_id == "DET-002" for a in alerts)


def test_mimikatz_detected():
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="dc01", process="mimikatz.exe", command_line="mimikatz sekurlsa::logonpasswords",
    ))
    alerts = _engine().run(case)
    assert any(a.rule_id == "DET-005" for a in alerts)


def test_benign_activity_produces_no_alerts():
    case = Case()
    case.events.append(TelemetryEvent(source="edr", host="wkstn-42", process="chrome.exe"))
    case.events.append(TelemetryEvent(source="syslog", host="jump01", process="sshd",
                                       raw={"auth_result": "success"}))
    alerts = _engine().run(case)
    assert alerts == []


def test_brute_force_threshold():
    case = Case()
    case.events.append(TelemetryEvent(
        source="syslog", host="jump01", src_ip="203.0.113.42", user="root",
        process="sshd", raw={"auth_result": "fail", "fail_count": 7},
    ))
    alerts = _engine().run(case)
    assert any(a.rule_id == "DET-003" for a in alerts)


def test_brute_force_below_threshold_not_detected():
    case = Case()
    case.events.append(TelemetryEvent(
        source="syslog", host="jump01", process="sshd",
        raw={"auth_result": "fail", "fail_count": 2},
    ))
    alerts = _engine().run(case)
    assert all(a.rule_id != "DET-003" for a in alerts)
