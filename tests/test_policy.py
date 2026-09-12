"""Deterministic policy engine tests."""
from soc.config import SOCConfig
from soc.detection.engine import DetectionEngine, default_rules
from soc.models import (
    AIAnalysis,
    Case,
    DecisionOutcome,
    Severity,
    TelemetryEvent,
)
from soc.policy.engine import PolicyEngine


def _mk_case(events, ai_confidence=None, ai_severity=None):
    case = Case()
    for e in events:
        case.events.append(e)
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    de.run(case)
    if ai_confidence is not None:
        # Use alert evidence to keep refs legal (policy doesn't validate refs, but keeps case realistic)
        ev_ids = [e.evidence_id for a in case.alerts for e in a.evidence]
        case.ai_analysis = AIAnalysis(
            summary="s",
            severity_assessment=ai_severity or max((a.severity for a in case.alerts), key=lambda s: {"info":0,"low":1,"medium":2,"high":3,"critical":4}[s.value]),
            confidence=ai_confidence,
            evidence_refs=ev_ids,
            hypothesis="h",
            recommended_action="r",
            rationale="r",
        )
    return case


def test_no_alerts_blocks_action():
    cfg = SOCConfig()
    case = Case()
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.BLOCK


def test_low_confidence_recommends_only():
    cfg = SOCConfig()
    case = _mk_case([TelemetryEvent(source="edr", host="w", process="powershell.exe",
                                     command_line="powershell.exe -EncodedCommand x")],
                    ai_confidence=0.25)
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.RECOMMEND
    # Only observation/notification actions are allowed, which do not need approval
    assert "isolate_host" not in decision.allowed_actions
    assert "block_ip" not in decision.allowed_actions
    assert "notify_analyst" in decision.allowed_actions
    assert "add_ioc_watch" in decision.allowed_actions


def test_medium_confidence_enrich_and_recommend():
    cfg = SOCConfig()
    case = _mk_case([TelemetryEvent(source="syslog", host="j", process="sshd",
                                     raw={"auth_result": "fail", "fail_count": 7})],
                    ai_confidence=0.6)
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.ENRICH_AND_RECOMMEND
    assert decision.requires_approval is True


def test_high_confidence_severe_auto_contains():
    cfg = SOCConfig()
    case = _mk_case([TelemetryEvent(source="edr", host="dc01", process="mimikatz.exe",
                                     command_line="mimikatz sekurlsa::logonpasswords")],
                    ai_confidence=0.95)
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.AUTO_CONTAIN
    assert decision.requires_approval is False
    assert "block_ip" in decision.allowed_actions or "isolate_host" in decision.allowed_actions


def test_audit_only_mode_blocks_containment():
    cfg = SOCConfig()
    cfg.soar.response_mode = "audit_only"
    case = _mk_case([TelemetryEvent(source="edr", host="dc01", process="mimikatz.exe",
                                     command_line="mimikatz sekurlsa::logonpasswords")],
                    ai_confidence=0.95)
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.RECOMMEND
    assert "isolate_host" not in decision.allowed_actions


def test_no_ai_falls_back_to_recommend():
    cfg = SOCConfig()
    case = _mk_case([TelemetryEvent(source="edr", host="dc01", process="mimikatz.exe",
                                     command_line="mimikatz sekurlsa::logonpasswords")],
                    ai_confidence=None)
    decision = PolicyEngine(cfg).decide(case)
    assert decision.outcome == DecisionOutcome.RECOMMEND
    # With no AI, no containment actions allowed
    assert "isolate_host" not in decision.allowed_actions
    assert "notify_analyst" in decision.allowed_actions
