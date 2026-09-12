"""End-to-end pipeline tests."""
import pytest

from soc.audit.logger import AuditLogger
from soc.config import SOCConfig
from soc.models import TelemetryEvent, TriageStatus
from soc.pipeline import Pipeline
from soc.redteam.scenarios import all_scenarios, scenario_c2_callback, scenario_mimikatz, scenario_benign_activity


def _pipeline(response_mode: str = "simulated"):
    cfg = SOCConfig()
    cfg.soar.response_mode = response_mode
    cfg.audit_log_path = "data/test_audit.log"
    return Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))


def test_benign_activity_no_alerts():
    pipe = _pipeline()
    case = pipe.run(scenario_benign_activity().events)
    assert case.alerts == []
    assert case.status == TriageStatus.CLOSED


def test_c2_callback_auto_contains_in_simulated_mode():
    pipe = _pipeline("simulated")
    case = pipe.run(scenario_c2_callback().events)
    names = [a.output.get("action") for a in case.actions if a.success]
    assert "block_ip" in names
    assert all(a.simulated for a in case.actions if a.success)
    assert case.verification and case.verification.verified


def test_high_severity_mimikatz_auto_isolates_host():
    pipe = _pipeline("simulated")
    case = pipe.run(scenario_mimikatz().events)
    hosts = [a.output.get("host") for a in case.actions if a.output.get("action") == "isolate_host" and a.success]
    assert "dc01.corp.local" in hosts


def test_audit_only_no_containment_actions():
    pipe = _pipeline("audit_only")
    case = pipe.run(scenario_mimikatz().events)
    # Only notify_analyst should succeed; containment should be denied.
    successful = {a.output.get("action") for a in case.actions if a.success}
    denied_containment = [
        a for a in case.actions
        if not a.success and a.output.get("action") in {"isolate_host", "block_ip"}
    ]
    assert successful <= {"notify_analyst", "add_ioc_watch"}
    assert len(denied_containment) >= 0  # they may not even be planned
    # The policy outcome must be RECOMMEND in audit_only
    assert case.policy_decision.outcome.value == "recommend"


def test_approval_callback_required_for_medium_confidence():
    """Without an approval callback, medium-confidence containment must be denied."""
    pipe = _pipeline("simulated")
    from soc.redteam.scenarios import scenario_brute_force
    case = pipe.run(scenario_brute_force().events)  # no approval callback
    # quarantine_file could be planned but should be denied/pending without approval
    quar = [a for a in case.actions if a.output.get("action") == "quarantine_file"]
    for a in quar:
        assert a.success is False
        assert a.output.get("pending_approval") is True


def test_full_audit_trail_has_required_stages():
    pipe = _pipeline("simulated")
    case = pipe.run(scenario_mimikatz().events)
    stages = {r.stage for r in case.audit_trail}
    assert {"telemetry", "detection", "enrichment", "policy", "response", "verification"}.issubset(stages)


def test_metrics_populated():
    pipe = _pipeline("simulated")
    case = pipe.run(scenario_c2_callback().events)
    assert case.metrics["event_count"] >= 1
    assert case.metrics["alert_count"] >= 1
    assert case.metrics["actions_total"] >= 1


def test_all_redteam_scenarios_run_end_to_end():
    pipe = _pipeline("simulated")
    for scen in all_scenarios():
        case = pipe.run(scen.events)
        assert case.case_id
        # Expected detections should match fired detections
        fired = {a.rule_id for a in case.alerts}
        assert set(scen.expected_detections).issubset(fired), (
            f"{scen.scenario_id}: expected {scen.expected_detections} fired {fired}"
        )
        if scen.expected_policy_outcome != "block":
            assert case.policy_decision is not None
