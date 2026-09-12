"""SOAR executor tests — deny-list, allowlist, dry-run, approvals, timeouts."""
import pytest

from soc.audit.logger import AuditLogger
from soc.config import SOCConfig
from soc.detection.engine import DetectionEngine, default_rules
from soc.models import (
    ActionImpact,
    ActionMode,
    Case,
    DecisionOutcome,
    PolicyDecision,
    ResponseAction,
    TelemetryEvent,
)
from soc.soar.executor import SOARExecutor


def _executor(cfg=None):
    cfg = cfg or SOCConfig()
    audit = AuditLogger("data/test_audit.log")
    return cfg, SOARExecutor(cfg, audit)


def _case_with_mimikatz():
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="dc01", process="mimikatz.exe",
        command_line="mimikatz sekurlsa::logonpasswords",
    ))
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    de.run(case)
    return case


def test_deny_list_action_blocked():
    cfg, ex = _executor()
    case = _case_with_mimikatz()
    decision = PolicyDecision(
        outcome=DecisionOutcome.AUTO_CONTAIN,
        reason="ok",
        allowed_actions=list(cfg.soar.action_allowlist),
        denied_actions=list(cfg.soar.deny_list),
    )
    act = ResponseAction(
        name="wipe_host", impact=ActionImpact.DESTRUCTIVE,
        target={"host": "dc01"}, mode=ActionMode.REAL,
    )
    res = ex.execute(case, act, decision, approval_granted=True)
    assert res.success is False
    assert "deny_list" in (res.error or "")


def test_unallowlisted_action_blocked():
    cfg, ex = _executor()
    case = _case_with_mimikatz()
    decision = PolicyDecision(outcome=DecisionOutcome.AUTO_CONTAIN, reason="ok",
                              allowed_actions=["block_ip"], denied_actions=[])
    act = ResponseAction(name="isolate_host", impact=ActionImpact.CONTAINMENT,
                         target={"host": "dc01"})
    res = ex.execute(case, act, decision)
    assert res.success is False
    assert "not allowed" in (res.error or "")


def test_requires_approval_without_grant_denies():
    cfg, ex = _executor()
    case = _case_with_mimikatz()
    decision = PolicyDecision(
        outcome=DecisionOutcome.ENRICH_AND_RECOMMEND, reason="r",
        allowed_actions=["quarantine_file"], denied_actions=[],
        requires_approval=True,
    )
    act = ResponseAction(name="quarantine_file", impact=ActionImpact.CONTAINMENT,
                         target={"file": "/tmp/x"}, mode=ActionMode.SIMULATE)
    res = ex.execute(case, act, decision, approval_granted=False)
    assert res.success is False
    assert res.output.get("pending_approval") is True


def test_requires_approval_with_grant_executes_in_simulate():
    cfg = SOCConfig()
    cfg.soar.response_mode = "simulated"
    _, ex = _executor(cfg)
    case = _case_with_mimikatz()
    decision = PolicyDecision(
        outcome=DecisionOutcome.ENRICH_AND_RECOMMEND, reason="r",
        allowed_actions=["quarantine_file"], denied_actions=[],
        requires_approval=True,
    )
    act = ResponseAction(name="quarantine_file", impact=ActionImpact.CONTAINMENT,
                         target={"file": "/tmp/x"}, mode=ActionMode.SIMULATE)
    res = ex.execute(case, act, decision, approval_granted=True)
    assert res.success is True
    assert res.simulated is True
    assert res.rollback_state is not None


def test_real_mode_not_forced_by_action_when_global_simulated():
    cfg = SOCConfig()
    cfg.soar.response_mode = "simulated"
    _, ex = _executor(cfg)
    case = _case_with_mimikatz()
    decision = PolicyDecision(outcome=DecisionOutcome.AUTO_CONTAIN, reason="ok",
                              allowed_actions=["isolate_host"], denied_actions=[])
    act = ResponseAction(name="isolate_host", impact=ActionImpact.CONTAINMENT,
                         target={"host": "dc01"}, mode=ActionMode.REAL)
    res = ex.execute(case, act, decision)
    assert res.success is True
    # Global mode simulated overrides action REAL
    assert res.output.get("mode") == "simulate"
    assert res.simulated is True


def test_audit_only_runs_dry_run():
    cfg = SOCConfig()
    cfg.soar.response_mode = "audit_only"
    _, ex = _executor(cfg)
    case = _case_with_mimikatz()
    decision = PolicyDecision(outcome=DecisionOutcome.RECOMMEND, reason="audit",
                              allowed_actions=["notify_analyst"], denied_actions=[])
    act = ResponseAction(name="notify_analyst", impact=ActionImpact.NOTIFICATION,
                         target={"case_id": case.case_id})
    res = ex.execute(case, act, decision)
    assert res.success is True
    assert res.output.get("mode") == "dry_run"


def test_shell_execution_never_allowed():
    """The platform does not register an execute_shell handler, and it is on
    the deny list by default. Belt-and-suspenders."""
    cfg, ex = _executor()
    case = _case_with_mimikatz()
    decision = PolicyDecision(outcome=DecisionOutcome.AUTO_CONTAIN, reason="ok",
                              allowed_actions=list(cfg.soar.action_allowlist) + ["execute_shell"],
                              denied_actions=[])
    act = ResponseAction(name="execute_shell", impact=ActionImpact.DESTRUCTIVE,
                         target={"cmd": "rm -rf /"}, mode=ActionMode.REAL)
    res = ex.execute(case, act, decision, approval_granted=True)
    assert res.success is False
    assert "deny_list" in (res.error or "")
