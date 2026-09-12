"""Hallucination-control tests.

These explicitly attempt to make the pipeline act on hallucinated or
maliciously-crafted AI output and verify the system fails closed.
"""
import pytest

from soc.ai.client import AIAnalysisError, AIClient
from soc.config import AIConfig, SOCConfig
from soc.detection.engine import DetectionEngine, default_rules
from soc.enrichment.enricher import Enricher
from soc.models import (
    AIAnalysis,
    Case,
    Severity,
    TelemetryEvent,
)
from soc.pipeline import Pipeline
from soc.policy.engine import PolicyEngine
from soc.audit.logger import AuditLogger


def _base_case():
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JAB",
    ))
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    de.run(case)
    Enricher().enrich(case)
    return case


def test_hallucinated_evidence_ids_dropped_and_pipeline_continues():
    """If AI returns evidence refs that don't exist, validation must reject
    the analysis, and the pipeline must continue (fail closed — no AI)."""
    cfg = SOCConfig()
    cfg.audit_log_path = "data/test_audit.log"
    pipe = Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))

    # Intercept AI client to return a hallucinated payload
    class HallucinatingClient(AIClient):
        def _call_ai(self, case):
            return {
                "summary": "fabricated",
                "severity_assessment": "critical",
                "confidence": 1.0,
                "entities": {"host": "imaginary-host"},
                "mitre_techniques": ["T9999"],
                "evidence_refs": ["this-evidence-does-not-exist"],
                "hypothesis": "fabricated attacker",
                "recommended_action": "wipe_host",
                "rationale": "fabricated chain of thought",
            }
    pipe.ai = HallucinatingClient(cfg.ai)
    case = pipe.run([TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JAB",
    )])
    # AI analysis must have been rejected
    assert case.ai_analysis is None
    # Policy must have fallen back to RECOMMEND (analyst only), no containment
    assert case.policy_decision.outcome.value in {"recommend", "enrich_and_recommend"}
    # No destructive action should have run
    for a in case.actions:
        assert "wipe" not in (a.output.get("action") or "")


def test_deterministic_fallback_when_ai_throws():
    cfg = SOCConfig()
    cfg.audit_log_path = "data/test_audit.log"
    pipe = Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))

    class ExplodingClient(AIClient):
        def _call_ai(self, case):
            raise RuntimeError("simulated LLM outage")
    pipe.ai = ExplodingClient(cfg.ai)
    case = pipe.run([TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JAB",
    )])
    assert case.ai_analysis is None
    # Pipeline still produced detection + policy + recommendation actions
    assert len(case.alerts) == 1
    assert case.policy_decision is not None
    assert case.policy_decision.outcome.value == "recommend"


def test_ai_cannot_escalate_to_destructive_action_via_recommendation():
    """Even if AI recommends wipe_host, SOAR must refuse because wipe_host
    is on the deny_list and cannot be planned/executed."""
    cfg = SOCConfig()
    cfg.audit_log_path = "data/test_audit.log"
    pipe = Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))

    class BadAdviceClient(AIClient):
        def _call_ai(self, case):
            ev_ids = [e.evidence_id for a in case.alerts for e in a.evidence]
            return {
                "summary": "Bad advice",
                "severity_assessment": "critical",
                "confidence": 0.99,
                "entities": {"host": "dc01"},
                "mitre_techniques": ["T1003.001"],
                "evidence_refs": ev_ids,
                "hypothesis": "h",
                "recommended_action": "wipe_host",
                "rationale": "AI recommends wiping host; policy must still block.",
            }
    pipe.ai = BadAdviceClient(cfg.ai)
    # Mimikatz would normally be CRITICAL/high-confidence -> auto_contain
    from soc.redteam.scenarios import scenario_mimikatz
    case = pipe.run(scenario_mimikatz().events)
    # wipe_host must NOT have been executed
    for a in case.actions:
        assert a.output.get("action") != "wipe_host"
    # Containment (allowlisted reversible) actions may still run
    successful = {a.output.get("action") for a in case.actions if a.success}
    assert successful & {"isolate_host", "block_ip", "notify_analyst", "add_ioc_watch"}


def test_malformed_json_from_ai_does_not_crash_pipeline():
    cfg = SOCConfig()
    cfg.audit_log_path = "data/test_audit.log"
    pipe = Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))

    class GarbageClient(AIClient):
        def _call_ai(self, case):
            return {"not": "a valid", "analysis": object()}  # will fail validation
    pipe.ai = GarbageClient(cfg.ai)
    case = pipe.run([TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JAB",
    )])
    # Should have continued without AI
    assert case.ai_analysis is None
    assert len(case.alerts) == 1
