"""Tests for AI output schema validation and hallucination control."""
import pytest
from pydantic import ValidationError

from soc.ai.client import AIAnalysisError, AIClient
from soc.config import AIConfig
from soc.detection.engine import DetectionEngine, default_rules
from soc.enrichment.enricher import Enricher
from soc.models import (
    AIAnalysis,
    Case,
    Evidence,
    EvidenceSource,
    Severity,
    TelemetryEvent,
)


def _grounded_case() -> Case:
    case = Case()
    case.events.append(TelemetryEvent(
        source="edr", host="wkstn-42", process="powershell.exe",
        command_line="powershell.exe -EncodedCommand JABzAD0A",
    ))
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    de.run(case)
    Enricher().enrich(case)
    return case


def test_valid_mock_analysis_passes():
    case = _grounded_case()
    client = AIClient(AIConfig())
    out = client.analyze(case)
    assert out is not None
    assert isinstance(out, AIAnalysis)
    assert 0.0 <= out.confidence <= 1.0
    assert out.severity_assessment in list(Severity)
    assert out.rationale
    assert out.summary


def test_missing_evidence_ref_rejected():
    case = _grounded_case()
    client = AIClient(AIConfig())
    # Monkey-patch the provider to return a bad payload referencing
    # nonexistent evidence.
    bad = {
        "summary": "x", "severity_assessment": "high", "confidence": 0.9,
        "entities": {}, "mitre_techniques": [],
        "evidence_refs": ["does-not-exist"],
        "hypothesis": "h", "recommended_action": "r", "rationale": "r",
    }
    client._call_ai = lambda case: bad  # type: ignore[method-assign]
    with pytest.raises(AIAnalysisError):
        client._validate(bad, case)


def test_severity_inflation_rejected():
    case = _grounded_case()
    # The top deterministic alert is HIGH (DET-001). AI claiming CRITICAL
    # is +1 (allowed) — but claiming CRITICAL when top is MEDIUM is not.
    # We craft a MEDIUM-only alert set to test.
    case2 = Case()
    case2.events.append(TelemetryEvent(
        source="syslog", host="jump01", process="sshd",
        raw={"auth_result": "fail", "fail_count": 7},
    ))
    de = DetectionEngine()
    for r in default_rules():
        de.register(r)
    de.run(case2)

    client = AIClient(AIConfig())
    inflated = {
        "summary": "x", "severity_assessment": "critical", "confidence": 0.95,
        "entities": {}, "mitre_techniques": [],
        "evidence_refs": [case2.alerts[0].evidence[0].evidence_id],
        "hypothesis": "h", "recommended_action": "r",
        "rationale": "AI claims critical on a medium event",
    }
    with pytest.raises(AIAnalysisError):
        client._validate(inflated, case2)


def test_unsupported_attribution_rejected():
    case = _grounded_case()
    client = AIClient(AIConfig())
    bad = {
        "summary": "attacker is nation-state",
        "severity_assessment": "high", "confidence": 0.9,
        "entities": {}, "mitre_techniques": [],
        "evidence_refs": [case.alerts[0].evidence[0].evidence_id],
        "hypothesis": "h", "recommended_action": "r",
        "rationale": "r",
    }
    with pytest.raises(AIAnalysisError):
        client._validate(bad, case)


def test_malformed_response_rejected():
    case = _grounded_case()
    client = AIClient(AIConfig())
    with pytest.raises(ValidationError):
        # Missing required fields
        AIAnalysis(**{"summary": "", "confidence": 1.5})  # type: ignore


def test_rationale_length_limit():
    with pytest.raises(ValidationError):
        AIAnalysis(
            summary="ok",
            severity_assessment=Severity.HIGH,
            confidence=0.8,
            hypothesis="h",
            recommended_action="r",
            rationale="x" * 3000,
        )


def test_ai_disabled_returns_none():
    case = _grounded_case()
    client = AIClient(AIConfig(enabled=False))
    assert client.analyze(case) is None


def test_ai_failure_falls_back_gracefully():
    case = _grounded_case()
    client = AIClient(AIConfig())
    # Force a broken provider
    client.cfg.provider = "bogus-provider"
    assert client.analyze(case) is None
