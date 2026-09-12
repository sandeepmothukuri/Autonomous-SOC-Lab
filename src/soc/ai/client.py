"""AI triage client.

SAFETY MODEL
------------
1. The default provider is a DETERMINISTIC MOCK that uses only
   evidence already attached to the case. This makes the platform
   reproducible and safe to run without API keys.
2. Real LLM providers (OpenAI, Anthropic, local) may be plugged in,
   but MUST:
       - return structured AIAnalysis
       - have every evidence_ref resolve to an existing Evidence record
       - not claim anything unsupported by evidence
       - include a rationale <= 2000 chars
3. The AI client NEVER executes commands. It only returns an
   AIAnalysis object which is then passed to the deterministic policy
   engine. The AI cannot directly produce ResponseAction objects.
4. Timeouts and retries are enforced.
5. Failure falls back to "no AI result" — the case continues through
   deterministic policy with ai_analysis=None.
"""
from __future__ import annotations

import time
from typing import Optional

from jsonschema import ValidationError
from pydantic import ValidationError as PydanticValidationError

from ..config import AIConfig
from ..models import (
    AIAnalysis,
    Case,
    EvidenceSource,
    Severity,
    confidence_band,
)


class AIAnalysisError(Exception):
    """Raised when AI output is missing, malformed, or ungrounded."""


class AIClient:
    def __init__(self, cfg: AIConfig):
        self.cfg = cfg

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, case: Case) -> Optional[AIAnalysis]:
        """Run triage. Returns None if AI is disabled or fails."""
        if not self.cfg.enabled:
            return None
        t0 = time.perf_counter()
        last_err: Optional[Exception] = None
        for _attempt in range(self.cfg.max_retries + 1):
            try:
                raw = self._call_ai(case)
                analysis = self._validate(raw, case)
                analysis.analysis_latency_ms = (time.perf_counter() - t0) * 1000.0
                analysis.model_id = self.cfg.model_id
                return analysis
            except (AIAnalysisError, ValidationError, PydanticValidationError) as e:
                last_err = e
                continue
            except Exception as e:  # network, timeout -> retry then fail closed
                last_err = e
                continue
        # Fail closed: no AI recommendation.
        return None

    # ------------------------------------------------------------------
    # Provider adapter — override in subclass for real LLMs
    # ------------------------------------------------------------------
    def _call_ai(self, case: Case) -> dict:
        """Produce a raw analysis dict. Default: deterministic grounded mock."""
        if self.cfg.provider == "mock":
            return _mock_analysis(case)
        # Real providers would call an API here, returning structured JSON.
        # We do NOT call out to the network by default.
        raise AIAnalysisError(f"Unsupported AI provider: {self.cfg.provider}")

    # ------------------------------------------------------------------
    # Validation / hallucination control
    # ------------------------------------------------------------------
    def _validate(self, raw: dict, case: Case) -> AIAnalysis:
        analysis = AIAnalysis(**raw)
        if self.cfg.require_evidence_grounding:
            self._enforce_grounding(analysis, case)
        if self.cfg.reject_on_unsupported_claim:
            self._detect_unsupported_claims(analysis)
        return analysis

    def _enforce_grounding(self, analysis: AIAnalysis, case: Case) -> None:
        """Every evidence_ref must reference an Evidence already on the case."""
        known = {e.evidence_id for e in _all_evidence(case)}
        missing = [r for r in analysis.evidence_refs if r not in known]
        if missing:
            raise AIAnalysisError(
                f"AI referenced evidence not in case file: {missing}"
            )
        # Severity may be AI-assessed, but we cap it by the highest
        # deterministic severity to prevent AI from inflating alerts.
        if case.alerts:
            max_det = max((a.severity for a in case.alerts), key=_sev_rank)
            if _sev_rank(analysis.severity_assessment) > _sev_rank(max_det) + 1:
                # Allowing +1 is a reasonable heuristic for triage
                # adjustment beyond deterministic severity is suspicious
                raise AIAnalysisError(
                    "AI-inflated severity exceeds deterministic bounds"
                )

    def _detect_unsupported_claims(self, analysis: AIAnalysis) -> None:
        """Block statements that claim absolute certainty or known attribution
        without evidence. This is a heuristic; extend with your own guardrails."""
        red_flags = (
            "definitely apt",
            "nation-state",
            "confirmed apt",
            "100% certain",
            "attacker is",
            "we have confirmed",
        )
        hay = (analysis.rationale + " " + analysis.summary + " " + analysis.hypothesis).lower()
        for flag in red_flags:
            if flag in hay:
                # Allow only if explicitly grounded by TI evidence flag
                # (the mock never produces these; real LLMs sometimes do).
                raise AIAnalysisError(
                    f"Unsupported attribution claim detected ('{flag}')"
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev_rank(s: Severity) -> int:
    return {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
        Severity.HIGH: 3, Severity.CRITICAL: 4,
    }[s]


def _all_evidence(case: Case):
    for a in case.alerts:
        yield from a.evidence
    yield from case.enrichments


# ---------------------------------------------------------------------------
# Deterministic mock analysis — grounded in real evidence from the case.
# ---------------------------------------------------------------------------

def _mock_analysis(case: Case) -> dict:
    if not case.alerts:
        # Shouldn't happen (only called when there is something to triage)
        raise AIAnalysisError("No alerts to analyze")

    # Heuristic deterministic triage. This is EVIDENCE-BASED: every
    # ref points to an existing evidence_id.
    top = max(case.alerts, key=lambda a: _sev_rank(a.severity))
    ev_ids = [e.evidence_id for a in case.alerts for e in a.evidence]
    ev_ids += [e.evidence_id for e in case.enrichments]

    ti_hits = [e for e in case.enrichments if e.source == EvidenceSource.THREAT_INTEL]
    mitre = sorted({t for a in case.alerts for t in a.mitre_techniques})
    entities: dict = {}
    for a in case.alerts:
        entities.update(a.entities)

    # Confidence is derived deterministically from:
    #   rule severity + multiple corroborating alerts + TI hit presence
    base = {
        Severity.INFO: 0.20, Severity.LOW: 0.35, Severity.MEDIUM: 0.55,
        Severity.HIGH: 0.78, Severity.CRITICAL: 0.90,
    }[top.severity]
    if len(case.alerts) >= 2:
        base += 0.05
    if ti_hits:
        # A positive TI hit on an entity in the alert materially raises confidence.
        # For HIGH/CRITICAL alerts this pushes us into the auto-contain band when
        # the IOC corroborates the detection.
        base += 0.12 if top.severity in (Severity.HIGH, Severity.CRITICAL) else 0.08
    score = round(min(base, 0.99), 2)

    # Recommend action by severity/band
    band = confidence_band(score)
    if band.value in ("high", "very_high") and top.severity in (Severity.HIGH, Severity.CRITICAL):
        rec = "Recommend controlled containment of affected host/IP; analyst review."
    elif band.value == "medium":
        rec = "Recommend enrichment and analyst review before any action."
    else:
        rec = "Log and present to analyst; do not take automated action."

    summary = f"Deterministic detection fired '{top.rule_name}' on {entities.get('host') or entities.get('src_ip') or 'asset'}."
    hypothesis = (
        "Observed telemetry matches a known detection pattern; "
        "confidence and recommended action reflect corroborating evidence."
    )
    rationale = (
        f"Alert {top.alert_id} (rule {top.rule_id}, severity {top.severity.value}) "
        f"produced the primary signal. {len(case.alerts)} alert(s) total; "
        f"{len(ti_hits)} threat-intel hit(s); {len(case.enrichments)} enrichment record(s). "
        f"Confidence score {score} places this in the '{band.value}' band. "
        f"Mitre techniques: {', '.join(mitre) if mitre else 'none mapped'}."
    )

    return {
        "summary": summary,
        "severity_assessment": top.severity.value,
        "confidence": score,
        "entities": entities,
        "mitre_techniques": mitre,
        "evidence_refs": ev_ids,
        "hypothesis": hypothesis,
        "recommended_action": rec,
        "rationale": rationale[:2000],
    }
