"""Deterministic policy engine.

The policy engine is the SOLE authority that decides what response
actions are permitted. AI output is treated as one INPUT to policy —
it is never treated as authorization on its own.

Inputs:
    - DetectionAlerts (deterministic, authoritative)
    - AIAnalysis (advisory; may be None)
    - Config thresholds, allow/deny lists, response mode
Output:
    - PolicyDecision (deterministic)
"""
from __future__ import annotations

from typing import List, Optional

from ..config import SOCConfig
from ..models import (
    AIAnalysis,
    ActionImpact,
    Case,
    ConfidenceBand,
    DecisionOutcome,
    PolicyDecision,
    Severity,
    confidence_band,
)


_SEV_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


def _sev_rank(s: Severity) -> int:
    return _SEV_RANK[s]


SEV_ABOVE = {"high", "critical"}


class PolicyEngine:
    def __init__(self, cfg: SOCConfig):
        self.cfg = cfg

    def decide(self, case: Case) -> PolicyDecision:
        if not case.alerts:
            return PolicyDecision(
                outcome=DecisionOutcome.BLOCK,
                reason="No alerts on case; no action permitted.",
            )

        top_severity = max((a.severity for a in case.alerts), key=_sev_rank)
        analysis: Optional[AIAnalysis] = case.ai_analysis

        conf = analysis.confidence if analysis else 0.0
        band = confidence_band(conf)

        # DENY-LIST wins over everything
        allowed = list(self.cfg.soar.action_allowlist)
        denied = list(self.cfg.soar.deny_list)

        # Observation/notification actions are always allowed (they make no changes)
        safe_actions = [a for a in ("add_ioc_watch", "notify_analyst") if a in allowed and a not in denied]

        # If response_mode is audit_only, block everything but notifications
        if self.cfg.soar.response_mode == "audit_only":
            return PolicyDecision(
                outcome=DecisionOutcome.RECOMMEND,
                reason="response_mode=audit_only; recommendations only.",
                allowed_actions=list(safe_actions),
                denied_actions=[a for a in allowed if a not in safe_actions] + denied,
                requires_approval=True,
                approval_reason="Audit-only mode requires analyst approval for any action.",
                rollback_available=False,
            )

        # LOW confidence or no AI -> pure analyst recommendation
        if analysis is None or band == ConfidenceBand.LOW:
            return PolicyDecision(
                outcome=DecisionOutcome.RECOMMEND,
                reason="Low-confidence or AI unavailable: analyst review required.",
                allowed_actions=list(safe_actions),
                denied_actions=denied + [a for a in allowed if a not in safe_actions],
                # Observation/notification actions don't need approval;
                # there are no containment actions allowed here anyway.
                requires_approval=False,
                approval_reason=None,
            )

        # MEDIUM confidence -> enrich + recommend, containment requires approval
        if band == ConfidenceBand.MEDIUM:
            medium_allowed = list(safe_actions) + [a for a in ("quarantine_file",) if a in allowed and a not in denied]
            return PolicyDecision(
                outcome=DecisionOutcome.ENRICH_AND_RECOMMEND,
                reason="Medium confidence: additional enrichment + analyst approval for containment.",
                allowed_actions=medium_allowed,
                denied_actions=denied + [a for a in allowed if a not in medium_allowed],
                # Containment/impactful actions must be approved by an analyst,
                # but observation/notification actions fire automatically.
                requires_approval=True,
                approval_reason="Medium-confidence containment requires analyst approval.",
                rollback_available=True,
            )

        # HIGH / VERY_HIGH confidence
        meets_severity = top_severity.value in SEV_ABOVE
        meets_conf = conf >= self.cfg.thresholds.auto_contain_min_confidence

        if meets_conf and meets_severity:
            # Allow only actions on the autonomous_allowlist AND action_allowlist,
            # plus observation/notification actions.
            auto_allowed = list(safe_actions) + [
                a for a in self.cfg.soar.autonomous_allowlist
                if a in allowed and a not in denied
            ]
            still_denied = [
                a for a in allowed
                if a not in auto_allowed and a not in denied
            ]
            return PolicyDecision(
                outcome=DecisionOutcome.AUTO_CONTAIN,
                reason=(
                    f"High confidence ({conf:.2f}) + high severity "
                    f"({top_severity.value}); autonomous containment allowed "
                    f"for reversible, allowlisted actions."
                ),
                allowed_actions=auto_allowed,
                denied_actions=denied + still_denied,
                requires_approval=False,
                approval_reason=None,
                rollback_available=True,
            )

        # High confidence but severity threshold unmet -> recommend
        return PolicyDecision(
            outcome=DecisionOutcome.RECOMMEND,
            reason="Confidence high but severity below auto-containment threshold.",
            allowed_actions=list(safe_actions),
            denied_actions=denied + [a for a in allowed if a not in safe_actions],
            requires_approval=True,
            approval_reason="Severity threshold not met for autonomous action.",
            rollback_available=False,
        )
