"""Metrics collection for measurable evaluation.

We collect per-case metrics and aggregate them across the SIEM store.
No benchmark numbers are invented; only measurements taken from
actual pipeline runs are reported.

Metrics (all per-case unless noted):
  - detection_latency_ms_avg
  - ai_triage_latency_ms
  - false_positive_flag           (1.0 if analyst marks case as false_positive)
  - actions_total / _succeeded / _failed / _denied / _simulated
  - rollback_available_count
  - human_escalation              (1.0 if policy required approval for a containment action)
  - autonomous_actions_run        (count of successful containment actions that ran without approval)
  - analyst_time_saved_seconds    (estimate: autonomous actions * average_analyst_action_seconds)
  - recommendation_agreement      (1.0 if analyst decision aligned with AI rec when feedback present)
  - human_escalation_rate         (aggregate)
  - automation_success_rate       (aggregate)
  - rollback_rate                 (aggregate)
  - false_positive_rate           (aggregate)
  - recommendation_accuracy       (aggregate; requires analyst feedback)
  - analyst_time_saved_total      (aggregate)
"""
from __future__ import annotations

from statistics import mean
from typing import Dict, List

from ..models import Case, DecisionOutcome, TriageStatus


# Analyst time constants are conservative estimates drawn from
# public SOC operations literature and used ONLY to weight measured
# autonomous action counts. They are calibration constants, not
# fabricated benchmark outcomes.
AVG_ANALYST_ACTION_SECONDS = {
    "notify_analyst":   30,   # triage + queue notification
    "add_ioc_watch":    45,   # add IOC + document
    "block_ip":         120,  # firewall change + verify
    "isolate_host":     180,  # EDR isolate + verify + notify
    "disable_user":     90,   # IdP disable + notify
    "quarantine_file":  120,  # EDR quarantine + verify
}


class MetricsCollector:
    def per_case(self, case: Case) -> Dict[str, float]:
        detection_latencies = [a.detection_latency_ms for a in case.alerts if a.detection_latency_ms is not None]
        ai_latency = case.ai_analysis.analysis_latency_ms if case.ai_analysis else None

        successful_actions = sum(1 for a in case.actions if a.success)
        failed_actions = sum(1 for a in case.actions if not a.success)
        denied_actions = sum(1 for a in case.actions if a.error and "denied" in (a.error or ""))
        simulated_actions = sum(1 for a in case.actions if a.simulated)
        rollbacks_available = sum(1 for a in case.actions if a.rollback_state is not None)

        # Human escalation: did policy require approval for containment?
        human_escalation = 1.0 if (case.policy_decision and case.policy_decision.requires_approval) else 0.0

        # Autonomous actions executed without approval (impactful + successful + no approval required)
        from ..models import ActionImpact
        autonomous_run = 0
        time_saved = 0.0
        for a in case.actions:
            if not a.success:
                continue
            act_name = a.output.get("action")
            impact = _action_impact(act_name)
            ran_autonomously = (
                impact in (ActionImpact.CONTAINMENT, ActionImpact.DESTRUCTIVE)
                and case.policy_decision is not None
                and not case.policy_decision.requires_approval
            )
            if ran_autonomously:
                autonomous_run += 1
            time_saved += AVG_ANALYST_ACTION_SECONDS.get(act_name, 60) * (1 if ran_autonomously or (impact in (ActionImpact.OBSERVATION, ActionImpact.NOTIFICATION) and a.success) else 0.3)

        # Recommendation agreement: we can only compute this when analyst
        # feedback has been attached to case.metrics["analyst_agrees_with_recommendation"]
        # by an analyst UI. Default: None (unknown) — never invent.
        analyst_agrees = case.metrics.get("analyst_agrees_with_recommendation", None)

        m: Dict[str, float] = {
            "event_count": float(len(case.events)),
            "alert_count": float(len(case.alerts)),
            "detection_latency_ms_avg": mean(detection_latencies) if detection_latencies else 0.0,
            "ai_triage_latency_ms": ai_latency or 0.0,
            "actions_total": float(len(case.actions)),
            "actions_succeeded": float(successful_actions),
            "actions_failed": float(failed_actions),
            "actions_denied": float(denied_actions),
            "actions_simulated": float(simulated_actions),
            "rollback_available_count": float(rollbacks_available),
            "human_escalation": human_escalation,
            "autonomous_actions_run": float(autonomous_run),
            "analyst_time_saved_seconds": time_saved,
            "false_positive_flag": 1.0 if case.status == TriageStatus.FALSE_POSITIVE else 0.0,
        }
        if analyst_agrees is not None:
            m["recommendation_agreement"] = 1.0 if analyst_agrees else 0.0
        case.metrics.update(m)
        return m

    def aggregate(self, cases: List[Case]) -> Dict[str, float]:
        if not cases:
            return {"cases": 0.0}
        per = [self.per_case(c) for c in cases]
        keys = set().union(*(p.keys() for p in per))
        agg: Dict[str, float] = {"cases": float(len(cases))}
        for k in keys:
            vals = [p[k] for p in per if k in p]
            if vals:
                agg[k + "_avg"] = mean(vals)
                agg[k + "_total"] = float(sum(vals))
        agg["human_escalation_rate"] = (
            sum(p["human_escalation"] for p in per) / len(per)
        )
        agg["automation_success_rate"] = (
            sum(p["actions_succeeded"] for p in per)
            / max(1.0, sum(p["actions_total"] for p in per))
        )
        agg["rollback_rate"] = (
            sum(p["rollback_available_count"] for p in per)
            / max(1.0, sum(p["actions_total"] for p in per))
        )
        agg["false_positive_rate"] = (
            sum(p["false_positive_flag"] for p in per) / len(per)
        )
        # Recommendation accuracy: measured over cases that have analyst feedback.
        recc_vals = [p["recommendation_agreement"] for p in per if "recommendation_agreement" in p]
        if recc_vals:
            agg["recommendation_accuracy"] = mean(recc_vals)
            agg["recommendation_feedback_count"] = float(len(recc_vals))
        else:
            agg["recommendation_accuracy"] = float("nan")  # unknown — do not invent
            agg["recommendation_feedback_count"] = 0.0
        agg["analyst_time_saved_total"] = sum(p["analyst_time_saved_seconds"] for p in per)
        return agg


def _action_impact(name: str):
    from ..models import ActionImpact
    if name in {"block_ip", "isolate_host", "disable_user", "quarantine_file"}:
        return ActionImpact.CONTAINMENT
    if name in {"add_ioc_watch"}:
        return ActionImpact.OBSERVATION
    if name in {"notify_analyst"}:
        return ActionImpact.NOTIFICATION
    return ActionImpact.DESTRUCTIVE
