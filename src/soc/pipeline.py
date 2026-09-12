"""End-to-end pipeline orchestrator.

Stages (in order):
    1. Telemetry ingest
    2. Deterministic detection
    3. Enrichment
    4. AI triage   (advisory; may fail without breaking the pipeline)
    5. Policy decision (deterministic, authoritative)
    6. Response    (dry-run / simulate / real, per config and policy)
    7. Verification
    8. Audit + metrics + SIEM persistence

Every stage appends an AuditRecord. AI is sandboxed; it never executes
commands directly.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pathlib import Path

from .audit.logger import AuditLogger
from .ai.client import AIClient
from .config import SOCConfig
from .detection.engine import DetectionEngine, default_rules
from .detection.yaml_loader import load_yaml_rules
from .dfir.collector import DFIRCollector
from .enrichment.enricher import Enricher
from .metrics.collector import MetricsCollector
from .models import (
    ActionMode,
    Case,
    ResponseAction,
    TelemetryEvent,
    TriageStatus,
)
from .policy.engine import PolicyEngine
from .siem.store import SIEMStore
from .soar.executor import SOARExecutor
from .verification.verify import Verifier


class Pipeline:
    def __init__(
        self,
        cfg: Optional[SOCConfig] = None,
        *,
        siem: Optional[SIEMStore] = None,
        audit: Optional[AuditLogger] = None,
        detection: Optional[DetectionEngine] = None,
        enricher: Optional[Enricher] = None,
        ai: Optional[AIClient] = None,
        policy: Optional[PolicyEngine] = None,
        soar: Optional[SOARExecutor] = None,
        verifier: Optional[Verifier] = None,
        dfir: Optional[DFIRCollector] = None,
        metrics: Optional[MetricsCollector] = None,
    ):
        self.cfg = cfg or SOCConfig.load()
        self.audit = audit or AuditLogger(self.cfg.audit_log_path)
        self.siem = siem or SIEMStore("data/siem.jsonl")
        self.detection = detection or self._default_detection()
        self.enricher = enricher or Enricher()
        self.ai = ai or AIClient(self.cfg.ai)
        self.policy = policy or PolicyEngine(self.cfg)
        self.soar = soar or SOARExecutor(self.cfg, self.audit)
        self.verifier = verifier or Verifier()
        self.dfir = dfir or DFIRCollector()
        self.metrics = metrics or MetricsCollector()

    # ------------------------------------------------------------------
    def run(
        self,
        events: List[TelemetryEvent] | List[Dict[str, Any]],
        *,
        approval_callback: Optional[Any] = None,
        case: Optional[Case] = None,
    ) -> Case:
        """Execute the full pipeline for one incident case.

        events may be TelemetryEvent objects or raw dicts.
        approval_callback (optional) is a callable: (case, decision, action) -> bool
        that returns True if the human approves a pending action. When
        no callback is provided, approval is NOT granted (safe default).
        """
        case = case or Case()

        # 1. Telemetry (normalized dicts -> TelemetryEvent)
        normalized: List[TelemetryEvent] = []
        for e in events:
            if isinstance(e, TelemetryEvent):
                normalized.append(e)
            else:
                normalized.append(TelemetryEvent(**_normalize_raw(e)))
        case.events.extend(normalized)
        self.audit.record(
            case, stage="telemetry", actor="ingestor",
            description=f"Ingested {len(normalized)} event(s).",
            outputs_refs=[e.event_id for e in normalized],
        )

        # 2. Detection
        t0 = time.perf_counter()
        alerts = self.detection.run(case)
        det_ms = (time.perf_counter() - t0) * 1000.0
        self.audit.record(
            case, stage="detection", actor="detection-engine",
            description=f"Fired {len(alerts)} alert(s) in {det_ms:.2f}ms.",
            outputs_refs=[a.alert_id for a in alerts],
        )

        if not alerts:
            case.status = TriageStatus.CLOSED
            self._finalize(case)
            return case

        # 3. Enrichment
        enrichments = self.enricher.enrich(case)
        self.audit.record(
            case, stage="enrichment", actor="enricher",
            description=f"Added {len(enrichments)} enrichment record(s).",
            outputs_refs=[e.evidence_id for e in enrichments],
        )

        # 3b. DFIR plan (deterministic; collection not executed in sim mode)
        dfir_plan = self.dfir.plan(case)
        self.audit.record(
            case, stage="enrichment", actor="dfir-collector",
            description=f"DFIR collection plan: {len(dfir_plan)} artifact(s) to collect.",
            metadata={"plan": dfir_plan},
        )

        # 4. AI triage (advisory)
        try:
            case.ai_analysis = self.ai.analyze(case)
        except Exception:
            case.ai_analysis = None
        if case.ai_analysis is not None:
            self.audit.record(
                case, stage="ai", actor=f"ai:{case.ai_analysis.model_id}",
                description=(
                    f"AI triage produced {case.ai_analysis.severity_assessment.value} "
                    f"severity @ {case.ai_analysis.confidence:.2f}: "
                    f"{case.ai_analysis.recommended_action}"
                ),
                outputs_refs=[case.ai_analysis.model_id or "ai-analysis"],
            )
        else:
            self.audit.record(
                case, stage="ai", actor="ai",
                description="AI analysis unavailable or rejected; proceeding deterministically.",
            )

        # 5. Policy decision (deterministic)
        case.policy_decision = self.policy.decide(case)
        self.audit.record(
            case, stage="policy", actor="policy-engine",
            description=f"Policy outcome: {case.policy_decision.outcome.value} — {case.policy_decision.reason}",
            metadata={
                "allowed": case.policy_decision.allowed_actions,
                "denied": case.policy_decision.denied_actions,
                "requires_approval": case.policy_decision.requires_approval,
            },
        )

        # 6. Response — plan then execute
        actions = self.soar.plan_actions(case, case.policy_decision)
        for action in actions:
            approved = False
            if case.policy_decision.requires_approval and approval_callback is not None:
                try:
                    approved = bool(approval_callback(case, case.policy_decision, action))
                except Exception:
                    approved = False
            self.soar.execute(case, action, case.policy_decision, approval_granted=approved)

        # 7. Verification
        case.verification = self.verifier.verify(case)
        self.audit.record(
            case, stage="verification", actor="verifier",
            description=(
                "Verification " + ("PASSED" if case.verification.verified else "FAILED")
                + f": {case.verification.notes}"
            ),
            metadata={"checks": case.verification.checks},
        )

        # Update case status
        if case.verification.verified and any(a.success for a in case.actions if "isolate" in a.output.get("action", "") or "block" in a.output.get("action", "")):
            case.status = TriageStatus.CONTAINED
        elif all(not a.success for a in case.actions):
            case.status = TriageStatus.IN_REVIEW
        else:
            case.status = TriageStatus.IN_REVIEW

        self._finalize(case)
        return case

    # ------------------------------------------------------------------
    def _finalize(self, case: Case) -> None:
        self.metrics.per_case(case)
        self.siem.add(case)

    def _default_detection(self) -> DetectionEngine:
        de = DetectionEngine()
        for r in default_rules():
            de.register(r)
        # Load declarative YAML rules (deterministic, auditable).
        repo_root = Path(__file__).resolve().parents[2]
        for r in load_yaml_rules(repo_root / "config" / "detection_rules" / "rules.yaml"):
            de.register(r)
        return de


def _normalize_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Allow raw events to omit fields; pydantic handles defaults."""
    allowed = {"source", "host", "src_ip", "dst_ip", "user", "process",
               "command_line", "raw", "labels", "timestamp"}
    out = {k: v for k, v in raw.items() if k in allowed}
    out.setdefault("source", raw.get("source", "unknown"))
    out["raw"] = raw
    return out
