"""Shared Pydantic models used across the SOC platform.

All components communicate through these strongly-typed structures to
keep AI outputs bounded, auditable, and safely transformable into actions.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums — categorical distinctions MUST stay explicit
# ---------------------------------------------------------------------------

class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceBand(str, enum.Enum):
    """Deterministic band applied to AI confidence scores."""
    LOW = "low"            # 0.00 - 0.40
    MEDIUM = "medium"      # 0.40 - 0.70
    HIGH = "high"          # 0.70 - 0.90
    VERY_HIGH = "very_high"  # 0.90 - 1.00


class ActionMode(str, enum.Enum):
    """Determines the execution posture of a response action."""
    DRY_RUN = "dry_run"       # log what WOULD happen; do nothing
    SIMULATE = "simulate"     # simulate against an isolated sandbox
    REAL = "real"             # real action on a real asset


class ActionImpact(str, enum.Enum):
    """Rough ordering of how disruptive an action is on live systems."""
    OBSERVATION = "observation"   # read-only (enrichment, queries)
    NOTIFICATION = "notification" # send email/Slack/SIEM event
    CONTAINMENT = "containment"   # isolate host, block IP (reversible)
    DESTRUCTIVE = "destructive"   # delete file, wipe host (irreversible)


class DecisionOutcome(str, enum.Enum):
    RECOMMEND = "recommend"            # present to analyst; no automation
    ENRICH_AND_RECOMMEND = "enrich_and_recommend"
    REQUIRE_APPROVAL = "require_approval"
    AUTO_CONTAIN = "auto_contain"      # allowlisted, reversible
    BLOCK = "block"                    # deny action request
    ESCALATE = "escalate"


class TriageStatus(str, enum.Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class EvidenceSource(str, enum.Enum):
    TELEMETRY = "telemetry"
    DETECTION_RULE = "detection_rule"
    THREAT_INTEL = "threat_intel"
    ENRICHMENT = "enrichment"
    ANALYST = "analyst"
    AI_ANALYSIS = "ai_analysis"       # must never be treated as ground truth


class ResponseExecutionMode(str, enum.Enum):
    """Explicit top-level flag controlling whether the platform will ever
    perform real response actions. Default is SIMULATE."""
    AUDIT_ONLY = "audit_only"   # detection + triage; no response actions
    SIMULATED = "simulated"     # actions run against sandbox only
    REAL = "real"               # real response actions permitted (safeguards apply)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Core event / finding / action models
# ---------------------------------------------------------------------------

class TelemetryEvent(BaseModel):
    """A single raw or normalized telemetry record."""
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: datetime = Field(default_factory=_utcnow)
    source: str                          # e.g. "syslog", "edr", "netflow"
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)


class Evidence(BaseModel):
    """A pointer to a concrete, verifiable piece of evidence.

    AI output may reference Evidence, but Evidence.source must resolve
    to a deterministic, non-AI source when used to justify a finding.
    """
    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    source: EvidenceSource
    reference: str                       # e.g. event_id, IOC id, rule_id
    description: str
    data: Dict[str, Any] = Field(default_factory=dict)


class DetectionAlert(BaseModel):
    """Output of the deterministic detection engine."""
    alert_id: str = Field(default_factory=lambda: new_id("alert"))
    timestamp: datetime = Field(default_factory=_utcnow)
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_techniques: List[str] = Field(default_factory=list)
    entities: Dict[str, Any] = Field(default_factory=dict)  # host/ip/user/proc
    evidence: List[Evidence] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    # Latency bookkeeping (milliseconds from telemetry receipt to alert)
    detection_latency_ms: Optional[float] = None


class AIAnalysis(BaseModel):
    """Structured analyst-facing AI triage output.

    IMPORTANT: `evidence` here references Evidence records that must
    already exist in the case file. AI is not allowed to fabricate
    evidence. This schema is enforced; malformed LLM output is rejected.
    """
    summary: str
    severity_assessment: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    entities: Dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)   # evidence_ids
    hypothesis: str
    recommended_action: str
    rationale: str                           # concise, analyst-facing rationale
    model_id: Optional[str] = None
    analysis_latency_ms: Optional[float] = None

    @field_validator("rationale")
    @classmethod
    def _rationale_must_be_short(cls, v: str) -> str:
        if len(v) > 2000:
            raise ValueError("rationale must be <= 2000 characters")
        return v

    @field_validator("summary")
    @classmethod
    def _summary_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("summary must be non-empty")
        return v


class PolicyDecision(BaseModel):
    outcome: DecisionOutcome
    reason: str
    allowed_actions: List[str] = Field(default_factory=list)
    denied_actions: List[str] = Field(default_factory=list)
    requires_approval: bool = False
    approval_reason: Optional[str] = None
    rollback_available: bool = False


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: new_id("act"))
    name: str                              # e.g. "block_ip", "isolate_host"
    impact: ActionImpact
    target: Dict[str, Any]                 # host/ip/account/etc.
    parameters: Dict[str, Any] = Field(default_factory=dict)
    mode: ActionMode = ActionMode.DRY_RUN


class ActionResult(BaseModel):
    action_id: str
    success: bool
    simulated: bool = True                 # True unless real response executed
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: Optional[datetime] = None
    output: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    rollback_state: Optional[Dict[str, Any]] = None


class VerificationResult(BaseModel):
    verified: bool
    checks: List[Dict[str, Any]] = Field(default_factory=list)
    notes: str = ""


class AuditRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: new_id("audit"))
    timestamp: datetime = Field(default_factory=_utcnow)
    case_id: str
    stage: str                             # telemetry|detection|enrichment|ai|policy|response|verification
    actor: str                             # "rule:<id>", "ai:<model>", "analyst", "policy-engine", "response:<action>"
    description: str
    inputs_refs: List[str] = Field(default_factory=list)
    outputs_refs: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Case(BaseModel):
    """End-to-end incident case tying every layer together."""
    case_id: str = Field(default_factory=lambda: new_id("case"))
    created_at: datetime = Field(default_factory=_utcnow)
    status: TriageStatus = TriageStatus.OPEN

    events: List[TelemetryEvent] = Field(default_factory=list)
    alerts: List[DetectionAlert] = Field(default_factory=list)
    enrichments: List[Evidence] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysis] = None
    policy_decision: Optional[PolicyDecision] = None
    actions: List[ActionResult] = Field(default_factory=list)
    verification: Optional[VerificationResult] = None
    audit_trail: List[AuditRecord] = Field(default_factory=list)

    metrics: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def confidence_band(score: float) -> ConfidenceBand:
    if score < 0.40:
        return ConfidenceBand.LOW
    if score < 0.70:
        return ConfidenceBand.MEDIUM
    if score < 0.90:
        return ConfidenceBand.HIGH
    return ConfidenceBand.VERY_HIGH
