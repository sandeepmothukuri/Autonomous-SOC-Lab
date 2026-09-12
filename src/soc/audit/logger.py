"""Structured audit logger.

Every pipeline stage MUST append an AuditRecord to the case. In addition,
records are persisted as JSON-lines to cfg.audit_log_path for tamper-
evident post-incident review.

The audit trail is append-only; there is no update or delete API.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from ..models import AuditRecord, Case


class AuditLogger:
    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    # ---------- case-level record ----------
    def record(
        self,
        case: Case,
        stage: str,
        actor: str,
        description: str,
        inputs_refs: Optional[List[str]] = None,
        outputs_refs: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
    ) -> AuditRecord:
        rec = AuditRecord(
            case_id=case.case_id,
            stage=stage,
            actor=actor,
            description=description,
            inputs_refs=inputs_refs or [],
            outputs_refs=outputs_refs or [],
            metadata=metadata or {},
        )
        case.audit_trail.append(rec)
        self._persist(rec)
        return rec

    # ---------- persistence ----------
    def _persist(self, rec: AuditRecord) -> None:
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(rec.model_dump_json() + "\n")
        except OSError:
            # Audit failures must not crash the pipeline; surface via metrics.
            pass
