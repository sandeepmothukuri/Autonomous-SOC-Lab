"""SOAR action executor.

SAFETY PROPERTIES:
  - Every action is checked against allowlist AND denied-list.
  - Every action has a timeout and retry cap.
  - Default mode is DRY_RUN; response_mode global flag controls SIM/REAL.
  - Destructive actions are on the deny-list by default; they cannot be
    executed autonomously.
  - Reversible actions record rollback state (simulated here).
  - Every execution writes an ActionResult and an audit record.
  - The executor will NOT run shell commands.
"""
from __future__ import annotations

import time
from typing import Callable, Dict, Optional

from ..config import SOCConfig
from ..models import (
    ActionImpact,
    ActionMode,
    ActionResult,
    Case,
    PolicyDecision,
    ResponseAction,
)
from ..audit.logger import AuditLogger


class ActionDenied(Exception):
    pass


class ActionTimeout(Exception):
    pass


# Handlers return (output_dict, optional_rollback_state).
ActionHandler = Callable[[ResponseAction, ActionMode], tuple[dict, Optional[dict]]]


class SOARExecutor:
    def __init__(self, cfg: SOCConfig, audit: AuditLogger):
        self.cfg = cfg
        self.audit = audit
        self._handlers: Dict[str, ActionHandler] = {
            "block_ip": _handler_block_ip,
            "isolate_host": _handler_isolate_host,
            "disable_user": _handler_disable_user,
            "quarantine_file": _handler_quarantine_file,
            "add_ioc_watch": _handler_add_ioc_watch,
            "notify_analyst": _handler_notify_analyst,
        }

    # ------------------------------------------------------------------
    def execute(
        self,
        case: Case,
        action: ResponseAction,
        decision: PolicyDecision,
        approval_granted: bool = False,
    ) -> ActionResult:
        """Execute a single response action subject to policy."""
        # 1. Global denylist check
        if action.name in self.cfg.soar.deny_list:
            return self._deny(case, action, "action is on deny_list")

        # 2. Allowlist check
        if action.name not in self.cfg.soar.action_allowlist:
            return self._deny(case, action, "action not on action_allowlist")

        # 3. Policy outcome gating
        if action.name not in (decision.allowed_actions or []):
            return self._deny(case, action, f"action not allowed by policy outcome '{decision.outcome.value}'")

        # 4. Approval gating
        # Observation and notification actions never require approval.
        impactful = action.impact in (ActionImpact.CONTAINMENT, ActionImpact.DESTRUCTIVE)
        if impactful and decision.requires_approval and not approval_granted:
            return self._deny(case, action, "approval required but not granted", denied=False, pending=True)

        # 5. Determine actual execution mode (global response_mode + action.mode)
        mode = self._resolve_mode(action)

        # 6. Lookup handler
        handler = self._handlers.get(action.name)
        if handler is None:
            return self._deny(case, action, f"no handler registered for action '{action.name}'")

        # 7. Timeout + retry (synchronous, simulated timeout budget)
        timeout = self.cfg.soar.default_action_timeout_s
        last_err: Optional[str] = None
        for attempt in range(self.cfg.soar.max_action_retries + 1):
            t0 = time.perf_counter()
            try:
                output, rollback = handler(action, mode)
                # "timeout" simulation: if handler produced output dict with
                # __simulated_delay__ > timeout we raise. Real handlers would
                # be wrapped with signal/thread timeout.
                delay = float(output.get("__simulated_delay__", 0.0))
                if delay > timeout:
                    raise ActionTimeout(f"handler exceeded {timeout}s timeout")
                duration_ms = (time.perf_counter() - t0) * 1000.0
                result = ActionResult(
                    action_id=action.action_id,
                    success=True,
                    simulated=(mode != ActionMode.REAL),
                    output={**output, "duration_ms": duration_ms, "attempt": attempt + 1, "mode": mode.value},
                    rollback_state=rollback,
                )
                case.actions.append(result)
                self.audit.record(
                    case,
                    stage="response",
                    actor=f"response:{action.name}",
                    description=f"Executed action {action.name} (mode={mode.value}, success=True)",
                    inputs_refs=[action.action_id],
                    outputs_refs=[result.action_id],
                    metadata={"mode": mode.value, "target": action.target},
                )
                return result
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                continue

        # All retries exhausted
        result = ActionResult(
            action_id=action.action_id,
            success=False,
            simulated=True,
            error=last_err,
        )
        case.actions.append(result)
        self.audit.record(
            case,
            stage="response",
            actor=f"response:{action.name}",
            description=f"Action {action.name} FAILED after retries: {last_err}",
            inputs_refs=[action.action_id],
            metadata={"mode": mode.value, "error": last_err},
        )
        return result

    # ------------------------------------------------------------------
    def plan_actions(self, case: Case, decision: PolicyDecision) -> list[ResponseAction]:
        """Turn a PolicyDecision into a list of candidate ResponseActions
        (still subject to execute() checks). This is deterministic and
        grounded in alert entities."""
        actions: list[ResponseAction] = []
        if not case.alerts:
            return actions
        # Pull entities from the top alert
        top = max(case.alerts, key=lambda a: _sev_rank(a.severity))
        entities = top.entities

        # Always notify
        actions.append(ResponseAction(
            name="notify_analyst",
            impact=ActionImpact.NOTIFICATION,
            target={"case_id": case.case_id, "alert_id": top.alert_id},
            mode=ActionMode.DRY_RUN if self.cfg.soar.dry_run_by_default else ActionMode.SIMULATE,
        ))

        # Add IOC watch for any malicious IPs
        for key in ("src_ip", "dst_ip"):
            ip = entities.get(key)
            if ip:
                actions.append(ResponseAction(
                    name="add_ioc_watch",
                    impact=ActionImpact.OBSERVATION,
                    target={"ip": ip},
                ))

        # Containment actions only when policy permits
        if decision.outcome.value in ("auto_contain",) or decision.requires_approval:
            host = entities.get("host")
            if host and "isolate_host" in (decision.allowed_actions or []):
                actions.append(ResponseAction(
                    name="isolate_host",
                    impact=ActionImpact.CONTAINMENT,
                    target={"host": host},
                ))
            for key in ("src_ip", "dst_ip"):
                ip = entities.get(key)
                if ip and "block_ip" in (decision.allowed_actions or []):
                    actions.append(ResponseAction(
                        name="block_ip",
                        impact=ActionImpact.CONTAINMENT,
                        target={"ip": ip},
                    ))
            user = entities.get("user")
            if user and "disable_user" in (decision.allowed_actions or []):
                actions.append(ResponseAction(
                    name="disable_user",
                    impact=ActionImpact.CONTAINMENT,
                    target={"user": user},
                ))
        return actions

    # ------------------------------------------------------------------
    def _resolve_mode(self, action: ResponseAction) -> ActionMode:
        global_mode = self.cfg.soar.response_mode
        if global_mode == "audit_only":
            return ActionMode.DRY_RUN
        if global_mode == "simulated":
            return ActionMode.SIMULATE
        # global_mode == "real" -> respect action.mode, default DRY_RUN if requested
        if action.mode == ActionMode.REAL:
            return ActionMode.REAL
        return action.mode

    def _deny(self, case: Case, action: ResponseAction, reason: str,
              denied: bool = True, pending: bool = False) -> ActionResult:
        result = ActionResult(
            action_id=action.action_id,
            success=False,
            simulated=True,
            output={
                "action": action.name,
                "denied": denied,
                "pending_approval": pending,
                "reason": reason,
            },
            error=reason,
        )
        case.actions.append(result)
        self.audit.record(
            case,
            stage="response",
            actor="soar-policy",
            description=f"Action {action.name} denied: {reason}",
            inputs_refs=[action.action_id],
            metadata={"reason": reason, "pending_approval": pending},
        )
        return result


# ---------------------------------------------------------------------------
# Simulated action handlers.
# In REAL mode these would call out to EDR/firewall/IdP APIs.
# In this research build they record simulated state and rollback data.
# ---------------------------------------------------------------------------

def _handler_block_ip(action: ResponseAction, mode: ActionMode):
    ip = action.target.get("ip")
    return (
        {"action": "block_ip", "ip": ip, "firewall": "simulated-fw", "applied": mode.value},
        {"rollback": "unblock_ip", "ip": ip},
    )


def _handler_isolate_host(action: ResponseAction, mode: ActionMode):
    host = action.target.get("host")
    return (
        {"action": "isolate_host", "host": host, "edr": "simulated-edr", "applied": mode.value},
        {"rollback": "unisolate_host", "host": host},
    )


def _handler_disable_user(action: ResponseAction, mode: ActionMode):
    user = action.target.get("user")
    return (
        {"action": "disable_user", "user": user, "idp": "simulated-idp", "applied": mode.value},
        {"rollback": "enable_user", "user": user},
    )


def _handler_quarantine_file(action: ResponseAction, mode: ActionMode):
    return (
        {"action": "quarantine_file", "file": action.target.get("file"), "applied": mode.value},
        {"rollback": "restore_file", "file": action.target.get("file")},
    )


def _handler_add_ioc_watch(action: ResponseAction, mode: ActionMode):
    return (
        {"action": "add_ioc_watch", "ioc": action.target, "applied": mode.value},
        None,  # observation-only; no rollback needed
    )


def _handler_notify_analyst(action: ResponseAction, mode: ActionMode):
    return (
        {"action": "notify_analyst", "target": action.target, "channel": "soc-triage-sim", "applied": mode.value},
        None,
    )


def _sev_rank(s):
    from ..models import Severity
    return {Severity.INFO:0, Severity.LOW:1, Severity.MEDIUM:2, Severity.HIGH:3, Severity.CRITICAL:4}[s]
