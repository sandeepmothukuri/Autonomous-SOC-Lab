"""Health checks for platform components.

These checks are deterministic and designed to run at startup or in
CI. They verify that configuration, rules, allowlists, and schemas
are internally consistent — not that external services are reachable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..config import SOCConfig
from ..detection.engine import default_rules


@dataclass
class HealthResult:
    name: str
    ok: bool
    detail: str = ""


def run_health_checks(cfg: SOCConfig) -> List[HealthResult]:
    results: List[HealthResult] = []

    # 1. Config sanity
    results.append(_check_threshold_ordering(cfg))
    results.append(_check_allowlists(cfg))
    results.append(_check_deny_list_contains_destructive(cfg))

    # 2. Detection rules sanity
    results.append(_check_rules_have_required_fields())

    # 3. Mode safety
    results.append(_check_real_mode_safeguards(cfg))

    return results


def _check_threshold_ordering(cfg: SOCConfig) -> HealthResult:
    t = cfg.thresholds
    ok = 0.0 <= t.low_cutoff < t.medium_cutoff < t.high_cutoff <= 1.0
    return HealthResult(
        name="threshold_ordering",
        ok=ok,
        detail="Cutoffs must satisfy 0 <= low < medium < high <= 1.",
    )


def _check_allowlists(cfg: SOCConfig) -> HealthResult:
    s = cfg.soar
    overlap = set(s.autonomous_allowlist) - set(s.action_allowlist)
    ok = len(overlap) == 0
    return HealthResult(
        name="autonomous_allowlist_subset",
        ok=ok,
        detail=f"Autonomous actions must also be on action_allowlist. Offenders: {sorted(overlap)}",
    )


def _check_deny_list_contains_destructive(cfg: SOCConfig) -> HealthResult:
    required = {"wipe_host", "delete_file", "execute_shell", "run_arbitrary_command"}
    missing = required - set(cfg.soar.deny_list)
    ok = len(missing) == 0
    return HealthResult(
        name="deny_list_coverage",
        ok=ok,
        detail=f"High-risk actions missing from deny_list: {sorted(missing)}",
    )


def _check_rules_have_required_fields() -> HealthResult:
    problems = []
    for r in default_rules():
        if not r.rule_id or not r.rule_name or r.match_fn is None:
            problems.append(r.rule_id or "<unnamed>")
    return HealthResult(
        name="detection_rules_completeness",
        ok=len(problems) == 0,
        detail=f"Malformed rules: {problems}",
    )


def _check_real_mode_safeguards(cfg: SOCConfig) -> HealthResult:
    if cfg.soar.response_mode != "real":
        return HealthResult(
            name="real_mode_safeguards",
            ok=True,
            detail="Response mode is not REAL; safe by default.",
        )
        # If REAL mode is enabled, require that destructive actions are denied
        # and that autonomous_allowlist contains no destructive items.
    destructive = {"wipe_host", "delete_file", "reboot_host_without_approval"}
    leak = set(cfg.soar.autonomous_allowlist) & destructive
    return HealthResult(
        name="real_mode_safeguards",
        ok=len(leak) == 0,
        detail=f"Destructive actions on autonomous_allowlist in REAL mode: {sorted(leak)}",
    )
