"""Central configuration loading for the SOC platform.

Configuration is loaded from YAML files plus environment variable
overrides (SOC_*). Defaults are conservative: simulated response only,
high thresholds for autonomous action, strict allowlists.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "soc.yaml"


@dataclass
class PolicyThresholds:
    # Band cutoffs — keep in sync with models.confidence_band
    low_cutoff: float = 0.40
    medium_cutoff: float = 0.70
    high_cutoff: float = 0.90

    # Auto-containment requires BOTH:
    auto_contain_min_confidence: float = 0.90
    auto_contain_min_severity: str = "high"
    # and the action must be in the reversible allowlist


@dataclass
class SOARConfig:
    response_mode: str = "simulated"  # audit_only | simulated | real
    action_allowlist: List[str] = field(default_factory=lambda: [
        "block_ip",
        "isolate_host",
        "disable_user",
        "quarantine_file",
        "add_ioc_watch",
        "notify_analyst",
    ])
    # Actions that can run fully autonomously when thresholds are met.
    # Destructive actions (delete, wipe) are NEVER autonomous by default.
    autonomous_allowlist: List[str] = field(default_factory=lambda: [
        "block_ip",
        "isolate_host",
    ])
    deny_list: List[str] = field(default_factory=lambda: [
        "wipe_host",
        "delete_file",
        "execute_shell",
        "run_arbitrary_command",
    ])
    dry_run_by_default: bool = True
    default_action_timeout_s: int = 30
    max_action_retries: int = 2


@dataclass
class AIConfig:
    enabled: bool = True
    # In this research build the "AI client" is a deterministic mock
    # that returns structured, evidence-grounded analysis. Real LLM
    # integrations can be plugged in by replacing ai/client.py.
    provider: str = "mock"
    model_id: str = "mock-grounded-v0"
    request_timeout_s: int = 15
    max_retries: int = 2
    require_evidence_grounding: bool = True
    reject_on_unsupported_claim: bool = True


@dataclass
class SOCConfig:
    thresholds: PolicyThresholds = field(default_factory=PolicyThresholds)
    soar: SOARConfig = field(default_factory=SOARConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    siem_index: str = "soc-cases"
    audit_log_path: str = "data/audit.log"

    @classmethod
    def load(cls, path: Path | str | None = None) -> "SOCConfig":
        cfg = cls()
        p = Path(path) if path else DEFAULT_CONFIG_PATH
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                raw: Dict[str, Any] = yaml.safe_load(f) or {}
            _apply(cfg, raw)
        # Environment overrides (SOC_SOAR__RESPONSE_MODE=real, etc.)
        _apply_env(cfg)
        return cfg


def _apply(cfg: SOCConfig, raw: Dict[str, Any]) -> None:
    if "thresholds" in raw and isinstance(raw["thresholds"], dict):
        for k, v in raw["thresholds"].items():
            if hasattr(cfg.thresholds, k):
                setattr(cfg.thresholds, k, v)
    if "soar" in raw and isinstance(raw["soar"], dict):
        for k, v in raw["soar"].items():
            if hasattr(cfg.soar, k):
                setattr(cfg.soar, k, v)
    if "ai" in raw and isinstance(raw["ai"], dict):
        for k, v in raw["ai"].items():
            if hasattr(cfg.ai, k):
                setattr(cfg.ai, k, v)
    for k in ("siem_index", "audit_log_path"):
        if k in raw:
            setattr(cfg, k, raw[k])


def _apply_env(cfg: SOCConfig) -> None:
    mapping = {
        "SOC_SOAR__RESPONSE_MODE": ("soar", "response_mode"),
        "SOC_AI__ENABLED": ("ai", "enabled"),
        "SOC_AUDIT_LOG_PATH": (None, "audit_log_path"),
        "SOC_SIEM_INDEX": (None, "siem_index"),
    }
    for env_key, (section, attr) in mapping.items():
        val = os.environ.get(env_key)
        if val is None:
            continue
        if section == "soar":
            setattr(cfg.soar, attr, val)
        elif section == "ai":
            setattr(cfg.ai, attr, _bool(val))
        else:
            setattr(cfg, attr, val)


def _bool(v: str) -> bool:
    return v.strip().lower() in {"1", "true", "yes", "on"}
