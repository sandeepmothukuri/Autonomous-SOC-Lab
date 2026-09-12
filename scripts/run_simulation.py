#!/usr/bin/env python3
"""Run all red-team scenarios through the pipeline and print a report.

Usage:
    python scripts/run_simulation.py
    python scripts/run_simulation.py --mode real   # caution: requires explicit config
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make src importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.config import SOCConfig
from soc.health.checks import run_health_checks
from soc.metrics.collector import MetricsCollector
from soc.pipeline import Pipeline
from soc.redteam.scenarios import all_scenarios


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Autonomous-SOC-Lab red-team simulations")
    parser.add_argument("--mode", choices=["audit_only", "simulated", "real"],
                        default=None, help="Override SOAR response mode")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    args = parser.parse_args()

    cfg = SOCConfig.load()
    if args.mode:
        cfg.soar.response_mode = args.mode

    # Pre-flight health checks
    health = run_health_checks(cfg)
    failed = [h for h in health if not h.ok]
    if failed:
        print("[!] Pre-flight health checks FAILED:")
        for h in failed:
            print(f"    - {h.name}: {h.detail}")
        return 2

    pipe = Pipeline(cfg=cfg)
    results = []
    for scen in all_scenarios():
        case = pipe.run(events=list(scen.events))
        results.append({
            "scenario_id": scen.scenario_id,
            "name": scen.name,
            "expected_detections": scen.expected_detections,
            "fired_detections": [a.rule_id for a in case.alerts],
            "expected_policy_outcome": scen.expected_policy_outcome,
            "actual_policy_outcome": case.policy_decision.outcome.value if case.policy_decision else "n/a",
            "status": case.status.value,
            "actions": [
                {
                    "name": a.output.get("action", "<unnamed>"),
                    "success": a.success,
                    "simulated": a.simulated,
                    "denied": bool(a.error and "denied" in (a.error or "")),
                }
                for a in case.actions
            ],
            "ai_confidence": case.ai_analysis.confidence if case.ai_analysis else None,
            "verified": case.verification.verified if case.verification else None,
        })

    agg = MetricsCollector().aggregate(
        # Re-run isn't needed; we already have cases in siem._mem
        []
    )
    # Aggregate from cases stored in SIEM
    from soc.models import Case
    cases = [Case(**doc) for doc in pipe.siem.all()]
    agg = MetricsCollector().aggregate(cases)

    report = {
        "response_mode": cfg.soar.response_mode,
        "scenarios": results,
        "aggregate_metrics": agg,
        "health_checks": [h.__dict__ for h in health],
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_human(report)
    return 0


def _print_human(report: dict) -> None:
    print("=" * 72)
    print(f"Autonomous-SOC-Lab  |  response_mode = {report['response_mode']}")
    print("=" * 72)
    for s in report["scenarios"]:
        detect_ok = set(s["expected_detections"]) == set(s["fired_detections"])
        if not s["expected_detections"] and s["status"] == "closed":
            policy_ok = True  # benign case — no alerts, policy not invoked
        else:
            policy_ok = s["expected_policy_outcome"] == s["actual_policy_outcome"]
        mark = "OK" if (detect_ok and policy_ok and s["verified"] is not False) else "REVIEW"
        print(f"\n[{mark}] {s['scenario_id']} — {s['name']}")
        print(f"    expected detections : {s['expected_detections']}")
        print(f"    fired detections    : {s['fired_detections']}")
        print(f"    expected policy     : {s['expected_policy_outcome']}")
        print(f"    actual policy       : {s['actual_policy_outcome']}")
        print(f"    case status         : {s['status']}")
        print(f"    verified            : {s['verified']}")
        if s["ai_confidence"] is not None:
            print(f"    ai confidence       : {s['ai_confidence']:.2f}")
        if s["actions"]:
            for a in s["actions"]:
                tag = []
                if a["simulated"]: tag.append("SIM")
                if a["denied"]:   tag.append("DENIED")
                if a["success"]:  tag.append("OK")
                else:             tag.append("FAIL")
                name = a.get("name") or a.get("action") or "<unnamed>"
                print(f"       - {name:20s} {'/'.join(tag)}")
    print("\n" + "-" * 72)
    print("Aggregate metrics:")
    for k, v in report["aggregate_metrics"].items():
        if isinstance(v, float):
            print(f"  {k:35s} = {v:.3f}")
        else:
            print(f"  {k:35s} = {v}")


if __name__ == "__main__":
    raise SystemExit(main())
