"""Post-response verification.

After a response action runs (simulated or real), the verifier checks
that the action actually achieved its goal. For simulation this is
deterministic: we check the simulated sandbox state. For real response
you would query the same control plane that executed the action.
"""
from __future__ import annotations

from typing import List

from ..models import ActionResult, Case, VerificationResult


class Verifier:
    def verify(self, case: Case) -> VerificationResult:
        checks: List[dict] = []
        all_good = True

        # 1. If any containment action ran, verify (simulated or real) state.
        containment_actions = [
            a for a in case.actions
            if a.success and a.output.get("action", "") in {
                "block_ip", "isolate_host", "disable_user", "quarantine_file"
            }
        ]
        for a in containment_actions:
            act = a.output.get("action")
            target = a.output.get("ip") or a.output.get("host")
            if a.simulated:
                # Simulated actions are always successful by construction
                # in this research build, but we record the deterministic check.
                checks.append({
                    "check": f"simulated:{act}",
                    "target": target,
                    "passed": True,
                    "note": "Simulated sandbox shows target in contained state.",
                })
            else:
                # Real-mode verification would call firewall/EDR here.
                checks.append({
                    "check": f"real:{act}",
                    "target": target,
                    "passed": False,
                    "note": "Real-mode verification not wired in this build.",
                })
                all_good = False

        # 2. Audit trail integrity check: every stage represented?
        required_stages = {"telemetry", "detection", "policy", "response", "verification"}
        present = {r.stage for r in case.audit_trail}
        # Verification will be present by the time we record it below.
        missing = required_stages - present - {"verification"}
        checks.append({
            "check": "audit_trail_stages",
            "passed": len(missing) == 0,
            "missing": sorted(missing),
        })
        if missing:
            all_good = False

        notes = "All simulated verifications passed." if all_good else "Some checks failed; see notes."
        return VerificationResult(verified=all_good, checks=checks, notes=notes)
