# Workflows

Author: Sandeep Mothukuri

## 1. Triage workflow (per case)

1. **Telemetry arrives** → events normalized, appended to case.
2. **Detection** fires zero or more alerts.
   - If zero alerts, case closes; nothing to do.
3. **Enrichment** adds TI hits and asset context.
4. **AI triage** produces a structured `AIAnalysis` (if enabled and
   validation passes).
5. **Policy engine** maps (alerts, analysis, config) to a decision.
6. **SOAR** plans candidate actions.
   - If policy outcome is `RECOMMEND` or `ENRICH_AND_RECOMMEND`,
     containment actions are marked `pending_approval`.
   - If outcome is `AUTO_CONTAIN`, reversible allowlisted actions
     execute in the configured mode.
   - Deny-list actions are refused.
7. **Verification** checks that executed actions achieved their goal.
8. **Metrics & audit** are persisted.

## 2. Analyst workflow

Analysts see:
- Alerts with deterministic evidence
- Enrichment/TI context
- AI summary, severity, confidence, hypothesis, rationale, and
  recommended action (clearly labeled as AI-generated)
- Policy decision and why
- Pending approvals (one click to approve/deny)
- Action history with rollback state where applicable
- Verification status

Analysts can override any automated recommendation, mark a case as a
false positive, or request additional enrichment.

## 3. Operator workflow

- Run `python scripts/healthcheck.py` on every config change.
- Run `python scripts/run_simulation.py` to validate red-team
  scenarios end-to-end.
- Run `pytest` in CI.
- Review metrics dashboards weekly for drift.

## 4. Red-team validation workflow

For each scenario in `src/soc/redteam/scenarios.py`:
1. Simulator emits telemetry events.
2. Pipeline runs end-to-end.
3. Post-run comparison checks:
   - Expected detections fired (no misses on mapped techniques).
   - Policy outcome matches expected outcome.
   - No deny-list actions executed.
   - Audit trail contains all required stages.
4. Aggregate metrics are reported.
