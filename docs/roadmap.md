# Roadmap

Author: Sandeep Mothukuri

Planned, but not yet implemented. Contributions (by the author) are
organized along these tracks.

## Detection
- Add YAML-defined rules loader (in addition to Python rules).
- Add Sigma rule compatibility layer.
- Add cross-event correlation and sliding-window aggregations.

## AI
- Pluggable provider adapters for OpenAI, Anthropic, and local models.
- Structured output enforcement via provider-native schema modes.
- Retrieval-grounded enrichment from internal knowledge bases.
- Alert clustering across cases.
- Fine-grained calibration of confidence scores against historical
  analyst outcomes.

## Policy
- Time-of-day and asset-criticality modifiers.
- Policy-as-code (Rego or CEL) in addition to the Python engine.
- Explicit blast-radius controls per action.

## SOAR
- Real handlers for common EDRs, firewalls, and IdPs.
- Two-person approval for destructive actions.
- Rollback automation with explicit operator confirmation.
- Playbook versioning.

## DFIR
- Integrate Velociraptor / DFIR agent collection (simulation-only by
  default).
- Automatic artifact collection plan with estimated collection cost.

## Verification
- Active verification probes (in simulated environments).
- Post-remediation threat hunting to detect persistence.

## Metrics
- Time-series metrics export (Prometheus).
- Analyst time-saved estimation grounded in measured audit data.
- Continuous false-positive tracking.

## Platform
- UI for case triage and approvals.
- Multi-tenant / multi-environment support.
- Signed audit log (HMAC chains).
- Secrets backend integration.
- CI-compatible red-team regression harness.
