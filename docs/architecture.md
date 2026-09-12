# Architecture

Autonomous SOC Lab is an open-source detection-and-response platform that
demonstrates a safe-by-default autonomous SOC stack. The data flow is
strictly linear: every decision is deterministic, AI and enrichment are
advisory, and destructive response requires explicit opt-in.

## Components

```
   Endpoints / Servers
        │  (syslog, winlogbeat, zeek, file logs)
        ▼
     ┌─────────┐   normalisation   ┌────────────┐  routing/indices
     │ Vector  │ ────────────────► │ OpenSearch │ ◄── Dashboards
     └────┬────┘                   └─────┬──────┘
          │ ECS-normalized events         │ search
          ▼                              ▼
     ┌────────────┐ webhook         ┌────────────┐
     │ ElastAlert2│ ──────────────► │ StackStorm │ SOAR
     └────────────┘  alerts          └──┬──┬──┬───┘
                                        │  │  │
                  ┌─────────────────────┘  │  └──────────────┐
                  ▼                        ▼                 ▼
              ┌───────┐               ┌──────────┐     ┌────────────┐
              │ MISP  │               │ DFIR-IRIS│     │Velociraptor│
              └───────┘               └──────────┘     └────────────┘
                  ▲ TI                       ▲
                  │                          │
              AbuseIPDB/ipinfo (optional, offline-fallback)
                                        ┌─────────┐
                                        │ Analyst │
                                        └─────────┘
                           Caldera (adversary emulation, safe profile)
```

| Component | Role | Default state |
|---|---|---|
| OpenSearch 2.11 | Event + alert storage | Single-node, security plugin **disabled** for lab, persistent volume |
| OpenSearch Dashboards | Search / dashboards / visualizations | Bound to 127.0.0.1:5601 |
| Vector 0.35 | Log collection, normalization, routing | Reads sample_logs, writes `logs-*` and `alerts-critical-*` indices |
| ElastAlert2 2.14 | Rule-based alerting | Fires on normalized ECS events, POSTs to StackStorm webhook |
| StackStorm 3.8 | SOAR workflow engine | Response mode read from `SOC_RESPONSE_MODE` (default: simulation) |
| DFIR-IRIS v2.4 | Case management | Web UI on 127.0.0.1:8000, worker included |
| MISP | Threat intel | Redis+MySQL backend, bound to localhost |
| Velociraptor | DFIR collection and host isolation | GUI on 127.0.0.1:8889, sample VQL hunts provided (read-only) |
| MITRE Caldera | Adversary emulation | Safe profile only; no destructive actions; localhost-bound |

## Data flow

1. **Collect.** Vector tails file logs (synthetic sample logs by default;
   syslog/winlogbeat/Zeek sources can be enabled).
2. **Normalize.** Vector transforms events to an ECS-like schema. See
   `docs/detection-engineering.md` for the field contract.
3. **Store.** Events are indexed in OpenSearch under `logs-YYYY.MM.DD`.
   Critical alerts (PowerShell encoded commands, tagged `alert.rule`)
   are additionally routed to `alerts-critical-YYYY.MM.DD`.
4. **Detect.** ElastAlert2 rules fire on structured conditions (frequency,
   any, bool) over normalized fields.
5. **Enrich.** StackStorm workflows enrich with AbuseIPDB / ipinfo when
   API keys are configured; otherwise they fall back to local/unknown and
   still create cases.
6. **Decide.** Workflows branch on `SOC_RESPONSE_MODE`.
7. **Respond.** In `simulation` mode actions are logged only. In
   `approval` mode they create IRIS cases flagged for sign-off. In
   `active` mode they call Velociraptor / firewall / IdP APIs (real
   handlers must be wired per deployment).
8. **Verify & audit.** Every workflow posts a result to an IRIS case
   and echoes a structured log line.

## Trust model

- Deterministic components (Vector, ElastAlert2, policy branches in
  Orquesta, health checks) are the authority.
- Enrichment from external services (AbuseIPDB, ipinfo, MISP) is treated
  as advisory — failures never block case creation.
- Destructive actions are never executed in the default profile.
- Caldera adversary exercises are non-destructive discovery/execution
  profiles only.
