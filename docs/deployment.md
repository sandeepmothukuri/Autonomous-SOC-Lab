# Deployment

## Prerequisites

* Docker Engine ≥ 24 with the Compose v2 plugin
* ≥ 6 GB RAM (OpenSearch 2 GB + StackStorm + other services)
* ≥ 10 GB disk for persistent volumes
* An isolated lab network. Do not deploy this stack on a production
  network without hardening.

## Quick start

```bash
git clone https://github.com/sandeepmothukuri/Autonomous-SOC-Lab.git
cd Autonomous-SOC-Lab

cp .env.example .env
# Edit .env and replace every <GENERATE_*> placeholder with a strong
# random value. You can generate values with:
#   python -c 'import secrets; print(secrets.token_urlsafe(32))'

bash scripts/health-check.sh        # file + config sanity
docker compose pull
docker compose up -d

# Wait ~2 minutes for StackStorm to initialize, then register the pack:
bash scripts/setup-stackstorm.sh

bash scripts/health-check.sh        # runtime checks
```

## Ports

All services bind to **127.0.0.1** by default. Change the
`*_BIND_ADDRESS` variables in `.env` only when you understand the
exposure. Recommended port forwards:

| Service | Default port |
|---|---|
| OpenSearch | 127.0.0.1:9200 |
| Dashboards | 127.0.0.1:5601 |
| Vector API | 127.0.0.1:8686 |
| StackStorm webhook | 127.0.0.1:9101 |
| StackStorm API | 127.0.0.1:9100 |
| DFIR-IRIS | 127.0.0.1:8000 |
| MISP | 127.0.0.1:8080 |
| Velociraptor GUI | 127.0.0.1:8889 |
| Caldera GUI | 127.0.0.1:8888 |

## Response modes

`SOC_RESPONSE_MODE` controls SOAR behavior globally:

| Mode | Behavior |
|---|---|
| `simulation` (default) | Workflows log what they would do; no changes to endpoints or firewalls. IRIS cases are still created. |
| `approval` | Workflows create IRIS cases flagged for analyst sign-off. They do not apply containment without explicit approval via the IRIS UI. |
| `active` | Workflows invoke Velociraptor / firewall APIs for high-severity, high-confidence, reversible actions. **Do not enable until you have tested in simulation and wired real handlers.** |

External integrations (AbuseIPDB, ipinfo) are optional. Leave the keys
blank in `.env` and workflows will gracefully degrade to an "unknown
enrichment" path that still creates cases.

## Generating synthetic events

```bash
python scripts/generate-events.py --scenario all
```

Appends brute-force, PowerShell, lateral-movement, and priv-esc
synthetic events into `data/sample_logs/` where Vector ingests them.

## Tear down

```bash
docker compose down          # stop; keep volumes
docker compose down -v       # stop AND wipe all data
```

## Running the end-to-end test

```bash
bash scripts/test-end-to-end.sh
```

This emits synthetic events and reports which services are reachable.
Components that are not running report SKIP rather than failing the
test; there are no fake passes.
