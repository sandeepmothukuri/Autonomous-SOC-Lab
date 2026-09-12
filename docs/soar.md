# SOAR (StackStorm)

SOAR workflows live in `soar/` as StackStorm pack content:

```
soar/
├── pack.yaml
├── rules/elastalert.yaml      # webhook triggers mapped to actions
└── actions/
    ├── *.yaml                 # action metadata
    └── workflows/*.yaml       # Orquesta workflows
```

## Response modes

Every workflow reads `SOC_RESPONSE_MODE` (default `simulation`) from the
container environment set by docker compose. Workflows contain three
branches:

| Mode | Branch behavior |
|---|---|
| `simulation` | Print/log intended response (e.g. `SIMULATION: Would block IP x.x.x.x`). Open an IRIS case noting the simulated action. |
| `approval` | Post the case to IRIS with severity set to require analyst sign-off. Do not call containment APIs. |
| `active` | Call the configured containment API (Velociraptor for isolation, firewall hook for IP block). |

Default mode is **simulation**. Active mode should only be enabled
after:

1. Full simulated/approval-mode testing.
2. Real handlers are wired into the workflow HTTP tasks.
3. An approval/rollback SOP is documented.
4. Health checks for dependent services are passing.

## Datastore keys

Workflows read the following keys from the StackStorm datastore:

| Key | Purpose |
|---|---|
| `abuseipdb_key` | AbuseIPDB API key (optional — blank means offline) |
| `iris_token` | IRIS API bearer token for case creation (optional) |
| `velociraptor_token` | Velociraptor API bearer token (needed in `active` mode) |

These are set by `scripts/setup-stackstorm.sh` from environment
variables.

## Existing workflows

| Workflow | Triggering rule | Action taken |
|---|---|---|
| `auto_respond.yaml` | `auto_block_brute_force` | Enrich IP via ipinfo/AbuseIPDB; block in `active`; open IRIS case |
| `investigate_powershell.yaml` | `investigate_powershell` | Open IRIS case with script-block context |
| `isolate_host.yaml` | `respond_lateral_movement` | Velociraptor isolation request (mode-gated) + IRIS case |
| `create_iris_case.yaml` | `create_privilege_escalation_case` | Open a generic IRIS case |

## Registering the pack

After `docker compose up -d`, wait ~2 minutes for StackStorm to
initialize, then run:

```bash
bash scripts/setup-stackstorm.sh
```

This registers the pack, ensures the `elastalert` webhook exists,
populates datastore keys from your shell environment, and reloads
rules/actions.

## Design rules for new workflows

1. Always read `SOC_RESPONSE_MODE` and branch explicitly.
2. HTTP calls to external services must have `timeout` set and a
   `failed()` branch that still creates an IRIS case.
3. Never run shell commands from workflow input. Use predefined action
   targets and JSON request bodies only.
4. Destructive actions (host isolation, account disable, IP blocks)
   must be reversible and must fall through to simulation if the
   response mode is not `active`.
