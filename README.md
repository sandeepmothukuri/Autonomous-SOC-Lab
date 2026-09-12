# Autonomous-SOC-Lab

An open-source, safe-by-default Autonomous SOC research platform
built on Vector, OpenSearch, ElastAlert2, StackStorm, DFIR-IRIS, MISP,
Velociraptor, and MITRE Caldera.

> **Default mode is `simulation`.** The lab does not perform any
> containment action until you explicitly set
> `SOC_RESPONSE_MODE=approval` or `active` and wire real handlers.
> Management interfaces bind to **127.0.0.1** by default.

---

## What this project demonstrates

A complete detection-and-response pipeline that keeps deterministic
controls authoritative, treats AI/enrichment as advisory, and makes
response mode an explicit, auditable policy decision:

```
Endpoints / logs
    → Vector     (collection + ECS normalization)
    → OpenSearch (indexed storage + dashboards)
    → ElastAlert (deterministic rule-based detection)
    → StackStorm (SOAR workflows, mode-gated)
        ├── MISP / AbuseIPDB / ipinfo  (threat intel — optional, offline-safe)
        ├── Velociraptor               (DFIR collection + isolation)
        └── DFIR-IRIS                  (case management)
    → Analyst
```

Adversary emulation is provided via a safe MITRE Caldera profile
(non-destructive discovery / execution TTPs only).

## Technology stack

| Purpose | Technology |
|---|---|
| Log collection & normalization | Vector 0.35 |
| Storage / search | OpenSearch 2.11 + OpenSearch Dashboards 2.11 |
| Rule-based detection | ElastAlert2 2.14 |
| SOAR / workflow engine | StackStorm 3.8 |
| Case management | DFIR-IRIS v2.4.5 + Postgres 15 |
| Threat intelligence | MISP (Redis + MySQL 8.0) |
| DFIR collection & isolation | Velociraptor |
| Adversary emulation | MITRE Caldera (safe profile) |
| Deterministic AI-trust model | Python research framework in `src/soc/` |

## Quick start

```bash
git clone https://github.com/sandeepmothukuri/Autonomous-SOC-Lab.git
cd Autonomous-SOC-Lab

cp .env.example .env
# edit .env and replace every <GENERATE_*> placeholder with a strong
# random value. You can generate them with:
#   python -c 'import secrets; print(secrets.token_urlsafe(32))'

bash scripts/health-check.sh
docker compose pull
docker compose up -d

# Wait ~2 minutes for StackStorm to initialize, then register the pack:
bash scripts/setup-stackstorm.sh

# Generate synthetic events to exercise the pipeline:
python scripts/generate-events.py --scenario all

# Run health + end-to-end checks:
bash scripts/health-check.sh
bash scripts/test-end-to-end.sh
```

By default every service listens on `127.0.0.1`. Open Dashboards at
http://127.0.0.1:5601, IRIS at http://127.0.0.1:8000, MISP at
http://127.0.0.1:8080, Velociraptor at http://127.0.0.1:8889, Caldera
at http://127.0.0.1:8888.

## Configuration

All configuration is in `.env` (generated from `.env.example`) and
the YAML files under `configs/`. Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `SOC_RESPONSE_MODE` | `simulation` | `simulation` / `approval` / `active` |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | _(set in .env)_ | Unused when security plugin is disabled (lab default) |
| `ST2_PASSWORD` | _(set)_ | StackStorm admin password |
| `IRIS_*`, `POSTGRES_*` | _(set)_ | IRIS and Postgres credentials |
| `MISP_*`, `MYSQL_*` | _(set)_ | MISP credentials |
| `VELOCIRAPTOR_ADMIN_PASSWORD` | _(set)_ | Velociraptor GUI password |
| `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN` | empty | Optional; empty ⇒ offline fallback |
| `*_BIND_ADDRESS` | `127.0.0.1` | Bind address for each service |

See `docs/deployment.md` for full deployment guidance.

## Detection engineering

Detections are ElastAlert2 YAML rules under `detections/` that operate
on a single ECS-like schema produced by Vector. Four detections ship
by default:

| Rule | MITRE | Logic |
|---|---|---|
| Brute Force Attack Detected | T1110.001 | 5 failed_logins in 2 minutes per source.ip |
| Suspicious PowerShell Execution | T1059.001 | EncodedCommand / DownloadString / Bypass in Script Block logging |
| Lateral Movement Detected | T1021 | 3 internal RDP/SMB/SSH/WinRM connections in 5 minutes per source |
| Privilege Escalation Attempt | T1548.003 | Sudoers NOPASSWD use or web-server spawning shell |

For the field contract, false-positive handling, and how to add new
rules see `docs/detection-engineering.md` and `docs/mitre-coverage.md`.

## SOAR workflows

Workflows live under `soar/actions/workflows/` as Orquesta workflows.
Every workflow reads `SOC_RESPONSE_MODE` and branches accordingly:

| Mode | Behavior |
|---|---|
| `simulation` | Logs intended response, opens IRIS case. No changes. |
| `approval` | Creates IRIS case flagged for analyst sign-off. |
| `active` | Calls containment APIs (Velociraptor, firewall). Must be explicitly enabled. |

External enrichment (AbuseIPDB, ipinfo, MISP) is optional; if a key is
missing or the service is unreachable, workflows fall back to
"unknown" enrichment and still create cases.

See `docs/soar.md`.

## Threat intelligence

* **MISP** runs locally (Redis + MySQL). No feeds are preloaded.
* **AbuseIPDB / ipinfo** are called when API keys are configured.
* **Graceful degradation** is enforced at the workflow level.
* See `docs/threat-intelligence.md`.

## DFIR (Velociraptor + IRIS)

* Velociraptor serves its GUI on http://127.0.0.1:8889.
* Sample read-only VQL hunts are provided in `velociraptor/hunts/`
  (suspicious PowerShell, run-key persistence, network connections).
* Host isolation is only invoked when `SOC_RESPONSE_MODE=active`.
* All alerts create (or attempt to create) a DFIR-IRIS case.
* See `docs/incident-response.md`.

## MITRE Caldera

* Safe-by-default adversary profile (`caldera/red_team.yml`) with
  non-destructive APT29-inspired and pre-stage TTPs.
* Exercises validate the detection stack end-to-end without modifying
  endpoint state.
* Destructive actions (ransomware simulation, log wiping, LSASS
  dumps) are deliberately excluded.

## Lab exercises

1. Start the stack and generate brute-force events:
   `python scripts/generate-events.py --scenario brute_force`
2. Open Dashboards and verify the `logs-*` index contains events.
3. Wait for ElastAlert to fire (≤ 2× `run_every` = 60 seconds).
4. Verify the StackStorm webhook was triggered
   (`docker logs soc-stackstorm | grep soc_lab`).
5. Open IRIS and confirm the case was created.
6. Repeat for each scenario: `powershell`, `lateral_movement`,
   `privilege_escalation`, `all`.
7. Run a Caldera ability against a connected test agent and confirm
   the matching detection fires.

## Testing

Static tests run on every commit via GitHub Actions:

```bash
pytest -q                       # Python + YAML + security + VRL checks
bash scripts/health-check.sh    # files, compose validity, service reachability
bash scripts/test-end-to-end.sh # synthetic event + reachability chain
shellcheck scripts/*.sh         # shell lint
```

See `docs/testing.md` for details. **54 Python tests and a full static
validation suite** (`tests/validate_lab.py`) ship with the repo.

## Security model

* Default response mode is `simulation` — no containment actions
  execute out of the box.
* All management interfaces bind to 127.0.0.1.
* No hardcoded credentials. `.env` is gitignored; `.env.example` uses
  `<GENERATE_*>` placeholders.
* OpenSearch security plugin is disabled for lab use (auth-free,
  isolated network). Hardening instructions in `docs/security.md`.
* Caldera adversary profile is non-destructive.
* Critical-event routing is deterministic: only events tagged
  `event.severity = critical` or `alert.rule` by Vector flow to the
  `alerts-critical-*` index.

## Repository structure

```
.
├── architecture/             # architecture diagram (SVG mockup)
├── caldera/                  # MITRE Caldera safe adversary profile
├── configs/                  # OpenSearch / Dashboards / ElastAlert / Velociraptor
├── data/sample_logs/         # synthetic log fixtures for Vector
├── detections/               # ElastAlert2 detection rules
├── docs/                     # architecture, deployment, security, playbooks
├── pipeline/vector.toml      # Vector collection/normalization
├── scripts/                  # health check, e2e test, event generator, setup
├── soar/                     # StackStorm pack (rules, actions, workflows)
├── screenshots/              # UI mockups (SVG, labeled as mockups)
├── src/soc/                  # deterministic AI-trust research framework
├── tests/                    # pytest suite + fixtures
├── velociraptor/hunts/       # sample VQL hunts
├── docker-compose.yml
├── .env.example
└── README.md
```

> **Visuals note:** The PNG/SVG files in `screenshots/` and
> `architecture/` are labeled **mockups**. They represent the UI
> surface area of a deployed lab; they are not live screenshots of the
> running stack.

## Limitations

* OpenSearch security plugin is disabled in the default compose file
  — the stack is intended for an isolated lab network.
* Real firewall/EDR/IdP handlers for `active` mode are not shipped;
  workflows provide HTTP stubs that you must wire to your own control
  planes.
* Velociraptor endpoint agents are not pre-installed; distribute them
  manually per the Velociraptor docs.
* No AI / LLM integration is included in the Docker stack. The
  Python research framework in `src/soc/` provides a deterministic,
  evidence-grounded triage model with a pluggable client interface;
  wiring a real LLM is left as an explicit integration task (see
  `docs/ai_trust_model.md` in the Python framework docs).
* Runtime stack boot could not be validated in this sandbox (no Docker
  daemon). Static validation is exhaustive; run
  `bash scripts/test-end-to-end.sh` on a Docker-enabled host to
  complete runtime validation. See `docs/validation-matrix.md`.

## Documentation

| Document | Purpose |
|---|---|
| `docs/architecture.md` | Component diagram and data flow |
| `docs/deployment.md` | Installation, configuration, response modes |
| `docs/security.md` | Default guarantees and hardening steps |
| `docs/detection-engineering.md` | Field contract, tuning, writing new rules |
| `docs/soar.md` | SOAR workflows, response modes, datastore keys |
| `docs/threat-intelligence.md` | MISP / AbuseIPDB / ipinfo, offline fallback |
| `docs/incident-response.md` | Analyst triage playbooks |
| `docs/mitre-coverage.md` | Technique-by-technique coverage table |
| `docs/testing.md` | Static + runtime testing guide |
| `docs/troubleshooting.md` | Common failure modes and fixes |
| `docs/validation-matrix.md` | What has/has not been validated |

## Roadmap

* Signed / WORM audit log shipping
* Real EDR/firewall/IdP response handlers with rollback
* Alert clustering / cross-case correlation
* Two-person approval for active-mode destructive actions
* Prometheus metrics endpoint
* Sigma-rule loader for detections
* Full end-to-end Caldera → OpenSearch → IRIS exercise

## Author

Sandeep Mothukuri. See `LICENSE` (MIT).
