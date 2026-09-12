<div align="center">

# 🛡️ Autonomous SOC Lab

### Enterprise-Style Detection • Investigation • Response • DFIR • Adversary Emulation

[![CI](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab/actions/workflows/validate.yml/badge.svg)](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab/actions)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![OpenSearch](https://img.shields.io/badge/SIEM-OpenSearch-005EB8?logo=opensearch&logoColor=white)](https://opensearch.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![StackStorm](https://img.shields.io/badge/SOAR-StackStorm-4B8BBE)](https://stackstorm.com/)

**A reproducible open-source SOC engineering platform for building, validating and demonstrating modern detection-and-response operations.**

[Architecture](#-architecture) · [Visual Showcase](#-visual-showcase) · [Detection Engineering](#-detection-engineering) · [SOAR](#-soar-response-automation) · [DFIR](#-dfir--investigation) · [Quick Start](#-quick-start) · [Testing](#-validation--quality) · [Author](#-author)

</div>

---

## 🎯 Project Overview

**Autonomous SOC Lab** combines SIEM, detection engineering, SOAR, threat intelligence, endpoint DFIR, case management and adversary emulation into a single Docker-based security operations environment.

The project is designed to demonstrate the engineering lifecycle behind a modern SOC:

```text
Telemetry
   ↓
Collection & Normalisation
   ↓
Detection Engineering
   ↓
Alert Enrichment
   ↓
Policy / Decision Gate
   ↓
Automated Response
   ↓
DFIR Investigation
   ↓
Case Management
   ↓
Detection Validation & Coverage Measurement
```

The platform is **safe-by-default**. Deterministic security controls remain authoritative, while enrichment or AI-assisted analysis can provide additional context without bypassing response policy.

> **Default response mode: `simulation`** — no containment action is performed unless the operator explicitly enables `approval` or `active` mode and configures the required response handlers.

---

## 🧩 What the Platform Demonstrates

| Capability | Implementation | Purpose |
|---|---|---|
| Log collection | Vector | Collection, parsing and normalisation |
| SIEM | OpenSearch | Search, storage and dashboards |
| Detection | ElastAlert2 | Deterministic rule-based detections |
| SOAR | StackStorm | Orchestration and response workflows |
| Case management | DFIR-IRIS | Incidents, evidence and timelines |
| Threat intelligence | MISP | IOC enrichment and correlation |
| Endpoint DFIR | Velociraptor | Live hunts and forensic collection |
| Adversary emulation | MITRE Caldera | Controlled TTP validation |
| Detection mapping | MITRE ATT&CK | Technique-level coverage |
| Deployment | Docker Compose | Reproducible local environment |
| Quality gates | GitHub Actions + pytest | Automated validation |

---

# 🏗️ Architecture

The architecture separates telemetry collection, deterministic detection, response orchestration, investigation and case management into clearly defined layers.

<div align="center">

<img src="architecture/diagram.svg" alt="Autonomous SOC Lab architecture" width="100%">

</div>

### End-to-End Data Flow

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                                │
│ Windows • Linux • Network • Cloud • Applications • Caldera         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Vector                                                            │
│ Collection → Parsing → Remap / Normalisation → OpenSearch          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ OpenSearch                                                        │
│ SIEM • Search • Dashboards • Alert Data                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ElastAlert2                                                       │
│ ATT&CK-mapped deterministic detections                             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Webhook
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ StackStorm                                                        │
│ Enrichment → Decision Gate → Response → IRIS Case                 │
└──────────────┬──────────────────────┬───────────────────────────────┘
               │                      │
               ▼                      ▼
       ┌──────────────┐       ┌─────────────────┐
       │    MISP      │       │  Velociraptor   │
       │ Threat Intel │       │    DFIR / EDR   │
       └──────┬───────┘       └────────┬────────┘
              │                        │
              └────────────┬───────────┘
                           ▼
                   ┌───────────────┐
                   │   DFIR-IRIS   │
                   │ Case / Evidence│
                   │ Timeline / IOC │
                   └───────────────┘

MITRE Caldera → Controlled Adversary Emulation → Detection Validation
```

---

# 📸 Visual Showcase

The repository includes visual assets for the major SOC components. The PNG files below are the primary visual assets used in this README; the corresponding SVG sources are also retained in `screenshots/` for editable/vector representations.

## SOC Operations Dashboard

<div align="center">

<img src="screenshots/01-soc-dashboard.png" alt="SOC operations dashboard" width="100%">

</div>

**Purpose:** operational view of security events, alert activity, detection status and SOC metrics.

---

## Alert Investigation

<div align="center">

<img src="screenshots/02-alert-panel.png" alt="SOC alert investigation panel" width="100%">

</div>

**Purpose:** investigate suspicious activity with alert context, timeline information and response options.

---

## SOAR Response Workflow

<div align="center">

<img src="screenshots/03-soar-workflow.png" alt="StackStorm SOAR workflow" width="100%">

</div>

**Workflow pattern:**

```text
Detection
   ↓
Alert Normalisation
   ↓
Threat Intelligence Enrichment
   ↓
Decision Gate
   ↓
Simulation / Approval / Active Response
   ↓
IRIS Case
   ↓
Analyst Investigation
```

---

## Incident Response & Case Management

<div align="center">

<img src="screenshots/04-incident-case.png" alt="DFIR-IRIS incident case" width="100%">

</div>

**Purpose:** centralise incident context, evidence, indicators and investigation timelines.

---

## Threat Intelligence

<div align="center">

<img src="screenshots/05-threat-intel.png" alt="MISP threat intelligence interface" width="100%">

</div>

**Purpose:** IOC enrichment, correlation and threat-intelligence context for investigations.

---

## Adversary Emulation

<div align="center">

<img src="screenshots/06-attack-simulation.png" alt="MITRE Caldera adversary emulation" width="100%">

</div>

**Purpose:** controlled adversary behaviour is used to exercise detections and measure coverage.

> **Visual evidence note:** these repository assets are presentation/visual representations of the lab interfaces. They should not be interpreted as evidence of a continuously running production deployment. Runtime validation is performed through the documented lab procedures and automated checks.

---

# 🔎 Detection Engineering

Detections are maintained as version-controlled ElastAlert2 rules and mapped to MITRE ATT&CK techniques.

### Current Detection Set

| Detection | ATT&CK | Detection Logic |
|---|---|---|
| Brute Force Attack | T1110.001 | Repeated failed authentication from a source |
| Suspicious PowerShell | T1059.001 | Encoded command / DownloadString / bypass indicators |
| Lateral Movement | T1021 | Repeated internal RDP / SMB / SSH / WinRM activity |
| Privilege Escalation | T1548.003 | Sudoers / NOPASSWD and suspicious service-to-shell activity |

Detection rules live under:

```text
detections/
├── brute_force.yaml
├── powershell.yaml
├── lateral_movement.yaml
└── privilege_escalation.yaml
```

### Detection Lifecycle

```text
Raw Event
   ↓
Vector Parsing / Normalisation
   ↓
OpenSearch
   ↓
ElastAlert2 Rule
   ↓
MITRE ATT&CK Mapping
   ↓
StackStorm Webhook
   ↓
SOAR Workflow
```

### Detection Engineering Principles

- Version-controlled detection logic
- ATT&CK technique mapping
- Explicit field contracts
- Deterministic alert generation
- False-positive tuning
- Automated validation
- Reproducible synthetic test events
- Detection-to-response traceability

See [`docs/detection-engineering.md`](docs/detection-engineering.md) for the rule contract and tuning guidance.

---

# ⚡ SOAR Response Automation

StackStorm provides the orchestration layer between detection and response.

A response workflow can perform enrichment, evaluate policy, execute a mode-dependent response and create an IRIS case.

```text
                     ┌──────────────┐
                     │ Detection    │
                     └──────┬───────┘
                            ↓
                     ┌──────────────┐
                     │ Enrichment   │
                     │ MISP / CTI   │
                     └──────┬───────┘
                            ↓
                     ┌──────────────┐
                     │ Decision Gate│
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ↓             ↓             ↓
        Simulation       Approval       Active
              │             │             │
         Log intent     Human gate    Explicit action
              │             │             │
              └─────────────┼─────────────┘
                            ↓
                     ┌──────────────┐
                     │   IRIS Case  │
                     └──────┬───────┘
                            ↓
                     Analyst Review
```

### Response Modes

| Mode | Behaviour |
|---|---|
| `simulation` | Records intended action and creates investigation context; no containment |
| `approval` | Prepares response and requires analyst approval |
| `active` | Executes configured containment handlers explicitly enabled by the operator |

This model is intended to keep automated response **auditable, policy-controlled and reversible where the connected control plane supports rollback**.

See [`docs/soar.md`](docs/soar.md).

---

# 🕵️ DFIR & Investigation

Velociraptor provides endpoint investigation and forensic collection capabilities, while DFIR-IRIS provides centralized incident management.

Example investigation areas include:

- suspicious PowerShell activity
- persistence mechanisms
- network connections
- process activity
- endpoint artefacts
- targeted VQL hunts
- host isolation workflows when explicitly enabled

Example flow:

```text
Alert
  ↓
StackStorm
  ↓
Velociraptor Hunt
  ↓
Collected Evidence
  ↓
IRIS Case
  ↓
Timeline / IOC / Analyst Notes
```

See [`docs/incident-response.md`](docs/incident-response.md).

---

# 🌐 Threat Intelligence

MISP provides the local threat-intelligence layer.

The platform supports optional enrichment through local and external intelligence sources. External providers can be disabled without preventing the core detection pipeline from operating.

```text
IOC
 ↓
MISP / External Enrichment
 ↓
Reputation / Context
 ↓
SOAR Decision Gate
 ↓
Case Context
```

See [`docs/threat-intelligence.md`](docs/threat-intelligence.md).

---

# 🧪 Adversary Emulation

MITRE Caldera is used to exercise controlled adversary behaviour against the detection pipeline.

The objective is to validate the complete security lifecycle rather than simply execute attack techniques:

```text
Adversary Technique
        ↓
Endpoint / Network Telemetry
        ↓
Detection
        ↓
Alert
        ↓
Enrichment
        ↓
Response
        ↓
Investigation
        ↓
ATT&CK Coverage Measurement
```

The default Caldera profile is designed to remain non-destructive. Destructive activities such as ransomware execution, log wiping and credential-dumping operations are deliberately excluded from the safe default profile.

---

# 🎯 MITRE ATT&CK Coverage

The lab maps detection scenarios to ATT&CK techniques to make detection coverage measurable.

| Tactic | Example Coverage |
|---|---|
| Initial Access | Phishing / user execution scenarios where configured |
| Execution | PowerShell and command/scripting interpreter activity |
| Persistence | Scheduled-task and persistence indicators |
| Privilege Escalation | SUID / exploit / sudo-related indicators |
| Defense Evasion | Log-clearing and evasion indicators |
| Credential Access | Brute-force and credential-access scenarios |
| Lateral Movement | SMB / WMI / remote-service activity |
| Exfiltration | Controlled network exfiltration scenarios |

Coverage is treated as an engineering measurement and should be expanded as additional detections and telemetry sources are added.

See [`docs/mitre-coverage.md`](docs/mitre-coverage.md).

---

# 🧠 Automation & AI Trust Model

The platform separates **security decision authority** from optional enrichment or AI-assisted analysis.

```text
Deterministic Security Controls
        │
        ├── Detection
        ├── Policy
        ├── Validation
        └── Response Safety
        │
        ▼
Optional Intelligence / AI Assistance
        │
        ▼
Evidence-Grounded Analyst Context
```

The design goal is to keep automated reasoning:

- evidence-grounded
- auditable
- policy-constrained
- deterministic at the response boundary
- safe to disable without breaking core detection

The default Docker deployment does not require an external LLM to operate.

---

# 🔐 Security Model

Security controls are designed for a safe local research environment.

### Default safeguards

- `SOC_RESPONSE_MODE=simulation`
- Management interfaces bind to `127.0.0.1` by default
- Credentials are supplied through environment configuration
- `.env` is excluded from version control
- `.env.example` uses generated-secret placeholders
- Static Caldera API keys are rejected by validation
- Secret-pattern scanning is included in CI
- Safe Caldera content is non-destructive
- Active containment requires explicit configuration

### Important lab limitation

OpenSearch security is intentionally simplified in the default isolated lab deployment. Production deployments should enable authentication, TLS, network segmentation, secrets management and the appropriate security plugins before exposing any service beyond the trusted lab environment.

See [`docs/security.md`](docs/security.md).

---

# 🚀 Quick Start

## Prerequisites

Recommended host:

- Docker Engine
- Docker Compose v2
- Linux or WSL2
- 16 GB RAM recommended
- 50 GB available storage

## 1. Clone the repository

```bash
git clone https://github.com/sandeepmothukuri/Autonomous-SOC-Lab.git
cd Autonomous-SOC-Lab
```

## 2. Configure secrets

```bash
cp .env.example .env
```

Replace every `<GENERATE_*>` placeholder with a strong random value.

Generate a secret with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## 3. Start the stack

```bash
docker compose pull
docker compose up -d
```

## 4. Register StackStorm content

```bash
bash scripts/setup-stackstorm.sh
```

## 5. Generate test telemetry

```bash
python scripts/generate-events.py --scenario all
```

Available scenarios:

```text
brute_force
powershell
lateral_movement
privilege_escalation
all
```

## 6. Validate the deployment

```bash
bash scripts/health-check.sh
bash scripts/test-end-to-end.sh
pytest -q
python tests/validate_lab.py
```

---

# 🧪 Lab Exercises

### Exercise 1 — Brute Force Detection

```bash
python scripts/generate-events.py --scenario brute_force
```

Expected path:

```text
Synthetic Authentication Events
        ↓
Vector
        ↓
OpenSearch
        ↓
Brute Force Detection
        ↓
StackStorm
        ↓
IRIS Case
```

### Exercise 2 — Suspicious PowerShell

```bash
python scripts/generate-events.py --scenario powershell
```

Expected path:

```text
PowerShell Telemetry
        ↓
T1059.001 Detection
        ↓
SOAR
        ↓
Velociraptor Investigation
        ↓
IRIS Case
```

### Exercise 3 — Lateral Movement

```bash
python scripts/generate-events.py --scenario lateral_movement
```

Expected path:

```text
Remote Service Activity
        ↓
T1021 Detection
        ↓
StackStorm
        ↓
Investigation / Case Creation
```

### Exercise 4 — Full Pipeline

```bash
python scripts/generate-events.py --scenario all
bash scripts/test-end-to-end.sh
```

This exercises the complete detection-to-case workflow using controlled synthetic telemetry.

---

# 🧰 Technology Stack

| Layer | Technology | Role |
|---|---|---|
| Collection | Vector | Log collection and normalisation |
| SIEM | OpenSearch | Event storage, search and dashboards |
| Detection | ElastAlert2 | Rule-based detection |
| SOAR | StackStorm | Orchestration and response |
| Case Management | DFIR-IRIS | Incident lifecycle and evidence |
| Threat Intelligence | MISP | IOC intelligence and enrichment |
| Endpoint DFIR | Velociraptor | Endpoint hunts and evidence collection |
| Adversary Emulation | MITRE Caldera | Controlled TTP execution |
| Framework | MITRE ATT&CK | Detection coverage mapping |
| Runtime | Docker Compose | Reproducible service deployment |
| Testing | pytest / ShellCheck / yamllint | Quality validation |
| CI/CD | GitHub Actions | Automated repository quality gates |

---

# ✅ Validation & Quality

The repository contains automated checks for:

- YAML syntax
- detection metadata and ATT&CK mappings
- StackStorm rule/action references
- workflow references
- Docker Compose safety invariants
- environment configuration
- hardcoded credential patterns
- static Caldera API keys
- repository structure
- Python tests
- shell scripts
- YAML linting
- secret scanning

CI runs these checks automatically on pushes and pull requests.

```text
Commit
  ↓
GitHub Actions
  ├── ShellCheck
  ├── Python Tests
  ├── YAML Lint
  ├── Compose Validation
  ├── Detection / SOAR Validation
  ├── Structure Validation
  └── Secret Scan
        ↓
    PASS / FAIL
```

See [`docs/testing.md`](docs/testing.md) and [`docs/validation-matrix.md`](docs/validation-matrix.md).

---

# 📊 SOC Engineering Metrics

A core objective of the project is to move beyond tool integration and measure operational outcomes.

Future and extensible metrics include:

| Metric | Objective |
|---|---|
| MTTD | Mean time to detect |
| MTTR | Mean time to respond |
| Detection coverage | ATT&CK technique coverage |
| False-positive rate | Detection quality |
| Automation rate | Analyst workload reduction |
| Containment success | Response effectiveness |
| Investigation time | DFIR efficiency |
| Alert reduction | Noise reduction |
| Analyst hours saved | Operational impact |

---

# 📁 Repository Structure

```text
Autonomous-SOC-Lab/
│
├── architecture/
│   └── diagram.svg
│
├── caldera/
│   └── red_team.yml
│
├── configs/
│   ├── opensearch/
│   ├── elastalert/
│   └── ...
│
├── detections/
│   ├── brute_force.yaml
│   ├── powershell.yaml
│   ├── privilege_escalation.yaml
│   └── lateral_movement.yaml
│
├── pipeline/
│   └── vector.toml
│
├── screenshots/
│   ├── 01-soc-dashboard.png
│   ├── 02-alert-panel.png
│   ├── 03-soar-workflow.png
│   ├── 04-incident-case.png
│   ├── 05-threat-intel.png
│   ├── 06-attack-simulation.png
│   └── *.svg
│
├── scripts/
│   ├── health-check.sh
│   ├── generate-events.py
│   ├── setup-stackstorm.sh
│   └── test-end-to-end.sh
│
├── soar/
│   ├── rules/
│   └── actions/
│
├── tests/
│   ├── fixtures/
│   └── validate_lab.py
│
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── security.md
│   ├── detection-engineering.md
│   ├── soar.md
│   ├── threat-intelligence.md
│   ├── incident-response.md
│   ├── mitre-coverage.md
│   ├── testing.md
│   ├── troubleshooting.md
│   └── validation-matrix.md
│
├── docker-compose.yml
├── .env.example
├── LICENSE
└── README.md
```

---

# ⚠️ Scope & Limitations

This repository is an **SOC engineering, automation and research lab**, not a drop-in production SOC deployment.

Important limitations:

- The default response mode is simulation.
- Production EDR, firewall and identity-provider integrations require configuration.
- Velociraptor endpoint agents must be deployed separately.
- External threat-intelligence services are optional.
- The default Docker stack does not require an external LLM.
- The default OpenSearch security configuration is intended for an isolated lab.
- Runtime performance and availability depend on the host Docker environment.

These limitations are documented intentionally so the project remains reproducible and technically honest.

---

# 🛣️ Roadmap

### Detection Engineering

- [ ] Expand ATT&CK coverage
- [ ] Sigma rule ingestion
- [ ] Detection regression testing
- [ ] Detection quality scoring
- [ ] Cross-event correlation

### Autonomous Operations

- [ ] Evidence-grounded LLM triage
- [ ] Alert clustering
- [ ] Investigation planning
- [ ] Risk-based decisioning
- [ ] Two-person approval for high-impact actions
- [ ] Automated rollback verification

### Enterprise Integrations

- [ ] Microsoft Defender
- [ ] CrowdStrike
- [ ] Microsoft Sentinel
- [ ] Splunk
- [ ] AWS
- [ ] Azure
- [ ] Identity providers
- [ ] Network firewalls

### Observability

- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] MTTD / MTTR reporting
- [ ] Automation effectiveness metrics
- [ ] ATT&CK coverage reporting

---

# 🎯 Engineering Objective

The long-term objective is to demonstrate the evolution from a conventional alert-driven SOC toward a **policy-governed, evidence-driven autonomous SOC** without sacrificing security controls or analyst oversight.

```text
Alert-Driven SOC
       ↓
Automated SOC
       ↓
Evidence-Driven SOC
       ↓
Policy-Governed Autonomous SOC
```

The engineering priorities are:

**Detection quality → Evidence → Automation → Safety → Measurement → Continuous improvement**

---

# 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:

- Security Operations
- Detection Engineering
- Threat Hunting
- Incident Response
- SIEM / XDR
- SOAR
- DFIR
- MITRE ATT&CK
- Security Automation
- AI-Augmented SOC Operations

This repository is maintained as a practical security engineering environment for designing, testing and validating modern SOC capabilities.

- GitHub: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- Website: [cybertechnology.in](https://cybertechnology.in)
- LinkedIn: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- Email: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository | Description |
|---|---|
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for automated triage |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response |
| [cyberblue](https://github.com/sandeepmothukuri/cyberblue) | Containerised blue-team platform — SIEM, DFIR, CTI, SOAR, Network Analysis |

---

# 📄 License

MIT License. See [`LICENSE`](LICENSE).

---

<div align="center">

**Built as a practical SOC engineering platform — not a collection of disconnected tool installations.**

</div>
