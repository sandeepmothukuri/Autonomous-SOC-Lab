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

The project is designed to demonstrate the engineering lifecycle behind a modern SOC.

---

# 🏗️ Architecture
### End-to-End Data Flow

<div align="center">

<img src="architecture/diagram.svg" alt="Autonomous SOC Lab architecture" width="100%">

</div>

**Flow:** Telemetry → Collection & Normalisation → SIEM → Detection → SOAR → Enrichment / Decision → Response → DFIR → Validation.

---

# 📸 Visual Showcase

The repository includes visual assets for the major SOC components.

## SOC Operations Dashboard

<img src="screenshots/01-soc-dashboard.png" alt="SOC operations dashboard" width="100%">

## Alert Investigation

<img src="screenshots/02-alert-panel.png" alt="SOC alert investigation panel" width="100%">

## SOAR Response Workflow

<img src="screenshots/03-soar-workflow.png" alt="StackStorm SOAR workflow" width="100%">

## Incident Response & Case Management

<img src="screenshots/04-incident-case.png" alt="DFIR-IRIS incident case" width="100%">

## Threat Intelligence

<img src="screenshots/05-threat-intel.png" alt="MISP threat intelligence interface" width="100%">

## Adversary Emulation

<img src="screenshots/06-attack-simulation.png" alt="MITRE Caldera adversary emulation" width="100%">

---

# 🔎 Detection Engineering

Detections are maintained as version-controlled ElastAlert2 rules and mapped to MITRE ATT&CK techniques.

| Detection | ATT&CK | Detection Logic |
|---|---|---|
| Brute Force Attack | T1110.001 | Repeated failed authentication from a source |
| Suspicious PowerShell | T1059.001 | Encoded command / DownloadString / bypass indicators |
| Lateral Movement | T1021 | Repeated internal RDP / SMB / SSH / WinRM activity |
| Privilege Escalation | T1548.003 | Sudoers / NOPASSWD and suspicious service-to-shell activity |

---

# ⚡ SOAR Response Automation

StackStorm provides the orchestration layer between detection and response.

Response modes are `simulation`, `approval`, and `active`, with active containment requiring explicit operator configuration.

---

# 🕵️ DFIR & Investigation

Velociraptor provides endpoint investigation and forensic collection capabilities, while DFIR-IRIS provides centralized incident management.

---

# 🌐 Threat Intelligence

MISP provides the local threat-intelligence layer for IOC enrichment and correlation.

---

# 🧪 Adversary Emulation

MITRE Caldera is used to exercise controlled adversary behaviour against the detection pipeline.

---

# 🎯 MITRE ATT&CK Coverage

The lab maps detection scenarios to ATT&CK techniques to make detection coverage measurable.

---

# 🧠 Automation & AI Trust Model

The platform separates security decision authority from optional enrichment or AI-assisted analysis. Deterministic security controls remain authoritative at the response boundary.

---

# 🔐 Security Model

Security controls are designed for a safe local research environment. The default response mode is simulation, credentials are supplied through environment configuration, secrets are excluded from version control, and active containment requires explicit configuration.

---

# 🚀 Quick Start

```bash
git clone https://github.com/sandeepmothukuri/Autonomous-SOC-Lab.git
cd Autonomous-SOC-Lab
cp .env.example .env
docker compose up -d
bash scripts/setup-stackstorm.sh
python scripts/generate-events.py --scenario all
pytest -q
```

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

---

# ✅ Validation & Quality

The repository contains automated checks for YAML syntax, detection metadata, ATT&CK mappings, SOAR references, Docker Compose safety invariants, environment configuration, credential patterns, repository structure, Python tests, shell scripts, YAML linting and secret scanning.

---

# 📊 SOC Engineering Metrics

Future and extensible metrics include MTTD, MTTR, ATT&CK coverage, false-positive rate, automation rate, containment success, investigation time, alert reduction and analyst hours saved.

---

# ⚠️ Scope & Limitations

This repository is an SOC engineering, automation and research lab, not a drop-in production SOC deployment. Production EDR, firewall, identity-provider and cloud integrations require separate configuration.

---

# 🎯 Engineering Objective

The long-term objective is to demonstrate the evolution from a conventional alert-driven SOC toward a policy-governed, evidence-driven autonomous SOC without sacrificing security controls or analyst oversight.

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
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage |

---

# 📄 License

MIT License. See [`LICENSE`](LICENSE).
