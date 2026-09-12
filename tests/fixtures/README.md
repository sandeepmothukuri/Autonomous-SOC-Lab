# Validation Fixtures

Deterministic, non-sensitive event samples used by the test suite.

**Fixtures contain synthetic data only.** They do not contain real
customer telemetry, personal data, credentials, or malware samples.

| Fixture | Detection expected | Severity |
|---|---|---|
| `brute_force.json` | Brute Force Attack Detected | high |
| `powershell.json` | Suspicious PowerShell Execution | critical |
| `lateral_movement.json` | Lateral Movement Detected | high |
| `privilege_escalation.json` | Privilege Escalation Attempt | high |
| `normal_powershell.json` | _(none — FP control)_ | – |
| `normal_authentication.json` | _(none — FP control)_ | – |

Each fixture declares:

* `description`
* `source` — which Vector source it would come from
* `expected_detection` — alert name (or `null`)
* `expected_severity`
* `events` — list of event dicts

Use `python scripts/generate-events.py --scenario <name>` to append
events into `data/sample_logs/` where Vector ingests them during a
running deployment.
