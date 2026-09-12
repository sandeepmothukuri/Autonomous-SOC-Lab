# Detection Engineering

All detections live under `detections/` as ElastAlert2 YAML rules. They
operate on Vector-normalized fields (see Field contract below). New
rules should be added as `.yaml` files in that directory; ElastAlert2
hot-reloads them at the configured `run_every` interval.

## Field contract (ECS-like)

Vector emits a single, consistent schema. Every rule field referenced in
this directory must be one of:

| Field | Type | Description |
|---|---|---|
| `@timestamp` | datetime | Ingest timestamp |
| `event.kind` | keyword | `event` / `alert` / `enrichment` |
| `event.category` | keyword | `authentication` / `process` / `network` / `file` |
| `event.type` | keyword | e.g. `failed_login`, `powershell_execution`, `connection` |
| `event.action` | keyword | e.g. `ssh_login_failed`, `powershell_encoded`, `sudo_nopasswd_suspected` |
| `event.severity` | keyword | `info` / `low` / `medium` / `high` / `critical` |
| `source.ip` | ip | Originating address |
| `source.port` | integer | Originating port |
| `destination.ip` | ip | Target address |
| `destination.port` | integer | Target port |
| `host.name` | keyword | Target hostname |
| `user.name` | keyword | Account involved |
| `process.name` | keyword | Short process name |
| `process.command_line` | text | Full command line / script block |
| `process.parent.name` | keyword | Parent process name |
| `network.direction` | keyword | `internal` / `external` / `unknown` |
| `alert.rule` | keyword | Name of Vector flag that elevated severity |
| `mitre.technique` | keyword | ATT&CK technique id set by Vector |
| `mitre.tactic` | keyword | ATT&CK tactic id set by Vector |

Windows-specific fields (from Sysmon EventIDs):
`winlog.event_id`, `winlog.event_data.*`. These are normalized into the
ECS-like fields above by Vector so detections should prefer the ECS
fields.

## Existing detections

| File | Rule | Type | Threshold | MITRE |
|---|---|---|---|---|
| `brute_force.yaml` | Brute Force Attack Detected | frequency | 5 failed_login in 2m per source.ip | T1110.001 |
| `powershell.yaml` | Suspicious PowerShell Execution | any | EncodedCommand/DownloadString/Bypass + EventID 4104 | T1059.001 |
| `lateral_movement.yaml` | Lateral Movement Detected | frequency | 3 internal connections on ports 445/3389/22/135/5985/5986 in 5m per source.ip | T1021 |
| `privilege_escalation.yaml` | Privilege Escalation Attempt | any | `sudo NOPASSWD` or web-server spawning shell | T1548.003 |

## Adding a new detection

1. Add the detection logic in Vector VRL first, assigning
   `event.severity` and (where applicable) `alert.rule` and `mitre.*`.
2. Add an ElastAlert2 YAML file in `detections/` referencing only the
   normalized fields.
3. Add a StackStorm rule in `soar/rules/elastalert.yaml` (or a new rule
   file) mapping the alert name to an action.
4. Add an action + Orquesta workflow under `soar/actions/`.
5. Add a synthetic event fixture in `tests/fixtures/`.
6. Add an entry to `docs/mitre-coverage.md`.

## False-positive tuning

Each detection has a "False-positive considerations" comment block at
the top. In production:

* For brute force: add internal scanner IPs to a Vector allowlist
  transform before the `finalize` step.
* For PowerShell: pair encoded-command hits with parent-process checks
  (e.g., `process.parent.name` values like `word.exe`, `excel.exe`,
  `outlook.exe`) to reduce admin-script noise.
* For lateral movement: allowlist jump hosts, patch-management, and
  backup servers via a CIDR list in Vector.
* For privilege escalation: exclude approved config-management service
  accounts.
