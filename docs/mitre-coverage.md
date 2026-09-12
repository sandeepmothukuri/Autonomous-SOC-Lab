# MITRE ATT&CK Coverage

Only techniques actually implemented in Vector/ElastAlert detections are
listed. Coverage percentages are intentionally not reported — there is
no measurement framework in place yet.

| Detection | Technique | Sub-technique | Tactic | Data Source | Response |
|---|---|---|---|---|---|
| Brute Force Attack Detected | T1110 Brute Force | T1110.001 Password Guessing | credential-access | sshd auth logs | enrichment + simulated/approved block + IRIS case |
| Suspicious PowerShell Execution | T1059 Command & Scripting Interpreter | T1059.001 PowerShell | execution | Sysmon EventID 4104 (script block) | IRIS case, Velociraptor hunt (active) |
| Privilege Escalation Attempt | T1548 Abuse Elevation Control Mechanism | T1548.003 Sudo NOPASSWD | privilege-escalation, persistence | auth logs (sudo), process events (web-spawned shells) | IRIS case |
| Lateral Movement Detected | T1021 Remote Services | T1021.001 RDP, T1021.002 SMB, T1021.004 SSH | lateral-movement | Sysmon EventID 3, Zeek conn | simulated/approved host isolation + IRIS case |
| Vector rule: powershell_download_cradle | T1059 | T1059.001 | execution | Sysmon EventID 4104 | feeds `powershell.yaml` severity=high |
| Vector rule: powershell_executionpolicy_bypass | T1059 | T1059.001 | defense-evasion | Sysmon EventID 4104 | feeds `powershell.yaml` severity=high |

## Caldera exercises

Caldera adversary profiles and the detection they exercise:

| Exercise | Techniques | Expected Detection |
|---|---|---|
| EX-001 Detect Brute Force + Review | T1110.001 | `brute_force.yaml` + IRIS case |
| EX-002 PowerShell Encoded Command | T1059.001 | `powershell.yaml` + IRIS case |
| EX-003 Lateral Movement Telemetry | T1021 | `lateral_movement.yaml` + IRIS case |
