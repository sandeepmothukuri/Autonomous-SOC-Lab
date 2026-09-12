# Validation Fixtures

This directory is reserved for deterministic, non-sensitive event samples used by offline tests.

Fixtures must contain synthetic data only. Do not place credentials, real customer telemetry, malware, proprietary logs, or personal data here.

Recommended fixture families:

- `failed_login.json` — repeated SSH/Windows failed-login events for T1110.
- `powershell.json` — synthetic PowerShell Script Block logging for T1059.001.
- `lateral_movement.json` — synthetic SMB/RDP/SSH connection telemetry for T1021.
- `privilege_escalation.json` — synthetic sudo/SUID/process-parent telemetry for T1548.

The validator intentionally checks configuration contracts rather than executing attack commands. Full-stack exercises should be run only inside an isolated lab network.
