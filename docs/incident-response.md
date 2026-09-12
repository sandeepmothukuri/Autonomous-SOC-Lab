# Incident Response Playbook

This document outlines how an analyst interacts with the lab stack
when an alert fires. It is deliberately concise and maps alert types
to concrete investigation steps.

## Triage loop

1. Acknowledge the StackStorm notification (or open IRIS directly at
   http://localhost:8000).
2. Open the linked case in DFIR-IRIS. The case description contains:
   * triggering detection rule
   * source / destination / host / user
   * severity
   * enrichment summary (country, org, abuse score — if available)
   * response mode and the action (simulated/approved/active) that was
     taken
3. Validate the signal in OpenSearch Dashboards. Use the `logs-*` index
   pattern and filter on `alert.rule` or `event.type`.
4. If the alert is a true positive, use Velociraptor to run the
   relevant VQL hunt (see `velociraptor/hunts/`):
   * `suspicious_powershell.yaml` for PowerShell alerts
   * `network_connections.yaml` for lateral movement
   * `persistence_runkeys.yaml` for follow-up
5. If the alert is a false positive, close the IRIS case as
   "False Positive" and note the reason. Consider adding the source to
   a Vector allowlist (see `docs/detection-engineering.md`).

## Playbooks

### Brute force (T1110.001)

1. Confirm the source IP is not a known vulnerability scanner.
2. In `approval`/`active` mode, approve or execute the block action.
3. Review IRIS for past cases involving the same source IP.
4. For successful logins following failures, check `auth.log` for
   post-compromise activity.

### Suspicious PowerShell (T1059.001)

1. Pull the full script block text from the case description.
2. Decode any `-EncodedCommand` payloads locally.
3. Correlate with parent process (Sysmon EventID 1) to determine
   delivery mechanism (Office macro, LOLBin, etc.).
4. Collect PowerShell console history via Velociraptor.

### Lateral movement (T1021)

1. Identify the source host; in `active` mode the host will already be
   isolated via Velociraptor.
2. Use Velociraptor `pstree` and `netstat` artifacts to enumerate
   active sessions.
3. Review authentication logs for the affected accounts.
4. Only un-isolate after confirming no additional persistence.

### Privilege escalation (T1548)

1. Capture the full sudoers line and process tree.
2. Verify whether the NOPASSWD entry is approved config management or
   a new persistence mechanism.
3. Audit `/etc/sudoers` and `/etc/sudoers.d/` for drift.
