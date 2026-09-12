# Security Boundaries

Author: Sandeep Mothukuri

## Subsystem capabilities matrix

| Subsystem | Reads | Writes | Calls external services | Executes arbitrary code |
|-----------|-------|--------|--------------------------|--------------------------|
| Telemetry ingest | Events | Events (to case) | No | No |
| Detection engine | Events | Alerts, Evidence | No | No |
| Enrichment | Alerts | Evidence (TI, asset) | TI feeds (configurable) | No |
| Threat intel | IOC table | — | Optional upstream TI | No |
| AI client | Case copy | None (returns AIAnalysis) | LLM provider (configurable; default mock) | No |
| Policy engine | Case | PolicyDecision (on case) | No | No |
| SOAR executor | Case, PolicyDecision | ActionResult (on case) | EDR/firewall/IdP (only in REAL mode, only allowlisted actions) | No |
| DFIR collector | Case | Evidence (stubs) | DFIR agents (only in REAL mode, only collection actions) | No |
| SIEM store | Case | JSON-lines persistence | Optional upstream SIEM | No |
| Verifier | Case + actions | VerificationResult | Control-plane queries in REAL mode | No |
| Audit logger | AuditRecords | Append-only log | Optional WORM/SIEM shipping | No |

## Hard boundaries

1. **No shell.** `execute_shell` and `run_arbitrary_command` are on the
   deny list and have no registered handler. No code path in the
   platform shells out based on AI output.
2. **AI is sandboxed.** The AI client returns a Pydantic model; it has
   no access to the filesystem, network, or the case file beyond what
   is passed in.
3. **Real response is opt-in.** Default mode is simulated. Switching to
   real requires explicit config and is re-validated by health checks.
4. **Destructive actions require approval and are never autonomous.**
   `wipe_host`, `delete_file`, and similar actions are denied by
   default and cannot be added to the autonomous allowlist without
   failing health checks.
5. **Audit logs are append-only** in the research build. Production
   deployments should forward to tamper-evident storage.
6. **Deterministic controls are authoritative.** AI may annotate, but
   never override, detection or policy.
