# Limitations

Author: Sandeep Mothukuri

The research build is intentionally bounded. It is not a production
SOC. Limitations:

- **Simulated SOAR handlers.** Real EDR/firewall/IdP integrations are
  not included. Handlers return simulated state.
- **Local-only TI feed.** No MISP/OpenCTI/commercial TI integration
  ships by default; the default feed is a small deterministic list.
- **Mock AI provider.** The default AI client is a deterministic,
  evidence-grounded heuristic, not a real LLM. An interface point is
  provided for plugging real providers in.
- **In-memory + JSON-lines SIEM.** Not suitable for high-scale
  production telemetry volumes.
- **No multi-user approval UI.** Approvals are modeled as a callback
  interface; production deployments must wire in ITSM/Slack.
- **No signed audit log.** JSON-lines audit logs are append-only but
  not cryptographically sealed.
- **No encrypted credentials store.** Real integrations would need a
  secrets backend; the research build ships without one.
- **No clustering / deduplication.** At high event volumes the
  pipeline would benefit from cross-case correlation and alert
  clustering; this is planned.
- **No adversary emulation beyond scenarios.** The red-team scenarios
  generate telemetry events directly; they do not execute real
  attacker tooling.

These limitations are by design. The goal of this build is to
demonstrate and test a safe architecture, not to provide a drop-in
production SOC.
