# Security Model

Autonomous SOC Lab is a **laboratory**. It is designed to be safe by
default, not airtight for production deployment. This document lists
the guarantees that hold in the default configuration and the steps
required before any real response is enabled.

## Default guarantees

1. **Simulated response.** `SOC_RESPONSE_MODE=simulation` by default.
   Workflows log intended actions; they do not call firewall, EDR, or
   IdP APIs.
2. **No exposed admin interfaces.** Every service binds to
   `127.0.0.1` by default. To expose a service you must explicitly
   change the `*_BIND_ADDRESS` in `.env`.
3. **No hardcoded credentials.** All passwords are read from `.env`.
   `.env.example` contains only `<GENERATE_*>` placeholders. `.env` is
   in `.gitignore`.
4. **OpenSearch security plugin disabled in the lab build.** This means
   there is **no authentication** on OpenSearch or Dashboards. Only
   run this stack on an isolated lab host.
5. **No destructive Caldera actions.** The default adversary profile
   (`caldera/red_team.yml`) uses discovery/read-only commands and
   explicitly excludes ransomware, log clearing, and LSASS dumping.
6. **Velociraptor isolation API is not invoked in simulation.**
   Workflows fall through to the simulated path unless
   `SOC_RESPONSE_MODE=active` and a valid `velociraptor_token` is set.
7. **External enrichment gracefully degrades.** Missing API keys for
   AbuseIPDB/ipinfo never break a workflow; they just produce
   "unknown" enrichment.
8. **Critical-index routing is deterministic.** Only events Vector has
   explicitly tagged with `event.severity = critical` or `alert.rule`
   flow to the `alerts-critical-*` index. The sink is not a copy of
   everything.

## Hardening for production-style deployments

The default lab settings are intentionally relaxed (no TLS, no auth on
OpenSearch). Before exposing the stack beyond localhost:

1. Re-enable the OpenSearch security plugin and provision TLS
   certificates.
2. Enable authentication on Dashboards, StackStorm, IRIS, MISP, and
   Velociraptor.
3. Move `SOC_RESPONSE_MODE` to `approval` and add an approval webhook
   to IRIS before considering `active`.
4. Run behind a reverse proxy with SSO.
5. Replace the `opensearch-data`, `postgres-data`, and `misp-*` volumes
   with encrypted block storage.
6. Restrict the Docker daemon to trusted images; pin image digests in
   `docker-compose.yml`.
7. Forward append-only audit logs to a SIEM outside the lab.

## Secret scanning

CI runs a grep-based secret scanner that fails the build if it finds
AWS keys, private keys, static Caldera API keys, or obvious weak
password defaults outside `.env.example`.
