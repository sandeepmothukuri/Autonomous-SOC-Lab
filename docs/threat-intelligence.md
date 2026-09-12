# Threat Intelligence

The lab ships with three intelligence layers:

1. **MISP** (local) — self-hosted MISP instance running in Docker. No
   default feeds are configured out of the box. Import feeds or add
   events manually through the MISP UI at http://localhost:8080.
2. **AbuseIPDB** (optional cloud) — used by the brute-force response
   workflow to check confidence scores. Only queried when
   `ABUSEIPDB_API_KEY` is set in `.env`.
3. **ipinfo** (optional cloud) — used for GeoIP/ASN enrichment of
   source IPs. Only queried when reachable and not blocked.

## Offline / graceful degradation

Every TI call in StackStorm workflows has a `failed()` branch:
unreachable services and missing API keys result in an
"unknown/zero-confidence" enrichment rather than a broken workflow.
IRIS cases are still created with whatever context is available.

## Adding a feed

To add an additional feed (e.g., a MISP warninglist pull, a custom
threat-intel flat file):

1. Add a new `core.http` task in the relevant workflow, OR
2. Extend Vector with a `get_enrichment_table_record` transform that
   reads a mounted CSV (recommended for static lists).

Keep deterministic list-matches authoritative over cloud lookups.

## MISP credentials

Defaults are set from `.env` (`MISP_ADMIN_EMAIL`,
`MISP_ADMIN_PASSWORD`). Log in at http://localhost:8080 after first
boot and change the passphrase if you expose MISP beyond localhost.
