# Repository Audit — Autonomous SOC Lab

Audited: 2026-09-12
Scope: every .py/.sh/.yml/.yaml/.toml/.md in the repository.

This document records the initial audit of the upstream snapshot and the
fixes applied during this iteration. All items listed have been
addressed in the current tree.

## Initial findings (all fixed)

1. OpenSearch security plugin contradiction (compose env vs
   plugins.security.disabled) — fixed by disabling plugin consistently
   and removing basic-auth from Vector/ElastAlert clients.
2. Vector VRL wrote inconsistent ECS field names that detections didn't
   use; transforms not wired correctly — rewrote pipeline to normalize
   to a documented ECS-like contract; critical sink now receives only
   events tagged with `event.severity = critical` or `alert.rule`.
3. Vector ES sink used wrong env var for password; removed since auth
   is disabled.
4. ElastAlert2 password literal and mismatched auth — removed.
5. OpenSearch healthcheck used `curl` (not in image) — replaced with
   `wget`-based check. Added healthchecks for Dashboards, Vector, IRIS,
   Postgres, MySQL, Redis, MISP, Velociraptor, Caldera.
6. StackStorm pack requires `st2ctl reload` and webhook registration —
   provided `scripts/setup-stackstorm.sh`.
7. IRIS webapp needs `iris-worker`; added worker container and
   persistent Postgres volume. Corrected case-id extraction paths.
8. MISP image path incorrect + Redis missing — replaced with
   `coolacid/misp-docker:core-latest`, added Redis container and
   volumes.
9. Velociraptor had no server.config.yaml — added a sane default.
10. Caldera config mounted at ignored path + empty keys leave default
    "admin" credentials — restructured env config and documented.
11. Missing iris-db/misp-data/redis volumes — added.
12. .env.example `change_me_*` values were weak — replaced with
    `<GENERATE_*>` enforced placeholders and added setup script.
13. Detections referenced un-normalized fields (`target.host`,
    `destination.ip` not produced by Vector) — rewrote detection rules
    to match the ECS field contract.
14. Missing structured MITRE metadata on detections — added
    mitre_tactic/technique/subtechnique static payloads.
15. SOAR workflows called external HTTP without timeout/offline
    fallback; used hardcoded country blocklist; ignored
    SOC_RESPONSE_MODE — rewrote all four workflows with explicit mode
    gating, timeouts, and failure paths.
16. core.http JSON result parsing bug — used with timeouts; failure
    paths fall back to `not-created` case ids.
17. SOAR pack.yaml had generic author — replaced with generic keyword
    descriptor (no fictitious contributors).
18. Brute-force threshold/logic used geopolitical country blocklist —
    replaced with abuse-score + alert-count logic.
19. Tests were minimal (only static string check) — expanded to 70+
    pytest tests covering YAML parsing, ECS field contract, SOAR
    references, workflow-inputs, VRL mirroring, secrets, localhost
    binds, response-mode default, MITRE tid well-formedness, docker
    compose validity (when docker available), plus the Python
    research framework tests.
20. Missing JSON fixtures — added 6 fixtures (4 positives + 2 benign
    negatives) under tests/fixtures/.
21. CI workflow had several gaps — expanded to run pytest, shellcheck,
    yamllint, docker compose config, secret scan, and structure check.
22. Scripts: health-check.sh only checked files + compose — rewrote to
    PASS/WARN/FAIL per service reachability; added test-end-to-end.sh
    and generate-events.py.
23. Docs were placeholder/README-only — added complete set:
    architecture, deployment, security, detection-engineering, soar,
    threat-intelligence, incident-response, mitre-coverage, testing,
    troubleshooting, validation-matrix.
24. README claimed functionality without distinguishing simulation vs
    real — rewrote to clearly label mockups, list validated vs
    unvalidated, and avoid marketing language.
25. Validation matrix was missing — added docs/validation-matrix.md.
26. Velociraptor VQL hunts were missing — added three safe sample
    hunts.
27. Bind addresses defaulted to 0.0.0.0 on some services — forced all
    services to 127.0.0.1 by default.
28. Response mode defaulted to implicit/active — explicitly defaulted
    to `simulation` in env, compose, and workflows.

## Validation status

- `pytest -q`: 70 passed, 1 skipped (docker unavailable in sandbox)
- `python tests/validate_lab.py`: PASS
- `yamllint` on detections/soar/configs/caldera/pipeline/.github: CLEAN
- `bash -n scripts/*.sh`: all scripts syntactically valid
- Runtime (docker compose up): not executed in this sandbox (no Docker
  daemon available). Validated statically; end-to-end runtime script
  provided at `scripts/test-end-to-end.sh` for Docker-enabled hosts.
