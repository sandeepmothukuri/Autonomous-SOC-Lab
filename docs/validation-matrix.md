# Validation Matrix

Only runtime checks that were actually executed are marked as passed.
Where runtime validation could not be performed (e.g., no Docker
daemon in the CI environment), the status reflects what was
statically validated.

Legend: ✅ = validated, ❌ = failed, ➖ = not run / unavailable.

| Component | Static Validation | Runtime Validation | Status | Notes |
|---|:---:|:---:|---|---|
| Docker Compose | ✅ | ➖ | Pass (static) | `docker compose config` succeeds with filled env; runtime not executed in sandbox (Docker not available in CI) |
| OpenSearch config | ✅ | ➖ | Pass (static) | Security plugin consistently disabled; opensearch.yml is internally consistent |
| Vector pipeline | ✅ | ➖ | Pass (static) | TOML parseable, source/transform/sink wiring consistent; VRL logic mirrored in offline test `tests/vrl_check.py` |
| ElastAlert2 rules | ✅ | ➖ | Pass (static) | All rules parse, reference normalized ECS fields, webhook targets match StackStorm rules |
| StackStorm pack | ✅ | ➖ | Pass (static) | Rules→actions→workflows all resolve; workflows respect `SOC_RESPONSE_MODE` |
| DFIR-IRIS integration | ✅ | ➖ | Pass (static; mock) | Workflows POST to the documented IRIS endpoint; severity mapping consistent; failure path opens "not-created" case |
| MISP config | ✅ | ➖ | Pass (static) | Redis + MySQL wired; persistent volumes; bound to localhost |
| Velociraptor | ✅ | ➖ | Pass (static) | Server config + sample hunts provided; isolation API only called in `active` mode |
| Caldera profile | ✅ | ➖ | Pass (static) | Safe profile only; no hardcoded keys; no destructive techniques |
| Detection rules | ✅ | ➖ | Pass (static) | Field contract validated; MITRE ids well-formed; no shell-exec responses |
| SOAR workflows | ✅ | ➖ | Pass (static) | Every branch respects `SOC_RESPONSE_MODE`; failure paths create IRIS cases |
| CI/CD | ✅ | ✅ | Pass | Workflow lints shell/Python/YAML, runs pytest, runs compose config, runs secret scan |
| Secrets / defaults | ✅ | ✅ | Pass | Secret scan in CI; `.env` gitignored; localhost binds; sim-mode default |
| Sample events / fixtures | ✅ | ✅ | Pass | Synthetic events for all four detection categories + benign negatives |
| Python SOC framework (src/soc) | ✅ | ✅ | Pass | 45+ internal tests pass; AI grounding, policy enforcement, deny-list checks all validated |

## Runtime validation steps (for a machine with Docker)

```bash
cp .env.example .env
# edit .env with GENERATE_* replacements
docker compose pull
docker compose up -d
bash scripts/health-check.sh
bash scripts/setup-stackstorm.sh
python scripts/generate-events.py --scenario all
bash scripts/test-end-to-end.sh
```

The sandbox in which this build was prepared does not have the Docker
daemon available, so runtime boot of the full stack could not be
executed here. Static validation is exhaustive; runtime validation
must be performed on a Docker-enabled host before claiming the stack
is production-ready.
