# Testing

## Static tests (run on every commit by CI)

```bash
pytest -q
```

Covers:

* Python package tests (ai/policy/soar/pipeline from `src/soc`)
* YAML parsing for detections, SOAR, configs, Caldera
* Detection field contract (ECS-like fields only)
* StackStorm rule → action → workflow reference chain
* Docker Compose validity (when Docker is available)
* Vector TOML parsing and transform input/output wiring
* Offline mirror of VRL auth/sysmon normalization logic
* Secret scan (private keys, AWS keys, static Caldera API keys, weak
  defaults)
* MITRE technique id well-formedness
* Localhost bind defaults + simulation-mode default

## Shell lint

```bash
shellcheck scripts/*.sh
```

## Runtime validation

```bash
bash scripts/test-end-to-end.sh
```

This emits synthetic events and checks which services are reachable.
Services that are not running produce SKIP lines; there are no faked
PASS results.

## Synthetic event generation

```bash
python scripts/generate-events.py --scenario brute_force
python scripts/generate-events.py --scenario powershell
python scripts/generate-events.py --scenario lateral_movement
python scripts/generate-events.py --scenario privilege_escalation
python scripts/generate-events.py --scenario all
```

Events are appended to `data/sample_logs/` where Vector ingests them
(through the mounted `/var/log/soc` volume).

## Fixtures

`tests/fixtures/` contains synthetic JSON event samples for each
detection category. Fixtures are:

* **Synthetic only** — no real PII, no real malware, no real customer
  data.
* **Deterministic** — identical inputs every run.
* **Labeled** — each fixture declares the expected detection (or
  `null` for negative cases).

## Adding a new test

When you add a detection:

1. Add a positive fixture in `tests/fixtures/<name>.json`.
2. Add a negative fixture (benign look-alike) to confirm no false
   positive.
3. Extend `tests/test_detections.py`-style logic (ElastAlert config is
   static; we validate YAML fields and Vector normalization rather
   than running ES/EA in CI).
4. Add a VRL mirror check in `tests/vrl_check.py` asserting
   normalized ECS fields match detection rule expectations.
