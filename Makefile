# Autonomous-SOC-Lab — convenience targets
# Author: Sandeep Mothukuri

.PHONY: install health test sim sim-json clean

install:
	pip install -e .[dev]

health:
	python scripts/healthcheck.py

test:
	pytest -q

sim:
	python scripts/run_simulation.py

sim-json:
	python scripts/run_simulation.py --json

clean:
	rm -rf data/*.log data/*.jsonl .pytest_cache src/soc.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
