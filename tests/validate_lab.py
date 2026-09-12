#!/usr/bin/env python3
"""Static validation for the Autonomous SOC Lab repository.

These checks intentionally avoid starting the full stack. They validate the
contracts that can be checked offline: YAML syntax, required MITRE metadata,
webhook/action references, unsafe embedded credentials, and basic compose
invariants.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_yaml(path: Path):
    text = path.read_text(encoding="utf-8")
    return list(yaml.safe_load_all(text))


def assert_yaml_files() -> None:
    candidates = list((ROOT / "detections").glob("*.yaml"))
    candidates += list((ROOT / "soar").rglob("*.yaml"))
    candidates += list((ROOT / "configs").rglob("*.yaml"))
    candidates += list((ROOT / "configs").rglob("*.yml"))
    candidates += list((ROOT / "caldera").glob("*.yml"))
    for path in candidates:
        load_yaml(path)


def assert_detection_contracts() -> None:
    expected = {
        "brute_force.yaml": "T1110",
        "powershell.yaml": "T1059.001",
        "privilege_escalation.yaml": "T1548",
        "lateral_movement.yaml": "T1021",
    }
    for filename, technique in expected.items():
        path = ROOT / "detections" / filename
        text = path.read_text(encoding="utf-8")
        assert f"MITRE ATT&CK: {technique}" in text, f"{filename}: missing ATT&CK technique"
        assert "http_post_url:" in text, f"{filename}: missing StackStorm webhook"
        assert "http_post_static_payload:" in text, f"{filename}: missing static alert payload"


def assert_soar_references() -> None:
    rules = load_yaml(ROOT / "soar" / "rules" / "elastalert.yaml")
    assert len(rules) == 4, "Expected four StackStorm webhook rules"
    for rule in rules:
        action = rule["action"]["ref"]
        _, pack, action_name = action.split(".")
        assert pack == "soc_lab"
        action_path = ROOT / "soar" / "actions" / f"{action_name}.yaml"
        assert action_path.exists(), f"Missing StackStorm action definition: {action_path}"


def assert_no_static_caldera_keys() -> None:
    text = (ROOT / "caldera" / "red_team.yml").read_text(encoding="utf-8")
    assert not re.search(r"api_key_(red|blue):\s*(?!\$\{)[^\s]+", text), "Static CALDERA API key found"


def assert_compose_fails_closed() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    required = [
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD:?Set",
        "ST2_PASSWORD:?Set",
        "POSTGRES_PASSWORD:?Set",
        "IRIS_SECRET_KEY:?Set",
        "IRIS_SECURITY_PASSWORD_SALT:?Set",
        "IRIS_ADMIN_PASSWORD:?Set",
        "MYSQL_ROOT_PASSWORD:?Set",
        "MYSQL_PASSWORD:?Set",
        "VELOCIRAPTOR_ADMIN_PASSWORD:?Set",
        "127.0.0.1",
    ]
    for marker in required:
        assert marker in text, f"docker-compose.yml missing hardening marker: {marker}"


def assert_docs_match_layout() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for path in [
        "pipeline/vector.toml",
        "detections/brute_force.yaml",
        "detections/powershell.yaml",
        "detections/privilege_escalation.yaml",
        "detections/lateral_movement.yaml",
        "tests/validate_lab.py",
    ]:
        assert path in readme, f"README missing repository path: {path}"


def main() -> None:
    assert_yaml_files()
    assert_detection_contracts()
    assert_soar_references()
    assert_no_static_caldera_keys()
    assert_compose_fails_closed()
    assert_docs_match_layout()
    print("Autonomous SOC Lab validation: PASS")


if __name__ == "__main__":
    main()
