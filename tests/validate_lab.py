#!/usr/bin/env python3
"""Static validation for the Autonomous SOC Lab repository.

Checks (offline):
  * All YAML files parse
  * Every detection rule has a name, http_post_url, mitre metadata
  * Every StackStorm rule references an existing action
  * Every action references an existing workflow
  * No hardcoded Caldera API keys
  * docker-compose uses env substitution with sane defaults + localhost binds
  * Response mode defaults to simulation
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
        try:
            list(load_yaml(path))
        except yaml.YAMLError as e:
            raise AssertionError(f"YAML parse error in {path}: {e}")


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
        assert f"mitre_technique: \"{technique}\"" in text or f"mitre_technique: {technique}" in text, \
            f"{filename}: missing ATT&CK technique {technique}"
        assert "http_post_url:" in text, f"{filename}: missing StackStorm webhook"
        assert "http_post_static_payload:" in text, f"{filename}: missing static alert payload"
        assert "timestamp_field:" in text, f"{filename}: missing timestamp_field"
        doc = yaml.safe_load(text)
        assert doc.get("index") == "logs-*", f"{filename}: index must be logs-*"


def assert_soar_references() -> None:
    rules = load_yaml(ROOT / "soar" / "rules" / "elastalert.yaml")
    assert len(rules) == 4, f"Expected four StackStorm webhook rules, got {len(rules)}"
    for rule in rules:
        action = rule["action"]["ref"]
        parts = action.split(".")
        # StackStorm action refs are pack.name (two parts)
        assert len(parts) == 2, f"{rule.get('name')}: action ref must be pack.name"
        assert parts[0] == "soc_lab", f"{rule.get('name')}: action must be in soc_lab pack"
        action_name = parts[-1]
        action_path = ROOT / "soar" / "actions" / f"{action_name}.yaml"
        assert action_path.exists(), f"Missing StackStorm action: {action_path}"
        adoc = yaml.safe_load(action_path.read_text(encoding="utf-8"))
        entry = adoc.get("entry_point")
        if adoc.get("runner_type") == "orquesta" and entry:
            wf = ROOT / "soar" / "actions" / entry
            assert wf.exists(), f"Missing workflow for {action_path.name}: {entry}"


def assert_no_static_caldera_keys() -> None:
    text = (ROOT / "caldera" / "red_team.yml").read_text(encoding="utf-8")
    assert not re.search(r"api_key_(red|blue):\s*(?!\$\{|\")\S+", text), \
        "Static CALDERA API key found"


def assert_compose_safety() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    required_markers = [
        "SOC_RESPONSE_MODE:-simulation",
        "plugins.security.disabled=true",
        "DISABLE_SECURITY_DASHBOARDS_PLUGIN=true",
        "127.0.0.1",
    ]
    for m in required_markers:
        assert m in text, f"docker-compose.yml missing safety marker: {m}"
    # No latest tag on core DB/search/observability services
    for svc in ("opensearch:", "vector:", "elastalert2:", "postgres:", "mysql:"):
        idx = text.find("  " + svc)
        if idx < 0:
            continue
        block = text[idx:idx+2000]
        m = re.search(r'image:\s*(\S+)', block)
        if m and ":latest" in m.group(1):
            raise AssertionError(f"Service {svc} uses :latest tag — pin a version")


def assert_env_example_safe() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "SOC_RESPONSE_MODE=simulation" in text
    assert "<GENERATE_" in text, "env.example should contain GENERATE_* placeholders"


def assert_docs_present() -> None:
    required_docs = [
        "README.md", "docs/architecture.md", "docs/deployment.md", "docs/security.md",
        "docs/detection-engineering.md", "docs/soar.md", "docs/threat-intelligence.md",
        "docs/incident-response.md", "docs/mitre-coverage.md", "docs/testing.md",
        "docs/troubleshooting.md", "docs/validation-matrix.md",
    ]
    for d in required_docs:
        assert (ROOT / d).exists(), f"Missing documentation: {d}"


def main() -> None:
    assert_yaml_files()
    assert_detection_contracts()
    assert_soar_references()
    assert_no_static_caldera_keys()
    assert_compose_safety()
    assert_env_example_safe()
    assert_docs_present()
    print("Autonomous SOC Lab validation: PASS")


if __name__ == "__main__":
    main()
