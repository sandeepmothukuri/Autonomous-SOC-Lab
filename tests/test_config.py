"""Compose, YAML, and SOAR workflow reference tests."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_yaml(path: Path):
    return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def test_all_yaml_files_parse():
    candidates = list((ROOT / "detections").glob("*.yaml"))
    candidates += list((ROOT / "soar").rglob("*.yaml"))
    candidates += list((ROOT / "configs").rglob("*.yaml"))
    candidates += list((ROOT / "configs").rglob("*.yml"))
    candidates += list((ROOT / "caldera").glob("*.yml"))
    for path in candidates:
        docs = list(_load_yaml(path))
        assert all(d is not None for d in docs), f"{path}: empty YAML document"


def test_detection_rules_have_required_fields():
    required = ["name", "type", "index", "alert", "http_post_url", "timestamp_field"]
    for path in (ROOT / "detections").glob("*.yaml"):
        doc = _load_yaml(path)[0]
        for k in required:
            assert k in doc, f"{path.name}: missing detection field '{k}'"
        # MITRE metadata must be present in static_payload
        assert "mitre_technique" in doc.get("http_post_static_payload", {}), \
            f"{path.name}: missing mitre_technique in static payload"
        assert "severity" in doc.get("http_post_static_payload", {}), \
            f"{path.name}: missing severity in static payload"


def test_detection_rules_use_ecs_fields():
    allowed_fields = {
        "source.ip", "host.name", "user.name", "destination.ip",
        "destination.port", "event.type", "event.severity", "event.action",
        "process.command_line",
        "process.name", "alert.rule", "network.direction",
        "process.parent.name", "mitre_technique", "mitre_tactic",
        "mitre_subtechnique",
    }
    winlog_prefixes = ("winlog.event_id", "winlog.event_data.")
    import re
    for path in (ROOT / "detections").glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        # Only inspect the query/filter block — not comments or http_post_payload keys/values
        # We look at tokens that look like dotted field names used in queries (term: / query_string:).
        for field in re.findall(r'([a-z_][a-z0-9_]*\.[a-z_][a-zA-Z0-9_.]*)', text):
            if field.endswith("."):
                continue  # ElastAlert placeholder like {source.ip}
            if field.startswith("http_") or field.startswith("alert_text") or field.startswith("include:"):
                continue
            if field.startswith(winlog_prefixes):
                continue  # winlog raw fields are acceptable alongside ECS normalization
            if field.split(".")[0] in {"source", "destination", "host", "user",
                                        "event", "process", "network", "file",
                                        "alert", "mitre"}:
                assert field in allowed_fields, f"{path.name}: unknown ECS field '{field}'"


def test_stackstorm_rules_reference_existing_actions():
    rules = _load_yaml(ROOT / "soar/rules/elastalert.yaml")
    for rule in rules:
        action_ref = rule["action"]["ref"]
        assert action_ref.startswith("soc_lab."), f"{rule.get('name')}: action must be in soc_lab pack"
        action_name = action_ref.split(".", 2)[-1]
        action_path = ROOT / "soar" / "actions" / f"{action_name}.yaml"
        assert action_path.exists(), f"Missing action file for {action_ref}: {action_path}"


def test_stackstorm_actions_reference_existing_workflows():
    for action_path in (ROOT / "soar/actions").glob("*.yaml"):
        doc = _load_yaml(action_path)[0]
        entry = doc.get("entry_point")
        if doc.get("runner_type") == "orquesta":
            assert entry, f"{action_path.name}: orquesta action missing entry_point"
            wf_path = action_path.parent / entry
            assert wf_path.exists(), f"{action_path.name}: workflow {entry} not found"


def test_workflow_inputs_match_action_parameters():
    for action_path in (ROOT / "soar/actions").glob("*.yaml"):
        doc = _load_yaml(action_path)[0]
        entry = doc.get("entry_point")
        if not entry or doc.get("runner_type") != "orquesta":
            continue
        wf_doc = _load_yaml(action_path.parent / entry)[0]
        wf_inputs = set(wf_doc.get("input", []))
        # every action parameter that is required must be in workflow inputs
        for name, spec in doc.get("parameters", {}).items():
            if spec.get("required"):
                assert name in wf_inputs, \
                    f"{action_path.name}: required param '{name}' missing from workflow inputs"


def test_github_actions_workflow_present():
    assert (ROOT / ".github" / "workflows" / "validate.yml").exists()


def test_docker_compose_resolves_with_example_env():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    env_path = ROOT / ".env.test"
    import re as _re
    filled = _re.sub(r"<GENERATE_[^>]+>", "test-placeholder-value", env)
    env_path.write_text(filled)
    try:
        try:
            r = subprocess.run(
                ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
                 "--env-file", str(env_path), "config", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            pytest.skip("docker not available in test environment")
        if r.returncode != 0:
            pytest.fail(f"docker compose config failed:\n{r.stderr}")
    finally:
        env_path.unlink(missing_ok=True)


def test_no_latest_tag_for_core_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    # Only MISP uses "latest" because upstream tags aren't stable; Caldera uses latest
    # but is an adversary-emulation tool without pinned tags. Verify opensearch etc are pinned.
    for svc in ("opensearch:", "opensearch-dashboards:", "vector:", "elastalert2:",
                "stackstorm:", "postgres:", "mysql:", "redis:"):
        m = _find_service_image(compose, svc)
        if m:
            assert ":latest" not in m, f"{svc} uses 'latest' tag; pin a version"


def _find_service_image(compose_text: str, service: str) -> str | None:
    import re
    # Naive search for "image:" lines between the service header and next service
    idx = compose_text.find("  " + service)
    if idx < 0:
        return None
    block = compose_text[idx:idx+2000]
    m = re.search(r'image:\s*(\S+)', block)
    return m.group(1) if m else None
