"""Security tests: no secrets committed, no unsafe defaults, response-mode
safety, localhost bind defaults."""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

TEXT_EXTS = {".yml", ".yaml", ".toml", ".md", ".sh", ".py", ".example", ""}


def _iter_tracked_text_files():
    skip_dirs = {".git", ".pytest_cache", "__pycache__", "data", "screenshots", ".venv"}
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        if any(part in skip_dirs for part in rel.parts):
            continue
        if p.suffix in {".png", ".jpg", ".svg", ".pyc"}:
            continue
        yield p


def test_no_hardcoded_passwords_in_tracked_files():
    bad_patterns = [
        (re.compile(r'(password|passwd|secret|token)\s*[:=]\s*["\']?(Soc@|Root@|admin123|password1|changeme|123456)', re.I),
         "weak hardcoded credential"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key id"),
        (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), "private key"),
        (re.compile(r'api_key_(red|blue)\s*:\s*[A-Za-z0-9._-]{8,}'), "Caldera static API key"),
    ]
    for path in _iter_tracked_text_files():
        if path.name == ".env.example":
            continue  # placeholders expected
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rx, label in bad_patterns:
            assert not rx.search(text), f"{path}: potential {label} found"


def test_default_bind_addresses_are_localhost():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for var in ("OPENSEARCH_BIND_ADDRESS", "DASHBOARDS_BIND_ADDRESS",
                "STACKSTORM_BIND_ADDRESS", "IRIS_BIND_ADDRESS", "MISP_BIND_ADDRESS",
                "VELOCIRAPTOR_BIND_ADDRESS", "CALDERA_BIND_ADDRESS"):
        assert f"{var}:-127.0.0.1" in compose, f"compose missing localhost default for {var}"


def test_default_response_mode_is_simulation():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "SOC_RESPONSE_MODE=simulation" in env
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "SOC_RESPONSE_MODE:-simulation" in compose


def test_opensearch_security_consistently_disabled():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    os_yml = (ROOT / "configs/opensearch/opensearch.yml").read_text(encoding="utf-8")
    dash_yml = (ROOT / "configs/opensearch/dashboards.yml").read_text(encoding="utf-8")
    vector_toml = (ROOT / "pipeline/vector.toml").read_text(encoding="utf-8")
    ea_cfg = (ROOT / "configs/elastalert/config.yaml").read_text(encoding="utf-8")

    assert "plugins.security.disabled: true" in os_yml
    assert "opensearch_security.disabled: true" in dash_yml
    assert "DISABLE_SECURITY_DASHBOARDS_PLUGIN=true" in compose
    # No auth in Vector sinks / ElastAlert
    assert "strategy = \"basic\"" not in vector_toml, \
        "Vector elasticsearch sink must not use basic auth when security is disabled"
    assert "es_username" not in ea_cfg or "# es_username" in ea_cfg, \
        "ElastAlert must not set es_username with security disabled"


def test_env_example_has_safe_placeholders():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    # Real weak password values (not comments or variable names ending in _PASSWORD)
    bad_values = ("admin123", "=password", "=changeme", "=default", ":password")
    for bad in bad_values:
        assert bad.lower() not in env.lower(), f".env.example contains unsafe value '{bad}'"
    assert "<GENERATE_" in env, ".env.example must contain GENERATE_* placeholders"


def test_screenshots_labeled_as_mockups_when_necessary():
    # The README must not present SVG mockups as live screenshots
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "mockup" in readme.lower() or "mock-ups" in readme.lower() or "mockups" in readme.lower(), \
        "README should label SVG visuals as mockups"


def test_gitignore_present_and_covers_env():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gi, ".gitignore must exclude .env"
