"""MITRE ATT&CK mapping validation."""
from __future__ import annotations

from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).resolve().parents[1]

# Current MITRE ATT&CK techniques actually referenced in this repository.
# This set is intentionally conservative — we only assert that technique IDs
# we reference are formatted correctly and look plausible; we do NOT attempt
# to validate against the full ATT&CK matrix offline.
KNOWN_TECHNIQUES = {
    "T1059.001",  # PowerShell
    "T1021",      # Remote Services
    "T1021.001",  # RDP
    "T1021.002",  # SMB Admin Shares
    "T1021.004",  # SSH
    "T1110",      # Brute Force
    "T1110.001",  # Password Guessing
    "T1548",      # Abuse Elevation Control Mechanism
    "T1548.003",  # Sudo NOPASSWD
    "T1053.005",  # schtasks
    "T1003.001",  # LSASS (python detection only)
    "T1027",
    "T1071.001",
}


def _tid(tid: str) -> bool:
    import re
    return bool(re.match(r"^T\d{4}(\.\d{3})?$", tid))


def test_detection_rules_have_valid_mitre_technique():
    for path in (ROOT / "detections").glob("*.yaml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        tid = doc.get("http_post_static_payload", {}).get("mitre_technique")
        assert tid, f"{path.name}: missing mitre_technique"
        assert _tid(tid), f"{path.name}: malformed technique id '{tid}'"
        assert tid in KNOWN_TECHNIQUES, f"{path.name}: unknown technique {tid}"
        tactic = doc.get("http_post_static_payload", {}).get("mitre_tactic")
        assert tactic, f"{path.name}: missing mitre_tactic"
