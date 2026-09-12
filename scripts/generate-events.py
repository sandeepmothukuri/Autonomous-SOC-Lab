#!/usr/bin/env python3
"""Generate synthetic SOC events into data/sample_logs/ to exercise the
Vector -> OpenSearch -> ElastAlert -> StackStorm pipeline.

Events are SYNTHETIC. No real PII, no real malware, no real credentials.

Usage:
    python scripts/generate-events.py --scenario brute_force
    python scripts/generate-events.py --scenario powershell
    python scripts/generate-events.py --scenario lateral_movement
    python scripts/generate-events.py --scenario all
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "data" / "sample_logs"
AUTH_LOG = LOG_DIR / "auth.log"
SYSMON = LOG_DIR / "sysmon.json"
ZEEK = LOG_DIR / "zeek_conn.log"

SYNTH_IP = "203.0.113.47"
SYNTH_HOST = "web-prod-01.corp.lab"
SYNTH_USER = "root"


def append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


def gen_brute_force(n: int = 6) -> None:
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    for i in range(n):
        port = 51000 + i * 2
        append(AUTH_LOG,
               f"{ts} web-prod-01 sshd[300{i}]: Failed password for {SYNTH_USER} from {SYNTH_IP} port {port} ssh2")


def gen_powershell() -> None:
    ev = {
        "winlog": {"event_id": 4104, "event_data": {
            "SubjectUserName": "alice",
            "ScriptBlockText": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        }},
        "host": {"name": "wkstn-42.corp.lab"},
        "ComputerName": "wkstn-42.corp.lab",
    }
    append(SYSMON, json.dumps(ev))


def gen_lateral() -> None:
    # 3 SMB/RDP connections from same synthetic source to internal hosts
    for host_suffix, port in [(20, 445), (21, 3389), (22, 22)]:
        ev = {
            "winlog": {"event_id": 3, "event_data": {
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "DestinationIp": f"10.0.0.{host_suffix}",
                "DestinationPort": port,
            }},
            "host": {"name": "wkstn-99.corp.lab", "ip": "10.0.0.99"},
            "ComputerName": "wkstn-99.corp.lab",
        }
        append(SYSMON, json.dumps(ev))


def gen_privesc() -> None:
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    append(AUTH_LOG, f"{ts} web-prod-01 sudo: bob : TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=NOPASSWD: /usr/local/bin/pwn.sh")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate synthetic SOC events for lab testing.")
    p.add_argument("--scenario",
                   choices=["brute_force", "powershell", "lateral_movement", "privilege_escalation", "all"],
                   required=True)
    args = p.parse_args()

    if args.scenario in ("brute_force", "all"):
        gen_brute_force()
        print(f"Appended brute-force events to {AUTH_LOG}")
    if args.scenario in ("powershell", "all"):
        gen_powershell()
        print(f"Appended PowerShell event to {SYSMON}")
    if args.scenario in ("lateral_movement", "all"):
        gen_lateral()
        print(f"Appended lateral-movement events to {SYSMON}")
    if args.scenario in ("privilege_escalation", "all"):
        gen_privesc()
        print(f"Appended priv-esc event to {AUTH_LOG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
