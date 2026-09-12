#!/usr/bin/env python3
"""Standalone health / configuration sanity check."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.config import SOCConfig
from soc.health.checks import run_health_checks


def main() -> int:
    cfg = SOCConfig.load()
    checks = run_health_checks(cfg)
    failed = False
    for c in checks:
        mark = "PASS" if c.ok else "FAIL"
        print(f"[{mark}] {c.name}: {c.detail}")
        if not c.ok:
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
