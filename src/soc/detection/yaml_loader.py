"""Load declarative YAML detection rules.

YAML rules are deterministic, just like Python rules; they just use a
declarative subset of matchers instead of Python predicates. This
keeps the AI out of rule creation and keeps rules auditable.

Supported match types:
  - substring : case-insensitive substring match on `field`, optionally
                also requiring `process_contains` on `process`.

Additional match types (regex, CIDR, etc.) can be added as pure
functions here; NEVER accept arbitrary Python expressions from
config.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from .engine import Rule
from ..models import Severity


def load_yaml_rules(path: str | Path) -> List[Rule]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    out: List[Rule] = []
    for r in doc.get("rules", []):
        out.append(_build(r))
    return out


def _build(r: dict) -> Rule:
    match = r["match"]
    mtype = match.get("type", "substring")
    field = match["field"]
    value = match["value"].lower()
    proc_contains = match.get("process_contains")

    if mtype != "substring":
        raise ValueError(f"Unsupported YAML rule match type: {mtype}")

    def predicate(ev, _field=field, _value=value, _proc=proc_contains):
        fval = getattr(ev, _field, None)
        if fval is None:
            # fallback into raw dict for fields beyond the explicit columns
            fval = ev.raw.get(_field)
        if fval is None:
            return False
        if _value not in str(fval).lower():
            return False
        if _proc:
            proc = (ev.process or "").lower()
            if _proc.lower() not in proc:
                return False
        return True

    return Rule(
        rule_id=r["rule_id"],
        rule_name=r["rule_name"],
        severity=Severity(r["severity"]),
        mitre_techniques=list(r.get("mitre_techniques", [])),
        match_fn=predicate,
        description=r.get("description", ""),
    )
