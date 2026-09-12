"""Lightweight in-memory SIEM-style case store.

For production this would sit on Elastic/OpenSearch/Splunk. For the
research build we expose the same add/search/flush interface on top of
a JSON-lines file so pipelines are reproducible.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

from ..models import Case


class SIEMStore:
    def __init__(self, index_path: str | Path):
        self.index_path = Path(index_path)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self._mem: List[dict] = []

    def add(self, case: Case) -> None:
        doc = case.model_dump(mode="json")
        self._mem.append(doc)
        try:
            with self.index_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(doc) + "\n")
        except OSError:
            pass

    def search(self, *, severity: Optional[str] = None, status: Optional[str] = None,
               case_id: Optional[str] = None) -> List[dict]:
        out = []
        for doc in self._mem:
            if case_id and doc["case_id"] != case_id:
                continue
            if status and doc["status"] != status:
                continue
            if severity:
                top = _top_severity(doc)
                if top != severity:
                    continue
            out.append(doc)
        return out

    def all(self) -> List[dict]:
        return list(self._mem)

    def load_from_disk(self) -> int:
        if not self.index_path.exists():
            return 0
        count = 0
        with self.index_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self._mem.append(json.loads(line))
                    count += 1
        return count


def _top_severity(doc: dict) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    ranks = [order.index(a["severity"]) for a in doc.get("alerts", [])]
    if not ranks:
        return "info"
    return order[max(ranks)]
