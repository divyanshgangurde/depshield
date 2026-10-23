"""Loads the local OSV snapshot built by scripts/fetch_data.py.

Snapshot format (data/osv_index.json):

    {
      "PyPI": {
        "requests": [
          {"id": "GHSA-...", "summary": "...", "severity": "HIGH",
           "ranges": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
        ]
      },
      "npm": { ... }
    }

Package keys are normalized the same way Dependency.key normalizes.
"""
from __future__ import annotations

import json
import os

from ..models import Advisory


class OsvIndex:
    def __init__(self, data: dict):
        self._data = data

    @classmethod
    def load(cls, data_dir: str) -> "OsvIndex | None":
        path = os.path.join(data_dir, "osv_index.json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def advisories_for(self, ecosystem: str, key: str) -> list[Advisory]:
        raw_list = self._data.get(ecosystem, {}).get(key, [])
        return [
            Advisory(
                id=r["id"],
                summary=r.get("summary", ""),
                ranges=r.get("ranges", []),
                severity=r.get("severity"),
            )
            for r in raw_list
        ]
