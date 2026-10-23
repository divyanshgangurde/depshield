"""Parser for pip requirements.txt files.

Handles the common shapes:
    requests==2.31.0            -> pinned
    flask>=2.0                  -> range (recorded, not verifiable offline)
    numpy                       -> unpinned
    uvicorn[standard]==0.24.0   -> extras ignored, pin kept
Comments, blank lines, and pip option lines (-r, --index-url, ...) are
skipped. Lines we cannot understand are skipped too, never crash.
"""
from __future__ import annotations

from packaging.requirements import Requirement

from ..models import Dependency


def parse_requirements(path: str) -> list[Dependency]:
    deps: list[Dependency] = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            try:
                req = Requirement(line)
            except Exception:
                continue
            pin = None
            spec = None
            for s in req.specifier:
                if s.operator == "==":
                    pin = s.version
                spec = str(req.specifier) or None
            deps.append(
                Dependency(
                    name=req.name,
                    ecosystem="PyPI",
                    version=pin,
                    spec=spec if pin is None else None,
                    source=path,
                )
            )
    return deps
