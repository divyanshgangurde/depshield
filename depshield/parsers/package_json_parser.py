"""Parser for npm package.json files.

Reads `dependencies` and `devDependencies`. npm specs are ranges by
convention ("^4.17.1"); we record the base version of the range as the
version to check and keep the raw spec for display. A bare "*" or
"latest" is unpinned.
"""
from __future__ import annotations

import json
import re

from ..models import Dependency

_RANGE_PREFIX = re.compile(r"^[\^~>=<\s]+")


def _base_version(spec: str) -> str | None:
    spec = spec.strip()
    if spec in ("", "*", "latest"):
        return None
    base = _RANGE_PREFIX.sub("", spec).split(" ")[0]
    # Things like "file:...", "git+https://..." are not registry versions.
    if ":" in base or "/" in base.replace("@", "", 1):
        return None
    return base or None


def parse_package_json(path: str) -> list[Dependency]:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (doc.get(section) or {}).items():
            base = _base_version(str(spec))
            deps.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    version=base,
                    spec=str(spec) if base is None else None,
                    source=path,
                )
            )
    return deps
