"""Manifest parsers: turn a file into a normalized Dependency list."""
from __future__ import annotations

import os

from ..models import Dependency
from .package_json_parser import parse_package_json
from .requirements_parser import parse_requirements


def parse_manifest(path: str) -> list[Dependency]:
    """Pick the right parser based on the manifest file name."""
    base = os.path.basename(path)
    if base.endswith("package.json"):
        return parse_package_json(path)
    if base in ("requirements.txt",) or base.endswith(".txt"):
        return parse_requirements(path)
    raise ValueError(f"Don't know how to parse {base!r} yet")
