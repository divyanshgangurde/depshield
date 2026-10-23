"""Typosquat detection: is this package name a lookalike of a popular one?

Method: normalize names (PEP 503 for PyPI), then Levenshtein edit
distance against a popular-packages list. Distance 1 or 2 from a popular
name, while not being that name, is suspicious. This is a heuristic for
a human to glance at — it suggests, never accuses.

Data: scripts/fetch_data.py builds data/popular_pypi.json (top ~1000).
Until that runs, a small built-in starter list keeps the check alive.
"""
from __future__ import annotations

import json
import os

from .models import Dependency, Finding

STARTER_POPULAR = {
    "PyPI": [
        "requests", "flask", "django", "numpy", "pandas", "colorama",
        "urllib3", "boto3", "pytest", "setuptools", "pip", "sqlalchemy",
        "fastapi", "pydantic", "pillow", "cryptography", "pyyaml",
        "click", "tqdm", "scipy", "matplotlib", "redis", "celery",
    ],
    "npm": [
        "lodash", "express", "chalk", "colors", "commander", "axios",
        "react", "debug", "uuid", "moment", "request", "yargs",
        "semver", "typescript", "webpack", "eslint", "prettier",
    ],
}


def _normalize(name: str, ecosystem: str) -> str:
    n = name.lower()
    if ecosystem == "PyPI":
        n = n.replace("_", "-").replace(".", "-")
    return n


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3  # beyond our flagging threshold; skip the full DP
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def load_popular(data_dir: str, ecosystem: str) -> list[str]:
    path = os.path.join(data_dir, f"popular_{ecosystem.lower()}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return STARTER_POPULAR.get(ecosystem, [])


def check_dependency(dep: Dependency, popular: list[str]) -> Finding | None:
    name = _normalize(dep.name, dep.ecosystem)
    best: tuple[int, str] | None = None
    for pop in popular:
        p = _normalize(pop, dep.ecosystem)
        if name == p:
            return None  # it IS the popular package
        d = _levenshtein(name, p)
        if d in (1, 2) and (best is None or d < best[0]):
            best = (d, pop)
    if best is None:
        return None
    dist, suggestion = best
    return Finding(
        dependency=dep,
        kind="typosquat",
        title=f"Possible typosquat of {suggestion!r}",
        detail=(
            f"{dep.name!r} is edit distance {dist} from the popular package "
            f"{suggestion!r}. Attackers register lookalike names to catch "
            "typos at install time. Verify this is the package you meant."
        ),
        suggestion=suggestion,
    )
