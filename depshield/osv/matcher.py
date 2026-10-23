"""Decides whether a concrete version is inside an advisory's range.

OSV expresses affected ranges as ordered events:
    introduced: version where the vuln appears ("0" = beginning of time)
    fixed:      version where it is fixed
    last_affected: last version still affected

We walk the events in order and track whether `version` is currently
inside the affected window.

PyPI versions compare with packaging.version (PEP 440). npm uses a
simplified semver compare — full npm range semantics are a roadmap item.
"""
from __future__ import annotations

from packaging.version import InvalidVersion, Version

from ..models import Advisory


def _cmp(a: str, b: str, ecosystem: str) -> int:
    """Return -1/0/1 comparing version a to b. Unparseable => 0 (no crash)."""
    if ecosystem == "PyPI":
        try:
            va, vb = Version(a), Version(b)
        except InvalidVersion:
            return 0
        return (va > vb) - (va < vb)
    # Simplified semver: numeric dotted parts.
    def parts(v: str) -> list[int]:
        out = []
        for p in v.split("-")[0].split("."):
            out.append(int(p) if p.isdigit() else 0)
        return out

    pa, pb = parts(a), parts(b)
    pa += [0] * (len(pb) - len(pa))
    pb += [0] * (len(pa) - len(pb))
    return (pa > pb) - (pa < pb)


def is_vulnerable(version: str, advisory: Advisory, ecosystem: str) -> bool:
    affected = False
    for event in advisory.ranges:
        if "introduced" in event:
            intro = event["introduced"]
            if intro == "0" or _cmp(version, intro, ecosystem) >= 0:
                affected = True
        elif "fixed" in event:
            if _cmp(version, event["fixed"], ecosystem) >= 0:
                affected = False
        elif "last_affected" in event:
            if _cmp(version, event["last_affected"], ecosystem) > 0:
                affected = False
    return affected
