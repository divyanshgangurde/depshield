"""Shared data types for DepShield.

Everything in the pipeline passes these around: parsers produce
Dependency objects, checks produce Finding objects, report renders them.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Dependency:
    """One dependency parsed out of a manifest file."""

    name: str                  # as written in the manifest
    ecosystem: str              # "PyPI" or "npm"
    version: str | None = None  # pinned version, if the manifest pins one
    spec: str | None = None     # raw version spec if not an exact pin (e.g. ">=2.0")
    source: str | None = None   # file it came from

    @property
    def key(self) -> str:
        """Normalized lookup key (PEP 503 style for PyPI, lowercase for npm)."""
        if self.ecosystem == "PyPI":
            return self.name.lower().replace("_", "-").replace(".", "-")
        return self.name.lower()


@dataclass
class Advisory:
    """One vulnerability record from the local OSV snapshot."""

    id: str                     # e.g. "GHSA-xxxx" or "PYSEC-2021-..."
    summary: str
    # Affected ranges as event lists, mirroring OSV:
    # [{"introduced": "0"}, {"fixed": "2.20.0"}, ...]
    ranges: list[dict] = field(default_factory=list)
    severity: str | None = None
    # Other record IDs merged into this one by dedupe (same CVE under a
    # different source ID, e.g. the PYSEC record of a GHSA advisory).
    aliases: list[str] = field(default_factory=list)

    @property
    def fixed_versions(self) -> list[str]:
        return [e["fixed"] for e in self.ranges if "fixed" in e]


@dataclass
class Finding:
    """One problem DepShield found with one dependency."""

    dependency: Dependency
    kind: str                   # "vuln" | "typosquat" | "unpinned"
    title: str                  # short human headline
    detail: str = ""            # longer explanation
    advisory: Advisory | None = None       # set when kind == "vuln"
    suggestion: str | None = None          # set when kind == "typosquat"
