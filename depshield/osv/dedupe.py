"""Collapse duplicate OSV advisory records into one finding each.

Two kinds of duplication show up in the local snapshot:

1. The SAME advisory ID indexed more than once for a package (the source
   record lists the package under several `affected` entries with different
   version ranges, and the fetcher indexes one row per entry).
2. The same underlying CVE carried by two different source IDs — a GHSA
   record and its PYSEC mirror. They share the same summary text.

Both cases inflate the findings table, so findings are deduplicated *before*
matching: merging ranges (union — a version must never stop matching because
a duplicate row was folded away) and recording the folded IDs as aliases.
"""
from __future__ import annotations

from ..models import Advisory


def _norm_summary(summary: str) -> str:
    return " ".join(summary.lower().split())


def _merge_group(group: list[Advisory]) -> Advisory:
    """Fold a group of advisories describing the same CVE into one."""
    # Deterministic primary: prefer GHSA over PYSEC over anything else.
    def rank(a: Advisory) -> int:
        if a.id.startswith("GHSA"):
            return 0
        if a.id.startswith("PYSEC"):
            return 1
        return 2

    ordered = sorted(group, key=lambda a: (rank(a), a.id))
    primary = ordered[0]
    merged_ranges: list[dict] = []
    for a in ordered:
        for event in a.ranges:
            if event not in merged_ranges:
                merged_ranges.append(event)
    severity = next((a.severity for a in ordered if a.severity), None)
    return Advisory(
        id=primary.id,
        summary=primary.summary,
        ranges=merged_ranges,
        severity=severity,
        aliases=[a.id for a in ordered[1:]],
    )


def dedupe_advisories(advisories: list[Advisory]) -> list[Advisory]:
    """Return one Advisory per distinct CVE from possibly duplicated records."""
    # Pass 1: fold exact ID duplicates (union of their ranges).
    by_id: dict[str, list[Advisory]] = {}
    for a in advisories:
        by_id.setdefault(a.id, []).append(a)
    folded = [_merge_group(g) if len(g) > 1 else g[0] for g in by_id.values()]

    # Pass 2: fold same-CVE records under different IDs. Records without a
    # summary never merge — an empty summary is no evidence of sameness.
    by_summary: dict[str, list[Advisory]] = {}
    unsummarized: list[Advisory] = []
    for a in folded:
        if not _norm_summary(a.summary):
            unsummarized.append(a)
        else:
            by_summary.setdefault(_norm_summary(a.summary), []).append(a)
    merged = [_merge_group(g) for g in by_summary.values()] + unsummarized
    return sorted(merged, key=lambda a: a.id)
