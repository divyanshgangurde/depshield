"""DepShield command line.

Usage:
    depshield requirements.txt
    depshield package.json --json
    depshield requirements.txt --data-dir ./data

Pipeline: parse manifest -> vulnerability match (local OSV snapshot)
-> typosquat check (popular-name list) -> report. The scan path never
touches the network. Exit code 1 if any finding, else 0.
"""
from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console

from .models import Finding
from .osv.index import OsvIndex
from .osv.matcher import is_vulnerable
from .parsers import parse_manifest
from .report import render_json, render_terminal
from .typosquat import check_dependency, load_popular


def run(manifest: str, data_dir: str) -> list[Finding]:
    deps = parse_manifest(manifest)
    findings: list[Finding] = []

    index = OsvIndex.load(data_dir)
    if index is None:
        print(
            "note: no OSV snapshot found in "
            f"{data_dir!r} — vulnerability check skipped. "
            "Run: python scripts/fetch_data.py",
            file=sys.stderr,
        )

    popular_cache: dict[str, list[str]] = {}
    for dep in deps:
        # Typosquat check runs even without the OSV snapshot.
        if dep.ecosystem not in popular_cache:
            popular_cache[dep.ecosystem] = load_popular(data_dir, dep.ecosystem)
        hit = check_dependency(dep, popular_cache[dep.ecosystem])
        if hit:
            findings.append(hit)

        if dep.version is None:
            findings.append(
                Finding(
                    dependency=dep,
                    kind="unpinned",
                    title="No pinned version — cannot verify",
                    detail="Pin an exact version so it can be checked "
                    "against known advisories.",
                )
            )
            continue

        if index is not None:
            for adv in index.advisories_for(dep.ecosystem, dep.key):
                if is_vulnerable(dep.version, adv, dep.ecosystem):
                    findings.append(
                        Finding(
                            dependency=dep,
                            kind="vuln",
                            title=f"{adv.id}: {adv.summary}",
                            advisory=adv,
                        )
                    )
    return findings, len(deps)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="depshield",
        description="Offline dependency vulnerability + typosquat checker",
    )
    ap.add_argument("manifest", help="requirements.txt or package.json")
    ap.add_argument(
        "--data-dir",
        default=os.path.join(os.getcwd(), "data"),
        help="directory holding the local data snapshot (default: ./data)",
    )
    ap.add_argument("--json", action="store_true", help="output JSON report")
    args = ap.parse_args(argv)

    findings, scanned = run(args.manifest, args.data_dir)
    if args.json:
        print(render_json(findings, scanned))
    else:
        render_terminal(findings, scanned, Console())
    return 1 if any(f.kind in ("vuln", "typosquat") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
