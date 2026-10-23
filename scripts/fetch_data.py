#!/usr/bin/env python3
"""Build DepShield's local data snapshot. NEEDS NETWORK. Run once.

Downloads:
  1. OSV per-ecosystem exports (PyPI, npm) and compacts them into
     data/osv_index.json  {ecosystem: {package_key: [advisories]}}
  2. Top PyPI packages list -> data/popular_pypi.json

Usage:
    python scripts/fetch_data.py                # everything
    python scripts/fetch_data.py --only pypi    # tonight's quick path
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import urllib.request
import zipfile

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
TOP_PYPI_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.min.json"
)
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def normalize(name: str, ecosystem: str) -> str:
    n = name.lower()
    if ecosystem == "PyPI":
        n = n.replace("_", "-").replace(".", "-")
    return n


def build_osv_index(eco_key: str, ecosystem: str) -> dict:
    url = OSV_URL.format(eco=ecosystem)
    print(f"downloading {url} ...")
    raw = urllib.request.urlopen(url).read()
    print(f"  {len(raw) / 1e6:.1f} MB; indexing ...")
    index: dict[str, list] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        for i, name in enumerate(names):
            if i % 5000 == 0:
                print(f"  {i}/{len(names)} advisories")
            try:
                adv = json.loads(zf.read(name))
            except Exception:
                continue
            severity = None
            if adv.get("severity"):
                severity = adv["severity"][0].get("score")
            for affected in adv.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem") != ecosystem:
                    continue
                events: list[dict] = []
                for rng in affected.get("ranges", []):
                    if rng.get("type") == "ECOSYSTEM":
                        events.extend(rng.get("events", []))
                if not events:
                    continue
                key = normalize(pkg.get("name", ""), ecosystem)
                index.setdefault(key, []).append(
                    {
                        "id": adv.get("id", "UNKNOWN"),
                        "summary": adv.get("summary", ""),
                        "severity": severity,
                        "ranges": events,
                    }
                )
    print(f"  {ecosystem}: {len(index)} packages with advisories")
    return index


def fetch_popular_pypi(limit: int = 1000) -> list[str]:
    print(f"downloading {TOP_PYPI_URL} ...")
    doc = json.load(urllib.request.urlopen(TOP_PYPI_URL))
    return [row["project"] for row in doc["rows"][:limit]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=list(ECOSYSTEMS), help="one ecosystem only")
    args = ap.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    wanted = [args.only] if args.only else list(ECOSYSTEMS)

    index_path = os.path.join(DATA_DIR, "osv_index.json")
    full: dict = {}
    if os.path.exists(index_path):
        with open(index_path, encoding="utf-8") as f:
            full = json.load(f)

    for eco_key in wanted:
        full[ECOSYSTEMS[eco_key]] = build_osv_index(eco_key, ECOSYSTEMS[eco_key])
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(full, f)
    print(f"wrote {index_path}")

    if "pypi" in wanted:
        popular = fetch_popular_pypi()
        path = os.path.join(DATA_DIR, "popular_pypi.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(popular, f)
        print(f"wrote {path} ({len(popular)} names)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
