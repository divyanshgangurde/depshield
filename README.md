# DepShield

**An offline dependency vulnerability + typosquat checker for Python and Node projects.**

Point it at a `requirements.txt` or `package.json`. It tells you, without any
network access, which of your dependencies have known vulnerabilities and
which ones look like typosquats of popular packages.

```bash
depshield requirements.txt
```

---

## Why this exists

Every project starts the same way: `pip install` / `npm install`, copy a few
names from a tutorial, move on. Two quiet risks ride along:

1. **Known-vulnerable versions.** Old pinned versions accumulate published
   advisories. The fix is usually one version bump, but nobody checks.
2. **Typosquats.** Attackers publish malicious packages with names one
   keystroke away from popular ones (`colourama`, `reqeusts`) and wait for a
   tired developer. Checkmarx documented PyPI `colorama` typosquats stealing
   credentials in June 2025; in October 2025, typosquatted packages were
   caught exfiltrating Discord tokens. Sonatype counted 454,600+ new
   malicious packages in 2025 alone (vendor-reported).

Existing scanners (pip-audit, osv-scanner, npm audit) are excellent but are
built for CI pipelines and security teams, assume network access, and say
nothing friendly about a suspicious package *name*. DepShield is built for
the student or indie dev at install time: fully offline, one command,
plain-language output, and a "did you mean `colorama`?" for names.

## What it does

| Check | How |
|---|---|
| Vulnerable versions | Matches every pinned dependency against a local snapshot of the [OSV](https://osv.dev) database (Google's open vulnerability database) |
| Typosquats | Compares each package name against a popular-packages list using edit distance on normalized names; flags distance 1–2 lookalikes with a suggestion |
| Unpinned deps | Warns when a dependency has no pinned version, so it cannot be verified |

Output is a colour-coded terminal report, with `--json` for a machine
-readable report. Exit code is `1` when findings exist, `0` when clean, so
it can gate a script or CI job.

## Architecture

```
                    ┌──────────────────────┐
  requirements.txt  │                      │   local snapshot (built once,
  package.json ───► │  parsers/            │   see scripts/fetch_data.py)
                    │  normalize name+ver  │        ┌─────────────────┐
                    └─────────┬────────────┘        │  OSV index      │
                              │                     │  popular lists  │
                    ┌─────────▼────────────┐        └────────┬────────┘
                    │  checks              │                 │
                    │  osv/matcher.py      │ ◄───────────────┘
                    │  typosquat.py        │
                    └─────────┬────────────┘
                              │
                    ┌─────────▼────────────┐
                    │  report.py           │  terminal (rich) / JSON
                    └──────────────────────┘
```

| Module | Responsibility |
|---|---|
| `depshield/cli.py` | Entry point. Parses args, runs the pipeline, sets exit code |
| `depshield/models.py` | `Dependency`, `Advisory`, `Finding` dataclasses shared everywhere |
| `depshield/parsers/` | One parser per manifest format → normalized `Dependency` list |
| `depshield/osv/index.py` | Loads the local OSV snapshot into a fast lookup index |
| `depshield/osv/matcher.py` | Decides if a version falls inside an advisory's affected range |
| `depshield/typosquat.py` | Edit-distance lookalike detection vs. popular package names |
| `depshield/report.py` | Terminal and JSON rendering of findings |
| `scripts/fetch_data.py` | One-time data build: downloads OSV exports + popular lists, writes `data/` |

Design rules: the scan path **never touches the network**; all data is
prepared ahead of time by `scripts/fetch_data.py`. Parsers are dumb and
total (never crash on a weird line, record what they could not parse).

## Quickstart

```bash
# 1. Install (from this repo)
pip install -e .

# 2. Build the local data snapshot (needs network, once)
python scripts/fetch_data.py

# 3. Scan something (works offline from here on)
depshield path/to/requirements.txt
depshield path/to/package.json --json
```

Try the bundled demos:

```bash
depshield samples/demo-requirements.txt
depshield samples/demo-package.json
```

## Data sources

- **OSV database** — per-ecosystem exports from
  `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`
  (we use `PyPI` and `npm`). OSV's documented offline mode is the model for
  this design.
- **Popular packages** — top PyPI packages list (hugovk/top-pypi-packages);
  a curated npm starter list ships in `depshield/typosquat.py` until the npm
  list builder lands.

Snapshots are data, not code: they live in `data/` and are git-ignored.
Re-run `fetch_data.py` whenever you want fresher advisories.

## Demo script (2 minutes)

1. "This is a normal-looking `requirements.txt` from a tutorial project."
   Run `depshield samples/demo-requirements.txt`.
2. The report lights up: old pinned versions with published advisories, each
   with the fixed version to bump to.
3. "And this line, `colourama`, is not `colorama`. One extra letter.
   Packages exactly like this were caught stealing credentials in 2025.
   DepShield caught it offline, before install."
4. Run the clean sample: green, exit code 0. "That's the whole product:
   check before you install, no internet required."

## Honest limitations

- Only **pinned** versions can be vulnerability-checked; ranges are reported
  as unverifiable.
- The OSV snapshot is only as fresh as your last `fetch_data.py` run.
- Typosquat detection is a heuristic (edit distance). It will miss clever
  names and may flag rare legitimate lookalikes; it suggests, never blocks.
- npm version-range matching uses simplified semver; full npm range
  semantics are on the roadmap.
- Duplicate advisories (the same GHSA indexed under multiple affected
  entries, or a GHSA + its PYSEC mirror) are merged by advisory ID and by
  identical summary text, with folded IDs shown as aliases. Summary-based
  merging is a heuristic — without per-record CVE aliases it can, in rare
  cases, fold two genuinely distinct advisories that share a summary.

## Roadmap

- [ ] Lockfile support (`package-lock.json`, `poetry.lock`, `Pipfile.lock`)
- [ ] Full npm semver ranges
- [ ] Severity scoring (CVSS) in the report
- [ ] `depshield fix` — rewrite the manifest with safe versions
- [ ] GitHub Action wrapper

## License

MIT. Vulnerability data © the OSV project and its source databases
(GHSA, PyPI Advisory Database, etc.) under their respective licenses.
