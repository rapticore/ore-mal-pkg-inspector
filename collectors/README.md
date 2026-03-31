# Threat Data Collectors

This module collects malicious-package intelligence from external sources, stores normalized raw JSON in `collectors/raw-data/`, and builds per-ecosystem SQLite databases in `collectors/final-data/` for the scanner.

## Source Tiers

| Source | Tier | Default | Notes |
|--------|------|---------|-------|
| `openssf` | core | yes | Primary malicious-package feed from the OpenSSF `malicious-packages` repository |
| `osv` | core | yes | Bulk OSV feed filtered to `MAL-` malware records |
| `phylum` | experimental | no | Heuristic extraction from Phylum blog content |
| `socketdev` | disabled | no | Placeholder only; not part of the default collection path |

Default refreshes use only the core sources. Include experimental data with `--include-experimental`.

## Outputs

### Raw source data

Files are written to `collectors/raw-data/`:

- `openssf.json`
- `osv.json`
- `phylum.json`
- `socketdev.json`

Each file contains:

- `source`
- `source_tier`
- `collected_at`
- `total_packages`
- `ecosystems`
- `packages`
- optional `error`

### Unified scan databases

The scanner consumes SQLite databases in `collectors/final-data/`:

- `unified_npm.db`
- `unified_pypi.db`
- `unified_rubygems.db`
- `unified_go.db`
- `unified_maven.db`
- `unified_cargo.db`

Each database also stores metadata describing:

- `data_status` as `complete`, `partial`, or `failed`
- `sources_used`
- `experimental_sources_used`
- `failed_sources`
- `last_successful_collect`

## Common Commands

Run the default core collection and rebuild databases:

```bash
python3 collectors/orchestrator.py
```

Force inclusion of experimental sources:

```bash
python3 collectors/orchestrator.py --include-experimental
```

Run only selected sources:

```bash
python3 collectors/orchestrator.py --sources openssf osv
```

Collector logging:

```bash
python3 collectors/orchestrator.py --verbose
python3 collectors/orchestrator.py --debug
```

## Data Flow

```text
external sources
  -> collectors/raw-data/*.json
  -> build_unified_index.py
  -> collectors/final-data/unified_*.db
  -> orewatch
```

## Design Notes

- The orchestrator treats missing metadata as stale data and forces a rebuild.
- `--latest-data` in the scanner always recollects and rebuilds instead of trusting a partial existing database set.
- Experimental data is opt-in and tracked separately in database metadata and scan reports.
- Socket.dev is intentionally excluded from the default path until a usable bulk collection strategy exists.

## Troubleshooting

If a source fails, inspect the raw JSON file in `collectors/raw-data/` for its `error` field and rerun with `--debug`.

If databases exist but the scanner still refreshes them, inspect the metadata with the orchestrator. Missing `data_status`, `sources_used`, or `last_successful_collect` means the databases were built by an older format and need a rebuild.
