# CLAUDE.md — FinSec IOC Monitor

## About
Financial sector IOC monitoring — aggregates threat feeds (FeodoTracker, ThreatFox, URLhaus), stores in SQLite, provides CLI for querying and alerting.

## Architecture
- `src/feeds/` — Feed parsers: FeodoTracker (C2 IPs), ThreatFox (IOCs), URLhaus (malicious URLs)
- `src/core/` — Database (SQLite), Monitor (orchestration)
- Config in YAML

## Running
```bash
python -m src.core.monitor
```

## Key Details
- Feeds are financial-sector focused
- IOC types: IP, domain, URL, hash
- SQLite storage with deduplication
- ~1,171 IOCs from initial feed pull
