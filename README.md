# 🏦 FinSec-IOC-Monitor

Real-time Indicator of Compromise (IOC) monitoring tool focused on the financial sector. Aggregates threat intelligence from multiple feeds, correlates IOCs against your infrastructure, and alerts when relevant threats are detected.

## Features

- **Multi-feed aggregation** — AlienVault OTX, AbuseIPDB, MISP, FS-ISAC, and custom feeds
- **Financial sector focus** — Prioritizes threats targeting banking, credit bureaus, and financial infrastructure
- **IOC matching** — Compare live feeds against your watchlist (IPs, domains, hashes, emails)
- **MITRE ATT&CK mapping** — Tags IOCs with relevant TTPs
- **Real-time alerting** — Telegram, Slack, email notifications
- **Dashboard** — CLI and web-based IOC viewer with trend analysis
- **Export** — STIX/TAXII, CSV, JSON formats for SIEM integration

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  IOC Feeds  │────▶│  Aggregator  │────▶│  IOC Store  │
│             │     │  & Parser    │     │  (SQLite)   │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
┌─────────────┐     ┌──────────────┐            │
│  Watchlist  │────▶│   Matcher    │◀───────────┘
│  (your IPs, │     │   Engine     │
│   domains)  │     └──────┬───────┘
└─────────────┘            │
                    ┌──────▼───────┐     ┌─────────────┐
                    │   Enrichment │────▶│   Alerting  │
                    │  (GeoIP,     │     │  (Telegram, │
                    │   Whois,     │     │   Slack,    │
                    │   VirusTotal)│     │   Email)    │
                    └──────────────┘     └─────────────┘
```

## Supported Feeds

| Feed | Type | API Key Required | Financial Focus |
|------|------|-----------------|-----------------|
| AlienVault OTX | OSINT | Free | General + FinSec pulses |
| AbuseIPDB | IP reputation | Free tier | General |
| MISP (public instances) | OSINT | Depends | Configurable |
| URLhaus | Malicious URLs | Free | General |
| ThreatFox | IOCs | Free | General |
| Feodo Tracker | C2 IPs | Free | Banking trojans ✅ |
| SSL Blacklist | SSL certs | Free | General |

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USER/finsec-ioc-monitor.git
cd finsec-ioc-monitor

# Install
pip install -r requirements.txt

# Configure
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys and watchlist

# Run
python -m src.core.monitor --config config/config.yaml

# One-time scan
python -m src.core.monitor --scan-once

# Dashboard
python -m src.core.dashboard
```

## Configuration

```yaml
feeds:
  otx:
    enabled: true
    api_key: "YOUR_OTX_API_KEY"
    pulse_tags: ["banking", "financial", "ransomware", "apt"]
  abuseipdb:
    enabled: true
    api_key: "YOUR_ABUSEIPDB_KEY"
    min_confidence: 80
  feodo:
    enabled: true  # No API key needed
  urlhaus:
    enabled: true  # No API key needed
  threatfox:
    enabled: true  # No API key needed

watchlist:
  ips: ["203.0.113.0/24", "198.51.100.0/24"]  # Your external IP ranges
  domains: ["example-bank.com", "*.example-bank.com"]
  
alerting:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  
schedule:
  interval_minutes: 30  # How often to check feeds
```

## Project Structure

```
finsec-ioc-monitor/
├── src/
│   ├── core/
│   │   ├── monitor.py          # Main orchestrator
│   │   ├── database.py         # SQLite IOC store
│   │   ├── matcher.py          # IOC matching engine
│   │   └── dashboard.py        # CLI/web dashboard
│   ├── feeds/
│   │   ├── base.py             # Abstract feed class
│   │   ├── otx.py              # AlienVault OTX
│   │   ├── abuseipdb.py        # AbuseIPDB
│   │   ├── feodo.py            # Feodo Tracker (banking C2s)
│   │   ├── urlhaus.py          # URLhaus
│   │   └── threatfox.py        # ThreatFox
│   ├── enrichment/
│   │   ├── geoip.py            # GeoIP lookup
│   │   ├── whois.py            # Whois lookup
│   │   └── virustotal.py       # VT enrichment
│   └── alerting/
│       ├── telegram.py         # Telegram alerts
│       ├── slack.py            # Slack alerts
│       └── email.py            # Email alerts
├── config/
│   ├── config.example.yaml     # Example configuration
│   └── mitre_mapping.yaml      # ATT&CK TTP mappings
├── tests/
├── docs/
├── requirements.txt
├── setup.py
└── README.md
```

## Roadmap

- [x] Project structure
- [ ] Core: IOC database (SQLite)
- [ ] Core: Feed aggregator framework
- [ ] Feed: Feodo Tracker (banking trojans)
- [ ] Feed: URLhaus
- [ ] Feed: ThreatFox
- [ ] Feed: AlienVault OTX
- [ ] Feed: AbuseIPDB
- [ ] Core: Matching engine
- [ ] Enrichment: GeoIP
- [ ] Alerting: Telegram
- [ ] Core: CLI dashboard
- [ ] Export: STIX format
- [ ] Web dashboard

## Requirements

- Python 3.9+
- SQLite3
- API keys (optional, for premium feeds)

## Author

**Esteban Rojas Villar** — Senior Cybersecurity Incident Responder
- LinkedIn: [linkedin.com/in/estebanrojas](https://linkedin.com/in/estebanrojas)
- BSides San José (Costa Rica) Founder & Organizer

## License

MIT
