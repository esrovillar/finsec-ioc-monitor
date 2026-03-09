"""
URLhaus Feed — Malicious URL database by abuse.ch
https://urlhaus.abuse.ch/

Tracks URLs distributing malware. Free, no API key required.
"""

import requests
from datetime import datetime
from typing import List

from .base import BaseFeed, IOC, IOCType, ThreatCategory


class URLhausFeed(BaseFeed):
    """URLhaus — Malicious URL tracking."""

    RECENT_URLS = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
    ONLINE_URLS = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = "URLhaus"
        self.limit = config.get("limit", 100)

    CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def fetch(self) -> dict:
        """Fetch recent malicious URLs."""
        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                data={"limit": str(self.limit)},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError:
            # Fallback to CSV
            response = requests.get(self.CSV_URL, timeout=30)
            response.raise_for_status()
            entries = []
            for line in response.text.split('\n'):
                if line.startswith('#') or not line.strip():
                    continue
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 4:
                    entries.append({
                        "url": parts[2] if len(parts) > 2 else "",
                        "url_status": parts[3] if len(parts) > 3 else "",
                        "date_added": parts[1] if len(parts) > 1 else "",
                        "threat": parts[4] if len(parts) > 4 else "",
                        "tags": (parts[5].split(",") if len(parts) > 5 and parts[5] else []),
                    })
            return {"urls": entries[:self.limit]}

    def parse(self, raw_data: dict) -> List[IOC]:
        """Parse URLhaus response into IOC objects."""
        iocs = []

        for entry in raw_data.get("urls", []):
            url = entry.get("url", "").strip()
            if not url:
                continue

            threat = entry.get("threat", "")
            status = entry.get("url_status", "")
            date_added = entry.get("date_added")
            tags = entry.get("tags", []) or []

            # Parse date
            fs = None
            try:
                if date_added:
                    fs = datetime.strptime(date_added, "%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError):
                pass

            # Determine category
            category = ThreatCategory.MALWARE
            financial_threats = ["emotet", "dridex", "trickbot", "qakbot", "icedid", "zloader"]
            if any(ft in threat.lower() for ft in financial_threats):
                category = ThreatCategory.BANKING_TROJAN
                tags.append("financial")

            # Confidence based on status
            confidence = 85 if status == "online" else 60

            ioc = IOC(
                value=url,
                ioc_type=IOCType.URL,
                source=self.name,
                category=category,
                confidence=confidence,
                first_seen=fs,
                description=f"Malicious URL distributing {threat}" if threat else "Malicious URL",
                tags=tags,
                raw_data=entry
            )
            iocs.append(ioc)

        return iocs
