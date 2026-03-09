"""
Feodo Tracker Feed — Banking Trojan C2 Servers
https://feodotracker.abuse.ch/

Tracks C2 infrastructure for banking trojans:
Emotet, Dridex, TrickBot, QakBot, IcedID, etc.

No API key required.
"""

import requests
from datetime import datetime
from typing import List

from .base import BaseFeed, IOC, IOCType, ThreatCategory


# Malware family to category mapping
BANKING_FAMILIES = {
    "emotet", "dridex", "trickbot", "qakbot", "icedid",
    "zloader", "pikabot", "bumblebee", "ursnif", "gozi"
}


class FeodoFeed(BaseFeed):
    """Feodo Tracker — Banking trojan C2 server feed."""

    CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = "FeodoTracker"

    def fetch(self) -> dict:
        """Fetch latest C2 server list from Feodo Tracker (CSV format)."""
        response = requests.get(self.CSV_URL, timeout=30)
        response.raise_for_status()
        # Parse CSV into list of dicts
        lines = [l.strip() for l in response.text.split('\n')
                 if l.strip() and not l.startswith('#')]
        entries = []
        for line in lines:
            parts = line.split(',')
            if len(parts) >= 1:
                entries.append({
                    "ip_address": parts[0].strip('"'),
                    "port": parts[1].strip('"') if len(parts) > 1 else None,
                    "status": "listed",
                    "malware": parts[4].strip('"') if len(parts) > 4 else "unknown",
                    "first_seen": parts[2].strip('"') if len(parts) > 2 else None,
                    "last_online": parts[3].strip('"') if len(parts) > 3 else None,
                })
        return {"data": entries}

    def parse(self, raw_data: dict) -> List[IOC]:
        """Parse Feodo Tracker data into IOC objects."""
        iocs = []

        for entry in raw_data.get("data", []):
            ip = entry.get("ip_address", "").strip()
            if not ip:
                continue

            port = entry.get("port")
            malware = entry.get("malware", "unknown").lower()
            first_seen = entry.get("first_seen")
            last_online = entry.get("last_online")
            status = entry.get("status", "")

            # Parse dates
            fs = None
            ls = None
            try:
                if first_seen:
                    fs = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
                if last_online:
                    ls = datetime.strptime(last_online, "%Y-%m-%d")
            except (ValueError, TypeError):
                pass

            # Determine category
            category = ThreatCategory.BANKING_TROJAN if malware in BANKING_FAMILIES else ThreatCategory.C2

            # Build tags
            tags = ["c2", "botnet", malware]
            if malware in BANKING_FAMILIES:
                tags.extend(["banking", "financial"])

            # Confidence based on status
            confidence = 90 if status == "online" else 70

            ioc = IOC(
                value=f"{ip}:{port}" if port else ip,
                ioc_type=IOCType.IP,
                source=self.name,
                category=category,
                confidence=confidence,
                first_seen=fs,
                last_seen=ls,
                description=f"{malware.upper()} C2 server ({status})",
                tags=tags,
                mitre_ttps=["T1071.001", "T1573"],  # Application Layer Protocol, Encrypted Channel
                raw_data=entry
            )
            iocs.append(ioc)

        return iocs
