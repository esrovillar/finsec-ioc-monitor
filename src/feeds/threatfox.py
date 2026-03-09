"""
ThreatFox Feed — IOC sharing platform by abuse.ch
https://threatfox.abuse.ch/

Shares IOCs (IPs, domains, URLs, hashes) associated with malware.
Free API, no key required for basic queries.
"""

import csv
import io
import requests
from datetime import datetime, timedelta
from typing import List

from .base import BaseFeed, IOC, IOCType, ThreatCategory


IOC_TYPE_MAP = {
    "ip:port": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5_hash": IOCType.HASH_MD5,
    "sha256_hash": IOCType.HASH_SHA256,
    "sha1_hash": IOCType.HASH_SHA1,
}

CATEGORY_MAP = {
    "botnet_cc": ThreatCategory.C2,
    "payload_delivery": ThreatCategory.MALWARE,
    "payload": ThreatCategory.MALWARE,
    "c2": ThreatCategory.C2,
}


class ThreatFoxFeed(BaseFeed):
    """ThreatFox — Malware IOC sharing platform."""

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = "ThreatFox"
        self.days_back = config.get("days_back", 1)

    CSV_URL = "https://threatfox.abuse.ch/export/csv/recent/"

    def fetch(self) -> dict:
        """Fetch recent IOCs from ThreatFox API, CSV fallback."""
        try:
            # Try API first
            payload = {"query": "get_iocs", "days": self.days_back}
            response = requests.post(
                self.API_URL, json=payload, timeout=30,
                headers={"Accept": "application/json"}
            )
            response.raise_for_status()
            data = response.json()
            if data.get("query_status") == "ok" and data.get("data"):
                return data
            raise ValueError("API returned no data, falling back to CSV")
        except Exception:
            # Fallback to CSV export
            response = requests.get(self.CSV_URL, timeout=30)
            response.raise_for_status()
            entries = []
            # CSV header: first_seen_utc, ioc_id, ioc_value, ioc_type,
            #   threat_type, fk_malware, malware_alias(variable commas!),
            #   malware_printable, last_seen_utc, confidence_level,
            #   is_compromised, reference, tags, anonymous, reporter
            # Note: malware_alias and tags can contain commas without
            # proper quoting, so we parse from known positions at start/end.
            for line in response.text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = [p.strip().strip('"') for p in line.split('", "')]
                # First field might have leading quote
                if parts:
                    parts[0] = parts[0].lstrip('"').strip()
                if len(parts) < 10:
                    continue

                # Fixed positions from start: 0-4
                first_seen = parts[0]
                ioc_value = parts[2]
                ioc_type = parts[3]
                threat_type = parts[4]
                malware = parts[5]

                # Fixed positions from end: reporter(-1), anonymous(-2),
                # tags(-3?), reference, is_compromised, confidence,
                # last_seen, malware_printable
                # Use last 7 fields from end for reliability
                end = parts[-7:]  # [..., last_seen, confidence, is_compromised, reference, tags, anonymous, reporter]
                # But variable alias length makes this tricky.
                # Safest: confidence is always a number, find it
                confidence = 50
                for p in parts[6:]:
                    if p.isdigit() and 0 <= int(p) <= 100:
                        confidence = int(p)
                        break

                entries.append({
                    "ioc": ioc_value,
                    "ioc_type": ioc_type,
                    "threat_type": threat_type,
                    "malware": malware,
                    "malware_printable": malware,
                    "confidence_level": confidence,
                    "first_seen_utc": first_seen,
                    "tags": [],
                })
            return {"query_status": "ok", "data": entries}

    def parse(self, raw_data: dict) -> List[IOC]:
        """Parse ThreatFox response into IOC objects."""
        iocs = []

        if raw_data.get("query_status") != "ok":
            return iocs

        for entry in raw_data.get("data", []) or []:
            ioc_value = entry.get("ioc", "").strip()
            ioc_type_str = entry.get("ioc_type", "")
            malware = entry.get("malware", "")
            malware_printable = entry.get("malware_printable", malware)
            threat_type = entry.get("threat_type", "")
            confidence_level = entry.get("confidence_level", 50)
            first_seen = entry.get("first_seen_utc")
            last_seen = entry.get("last_seen_utc")
            tags = entry.get("tags", []) or []
            reference = entry.get("reference", "")

            if not ioc_value:
                continue

            # Map IOC type
            ioc_type = IOC_TYPE_MAP.get(ioc_type_str, IOCType.IP)

            # Map category
            category = CATEGORY_MAP.get(threat_type, ThreatCategory.GENERAL)

            # Check if financial threat
            financial_keywords = ["emotet", "trickbot", "dridex", "qakbot", "icedid",
                                  "zloader", "pikabot", "banking", "financial"]
            if any(kw in malware.lower() for kw in financial_keywords):
                category = ThreatCategory.BANKING_TROJAN
                tags.append("financial")

            # Parse dates
            fs = ls = None
            try:
                if first_seen:
                    fs = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S UTC")
                if last_seen:
                    ls = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError):
                pass

            ioc = IOC(
                value=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                category=category,
                confidence=confidence_level,
                first_seen=fs,
                last_seen=ls,
                description=f"{malware_printable} ({threat_type})",
                tags=tags,
                mitre_ttps=entry.get("mitre_attack", []) or [],
                raw_data=entry
            )
            iocs.append(ioc)

        return iocs
