"""
AlienVault OTX Feed — Open Threat Exchange
https://otx.alienvault.com/

Pulls recent pulses tagged with banking/financial/ransomware/apt keywords.
Free tier works without API key for public pulses.
"""

import requests
from datetime import datetime, timedelta
from typing import List

from .base import BaseFeed, IOC, IOCType, ThreatCategory


# OTX indicator type to our IOCType mapping
OTX_TYPE_MAP = {
    "IPv4": IOCType.IP,
    "IPv6": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "FileHash-MD5": IOCType.HASH_MD5,
    "FileHash-SHA1": IOCType.HASH_SHA1,
    "FileHash-SHA256": IOCType.HASH_SHA256,
    "email": IOCType.EMAIL,
    "SSLCertFingerprint": IOCType.SSL_FINGERPRINT,
}

# Tags that indicate financial sector relevance
FINANCIAL_TAGS = {
    "banking", "financial", "bank", "credit", "payment", "swift",
    "atm", "pos", "fraud", "carding", "emotet", "trickbot",
    "dridex", "qakbot", "icedid", "zloader", "pikabot",
    "ursnif", "gozi", "zeus", "citadel",
}

# Pulse tags we're interested in
RELEVANT_TAGS = FINANCIAL_TAGS | {
    "ransomware", "apt", "malware", "c2", "botnet",
    "phishing", "credential", "trojan",
}

TAG_TO_CATEGORY = {
    "banking": ThreatCategory.BANKING_TROJAN,
    "financial": ThreatCategory.BANKING_TROJAN,
    "ransomware": ThreatCategory.RANSOMWARE,
    "apt": ThreatCategory.APT,
    "phishing": ThreatCategory.PHISHING,
    "c2": ThreatCategory.C2,
    "botnet": ThreatCategory.C2,
    "credential": ThreatCategory.CREDENTIAL_THEFT,
    "fraud": ThreatCategory.FRAUD,
}


class OTXFeed(BaseFeed):
    """AlienVault OTX — Open Threat Exchange public pulses."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = "AlienVaultOTX"
        self.api_key = config.get("api_key", "")
        self.pulse_tags = config.get("pulse_tags", [
            "banking", "financial", "ransomware", "apt"
        ])
        self.limit = config.get("limit", 10)
        self.days_back = config.get("days_back", 1)

    def _headers(self) -> dict:
        """Build request headers."""
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    def fetch(self) -> dict:
        """Fetch recent pulses from OTX matching relevant tags."""
        all_indicators = []
        since = (datetime.utcnow() - timedelta(days=self.days_back)).isoformat()

        for tag in self.pulse_tags:
            try:
                url = f"{self.BASE_URL}/search/pulses"
                params = {
                    "q": tag,
                    "sort": "modified",
                    "limit": self.limit,
                }
                response = requests.get(
                    url, params=params,
                    headers=self._headers(),
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()

                for pulse in data.get("results", []):
                    pulse_name = pulse.get("name", "")
                    pulse_tags = [t.lower() for t in pulse.get("tags", [])]
                    pulse_created = pulse.get("created", "")
                    pulse_desc = pulse.get("description", "")
                    pulse_ttp = []
                    for attack in pulse.get("attack_ids", []):
                        if attack.get("id"):
                            pulse_ttp.append(attack["id"])

                    # Fetch indicators for this pulse
                    pulse_id = pulse.get("id")
                    if not pulse_id:
                        continue

                    try:
                        ind_url = f"{self.BASE_URL}/pulses/{pulse_id}/indicators"
                        ind_params = {"limit": 100}
                        ind_response = requests.get(
                            ind_url, params=ind_params,
                            headers=self._headers(),
                            timeout=30
                        )
                        ind_response.raise_for_status()
                        ind_data = ind_response.json()

                        for ind in ind_data.get("results", []):
                            ind["_pulse_name"] = pulse_name
                            ind["_pulse_tags"] = pulse_tags
                            ind["_pulse_created"] = pulse_created
                            ind["_pulse_description"] = pulse_desc
                            ind["_pulse_ttps"] = pulse_ttp
                            all_indicators.append(ind)

                    except requests.RequestException:
                        continue

            except requests.RequestException:
                continue

        return {"indicators": all_indicators}

    def parse(self, raw_data: dict) -> List[IOC]:
        """Parse OTX indicators into IOC objects."""
        iocs = []
        seen = set()  # deduplicate within this fetch

        for entry in raw_data.get("indicators", []):
            indicator = entry.get("indicator", "").strip()
            ind_type = entry.get("type", "")

            if not indicator or ind_type not in OTX_TYPE_MAP:
                continue

            # Deduplicate
            dedup_key = (indicator, ind_type)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            ioc_type = OTX_TYPE_MAP[ind_type]

            # Determine category from pulse tags
            pulse_tags = entry.get("_pulse_tags", [])
            category = ThreatCategory.GENERAL
            is_financial = False
            for tag in pulse_tags:
                tag_lower = tag.lower()
                if tag_lower in FINANCIAL_TAGS:
                    is_financial = True
                if tag_lower in TAG_TO_CATEGORY:
                    category = TAG_TO_CATEGORY[tag_lower]

            # Financial banking trojans override
            if is_financial and category == ThreatCategory.GENERAL:
                category = ThreatCategory.BANKING_TROJAN

            # Build tags list
            tags = list(set(pulse_tags) & RELEVANT_TAGS)
            if is_financial and "financial" not in tags:
                tags.append("financial")

            # Parse dates
            created = entry.get("_pulse_created")
            fs = None
            try:
                if created:
                    fs = datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")
            except (ValueError, TypeError):
                pass

            pulse_name = entry.get("_pulse_name", "")
            pulse_ttps = entry.get("_pulse_ttps", [])
            title = entry.get("title", "") or entry.get("description", "")
            description = f"OTX Pulse: {pulse_name}" + (f" — {title}" if title else "")

            ioc = IOC(
                value=indicator,
                ioc_type=ioc_type,
                source=self.name,
                category=category,
                confidence=70,  # OTX community intelligence
                first_seen=fs,
                description=description[:500],
                tags=tags,
                mitre_ttps=pulse_ttps,
                raw_data={
                    "pulse_name": pulse_name,
                    "pulse_tags": pulse_tags,
                    "indicator_type": ind_type,
                }
            )
            iocs.append(ioc)

        return iocs
