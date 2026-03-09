"""
Base class for all IOC feeds.
Every feed must implement fetch() and parse().
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from enum import Enum


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    SSL_FINGERPRINT = "ssl_fingerprint"


class ThreatCategory(Enum):
    BANKING_TROJAN = "banking_trojan"
    RANSOMWARE = "ransomware"
    APT = "apt"
    PHISHING = "phishing"
    C2 = "c2"
    MALWARE = "malware"
    CREDENTIAL_THEFT = "credential_theft"
    FRAUD = "fraud"
    GENERAL = "general"


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""
    value: str
    ioc_type: IOCType
    source: str
    category: ThreatCategory = ThreatCategory.GENERAL
    confidence: int = 50  # 0-100
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitre_ttps: List[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    @property
    def is_financial_threat(self) -> bool:
        """Check if this IOC is relevant to financial sector."""
        financial_tags = {
            "banking", "financial", "bank", "credit", "payment",
            "swift", "atm", "pos", "fraud", "carding",
            "emotet", "trickbot", "dridex", "qakbot", "icedid",
            "zloader", "ursnif", "gozi", "zeus", "citadel"
        }
        ioc_tags = {t.lower() for t in self.tags}
        ioc_tags.add(self.description.lower())
        return (
            self.category == ThreatCategory.BANKING_TROJAN
            or bool(ioc_tags & financial_tags)
        )


class BaseFeed(ABC):
    """Abstract base class for IOC feeds."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.name = self.__class__.__name__

    @abstractmethod
    def fetch(self) -> dict:
        """Fetch raw data from the feed source."""
        pass

    @abstractmethod
    def parse(self, raw_data: dict) -> List[IOC]:
        """Parse raw data into standardized IOC objects."""
        pass

    def collect(self) -> List[IOC]:
        """Fetch and parse IOCs from this feed."""
        if not self.enabled:
            return []
        raw = self.fetch()
        return self.parse(raw)
