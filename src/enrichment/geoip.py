"""
GeoIP Enrichment — Basic IP geolocation via ip-api.com
Free tier: 45 requests/minute, no API key needed.
http://ip-api.com/docs/api:json

Adds country, ASN, and organization info to IP-based IOCs.
"""

import time
import logging
import ipaddress
import requests
from typing import List, Dict, Optional

from ..feeds.base import IOC, IOCType

logger = logging.getLogger("finsec-monitor.geoip")

# ip-api.com rate limit: 45 req/min
RATE_LIMIT_DELAY = 1.4  # ~43 requests/min, safe margin
BATCH_SIZE = 100  # ip-api.com batch endpoint supports up to 100


class GeoIPEnricher:
    """Enrich IP-based IOCs with geolocation data via ip-api.com."""

    SINGLE_URL = "http://ip-api.com/json/{ip}"
    BATCH_URL = "http://ip-api.com/batch"

    FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,query"

    def __init__(self, config: dict = None):
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.cache: Dict[str, dict] = {}

    def _extract_ip(self, value: str) -> Optional[str]:
        """Extract clean IP address from IOC value (may include port)."""
        # Handle ip:port format
        ip_str = value.split(":")[0].strip()
        try:
            addr = ipaddress.ip_address(ip_str)
            # Skip private/reserved IPs
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                return None
            return str(addr)
        except ValueError:
            return None

    def lookup_single(self, ip: str) -> Optional[dict]:
        """Look up a single IP address."""
        if ip in self.cache:
            return self.cache[ip]

        try:
            response = requests.get(
                self.SINGLE_URL.format(ip=ip),
                params={"fields": self.FIELDS},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                }
                self.cache[ip] = result
                return result
            else:
                logger.debug(f"GeoIP lookup failed for {ip}: {data.get('message')}")
                return None

        except requests.RequestException as e:
            logger.error(f"GeoIP request failed for {ip}: {e}")
            return None

    def lookup_batch(self, ips: List[str]) -> Dict[str, dict]:
        """Look up multiple IPs using the batch endpoint."""
        results = {}

        # Filter out cached and split into batches
        uncached = [ip for ip in ips if ip not in self.cache]
        cached = {ip: self.cache[ip] for ip in ips if ip in self.cache}
        results.update(cached)

        for i in range(0, len(uncached), BATCH_SIZE):
            batch = uncached[i:i + BATCH_SIZE]
            payload = [{"query": ip, "fields": self.FIELDS} for ip in batch]

            try:
                response = requests.post(
                    self.BATCH_URL,
                    json=payload,
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()

                for entry in data:
                    ip = entry.get("query", "")
                    if entry.get("status") == "success":
                        result = {
                            "country": entry.get("country", ""),
                            "country_code": entry.get("countryCode", ""),
                            "region": entry.get("regionName", ""),
                            "city": entry.get("city", ""),
                            "isp": entry.get("isp", ""),
                            "org": entry.get("org", ""),
                            "asn": entry.get("as", ""),
                        }
                        self.cache[ip] = result
                        results[ip] = result

                # Rate limit between batches
                if i + BATCH_SIZE < len(uncached):
                    time.sleep(RATE_LIMIT_DELAY)

            except requests.RequestException as e:
                logger.error(f"GeoIP batch request failed: {e}")

        return results

    def enrich_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """Enrich IP-based IOCs with GeoIP data."""
        if not self.enabled:
            return iocs

        # Collect IPs to look up
        ip_map: Dict[str, List[int]] = {}  # ip -> list of IOC indices
        for idx, ioc in enumerate(iocs):
            if ioc.ioc_type == IOCType.IP:
                ip = self._extract_ip(ioc.value)
                if ip:
                    ip_map.setdefault(ip, []).append(idx)

        if not ip_map:
            return iocs

        logger.info(f"Enriching {len(ip_map)} unique IPs with GeoIP data...")

        # Batch lookup
        geo_results = self.lookup_batch(list(ip_map.keys()))

        # Apply results to IOCs
        enriched_count = 0
        for ip, indices in ip_map.items():
            geo = geo_results.get(ip)
            if not geo:
                continue

            for idx in indices:
                ioc = iocs[idx]
                # Add geo data to raw_data
                ioc.raw_data["geoip"] = geo

                # Add geo tags
                country_code = geo.get("country_code", "")
                if country_code:
                    ioc.tags.append(f"geo:{country_code}")

                asn = geo.get("asn", "")
                if asn:
                    ioc.tags.append(f"asn:{asn.split()[0]}" if " " in asn else f"asn:{asn}")

                # Append to description
                geo_info = f" [📍 {geo.get('country', '')}]"
                if geo.get("org"):
                    geo_info += f" [{geo['org']}]"
                ioc.description += geo_info

                enriched_count += 1

        logger.info(f"Enriched {enriched_count} IOCs with GeoIP data")
        return iocs
