"""
Main orchestrator — collects IOCs from all feeds, stores them,
runs matching against watchlist, and triggers alerts.
"""

import time
import logging
import yaml
import click
from pathlib import Path
from datetime import datetime
from typing import List, Dict

from .database import IOCDatabase
from ..feeds.base import IOC
from ..feeds.feodo import FeodoFeed
from ..feeds.threatfox import ThreatFoxFeed
from ..feeds.urlhaus import URLhausFeed
from ..feeds.otx import OTXFeed
from ..alerting.telegram import TelegramAlerter
from ..enrichment.geoip import GeoIPEnricher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("finsec-monitor")


FEED_CLASSES = {
    "feodo": FeodoFeed,
    "threatfox": ThreatFoxFeed,
    "urlhaus": URLhausFeed,
    "otx": OTXFeed,
}


class IOCMonitor:
    """Main IOC monitoring engine."""

    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.db = IOCDatabase(self.config.get("database", {}).get("path", "iocs.db"))
        self.feeds = self._init_feeds()
        self.watchlist = self.config.get("watchlist", {})
        self.telegram = TelegramAlerter(
            self.config.get("alerting", {}).get("telegram", {})
        )
        self.geoip = GeoIPEnricher(
            self.config.get("enrichment", {}).get("geoip", {})
        )

    def _load_config(self, config_path: str) -> dict:
        """Load YAML configuration."""
        with open(config_path) as f:
            return yaml.safe_load(f)

    def _init_feeds(self) -> list:
        """Initialize configured feeds."""
        feeds = []
        feed_config = self.config.get("feeds", {})

        for feed_name, feed_cls in FEED_CLASSES.items():
            cfg = feed_config.get(feed_name, {})
            if cfg.get("enabled", True):
                feeds.append(feed_cls(cfg))
                logger.info(f"Initialized feed: {feed_name}")
            else:
                logger.info(f"Feed disabled: {feed_name}")

        return feeds

    def collect_all(self) -> Dict[str, List[IOC]]:
        """Collect IOCs from all enabled feeds."""
        results = {}

        for feed in self.feeds:
            start = time.time()
            try:
                logger.info(f"Collecting from {feed.name}...")
                iocs = feed.collect()
                duration = time.time() - start

                # Store in database
                total, new = self.db.bulk_upsert(iocs)
                self.db.log_feed_run(feed.name, total, new, duration)

                # GeoIP enrichment for IP-based IOCs
                iocs = self.geoip.enrich_iocs(iocs)

                results[feed.name] = iocs
                logger.info(
                    f"  {feed.name}: {total} IOCs ({new} new) in {duration:.1f}s"
                )

            except Exception as e:
                duration = time.time() - start
                self.db.log_feed_run(feed.name, 0, 0, duration, str(e))
                logger.error(f"  {feed.name} failed: {e}")
                results[feed.name] = []

        return results

    def match_watchlist(self, iocs: Dict[str, List[IOC]]) -> List[dict]:
        """Match collected IOCs against the watchlist."""
        matches = []
        watch_ips = set(self.watchlist.get("ips", []))
        watch_domains = set(self.watchlist.get("domains", []))

        for feed_name, feed_iocs in iocs.items():
            for ioc in feed_iocs:
                # IP matching
                if ioc.value in watch_ips:
                    matches.append({
                        "ioc": ioc,
                        "watchlist_entry": ioc.value,
                        "match_type": "exact_ip"
                    })

                # Domain matching
                for domain in watch_domains:
                    if domain.startswith("*."):
                        # Wildcard match
                        if ioc.value.endswith(domain[1:]):
                            matches.append({
                                "ioc": ioc,
                                "watchlist_entry": domain,
                                "match_type": "wildcard_domain"
                            })
                    elif ioc.value == domain:
                        matches.append({
                            "ioc": ioc,
                            "watchlist_entry": domain,
                            "match_type": "exact_domain"
                        })

        return matches

    def get_financial_summary(self, iocs: Dict[str, List[IOC]]) -> dict:
        """Generate a summary focused on financial sector threats."""
        all_iocs = [ioc for feed_iocs in iocs.values() for ioc in feed_iocs]
        financial = [ioc for ioc in all_iocs if ioc.is_financial_threat]

        return {
            "total_iocs": len(all_iocs),
            "financial_iocs": len(financial),
            "by_category": {},
            "by_malware": {},
            "high_confidence": [ioc for ioc in financial if ioc.confidence >= 80],
        }

    def run_once(self) -> dict:
        """Single scan: collect, match, and report."""
        logger.info("=" * 60)
        logger.info("Starting IOC collection scan...")
        logger.info("=" * 60)

        # Collect
        iocs = self.collect_all()

        # Match
        matches = self.match_watchlist(iocs)
        if matches:
            logger.warning(f"⚠️  WATCHLIST MATCHES FOUND: {len(matches)}")
            for m in matches:
                logger.warning(
                    f"  MATCH: {m['ioc'].value} ({m['ioc'].source}) "
                    f"→ {m['watchlist_entry']} ({m['match_type']})"
                )
            # Telegram alerts for watchlist matches
            if self.telegram.enabled:
                sent = self.telegram.alert_batch_matches(matches)
                logger.info(f"  Sent {sent} Telegram watchlist alerts")

        # Telegram alerts for high-confidence financial IOCs
        all_iocs = [ioc for feed_iocs in iocs.values() for ioc in feed_iocs]
        financial_iocs = [ioc for ioc in all_iocs if ioc.is_financial_threat]
        if self.telegram.enabled and financial_iocs:
            sent = self.telegram.alert_financial_batch(financial_iocs)
            logger.info(f"  Sent {sent} Telegram financial IOC alerts")

        # Stats
        stats = self.db.get_stats()
        logger.info(f"\nDatabase stats:")
        logger.info(f"  Total IOCs: {stats['total_iocs']}")
        logger.info(f"  Financial: {stats['financial_iocs']}")
        logger.info(f"  Last 24h: {stats['last_24h']}")
        logger.info(f"  Sources: {stats['sources']}")

        # Telegram scan summary
        if self.telegram.enabled:
            self.telegram.send_scan_summary(
                stats, len(matches), len(financial_iocs)
            )

        return {
            "iocs": iocs,
            "matches": matches,
            "stats": stats,
        }


@click.command()
@click.option("--config", "-c", default="config/config.yaml", help="Config file path")
@click.option("--scan-once", is_flag=True, help="Run a single scan and exit")
@click.option("--stats", is_flag=True, help="Show database stats and exit")
def main(config, scan_once, stats):
    """🏦 FinSec IOC Monitor — Financial Sector Threat Intelligence"""

    config_path = Path(config)
    if not config_path.exists():
        click.echo(f"❌ Config file not found: {config}")
        click.echo("Copy config/config.example.yaml to config/config.yaml")
        return

    monitor = IOCMonitor(str(config_path))

    if stats:
        db_stats = monitor.db.get_stats()
        click.echo("\n🏦 FinSec IOC Monitor — Database Stats\n")
        click.echo(f"  Total IOCs:     {db_stats['total_iocs']}")
        click.echo(f"  Financial IOCs: {db_stats['financial_iocs']}")
        click.echo(f"  Last 24h:       {db_stats['last_24h']}")
        click.echo(f"\n  By source:")
        for source, count in db_stats.get("sources", {}).items():
            click.echo(f"    {source}: {count}")
        click.echo(f"\n  By category:")
        for cat, count in db_stats.get("categories", {}).items():
            click.echo(f"    {cat}: {count}")
        return

    if scan_once:
        monitor.run_once()
    else:
        # Continuous monitoring
        interval = monitor.config.get("schedule", {}).get("interval_minutes", 30)
        click.echo(f"🏦 Starting continuous monitoring (every {interval}m)...")
        click.echo("Press Ctrl+C to stop.\n")

        while True:
            try:
                monitor.run_once()
                logger.info(f"\nNext scan in {interval} minutes...\n")
                time.sleep(interval * 60)
            except KeyboardInterrupt:
                logger.info("\nStopping monitor...")
                break

    monitor.db.close()


if __name__ == "__main__":
    main()
