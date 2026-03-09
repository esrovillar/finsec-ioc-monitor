"""
Telegram Bot Alerting — Send alerts via Telegram Bot API
when watchlist matches or high-confidence financial IOCs are detected.

Requires bot_token and chat_id in config.
Create a bot via @BotFather and get chat_id from @userinfobot.
"""

import logging
import requests
from typing import List, Optional

from ..feeds.base import IOC

logger = logging.getLogger("finsec-monitor.telegram")


class TelegramAlerter:
    """Send IOC alerts via Telegram Bot API."""

    API_BASE = "https://api.telegram.org/bot{token}"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", False)
        self.bot_token = config.get("bot_token", "")
        self.chat_id = config.get("chat_id", "")
        self.min_confidence = config.get("min_confidence", 80)

        if self.enabled and (not self.bot_token or not self.chat_id):
            logger.warning("Telegram alerting enabled but bot_token/chat_id not set")
            self.enabled = False

    def _send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send a message via Telegram Bot API."""
        if not self.enabled:
            return False

        url = f"{self.API_BASE.format(token=self.bot_token)}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Telegram send failed: {e}")
            return False

    def _format_ioc_alert(self, ioc: IOC, match_type: str = "",
                          watchlist_entry: str = "") -> str:
        """Format a single IOC into a Telegram alert message."""
        # Header emoji based on severity
        if ioc.confidence >= 90:
            emoji = "🔴"
        elif ioc.confidence >= 70:
            emoji = "🟠"
        else:
            emoji = "🟡"

        lines = [
            f"{emoji} <b>FinSec IOC Alert</b>",
            "",
        ]

        if match_type:
            lines.append(f"⚠️ <b>WATCHLIST MATCH</b> ({match_type})")
            if watchlist_entry:
                lines.append(f"Matched: <code>{watchlist_entry}</code>")
            lines.append("")

        lines.extend([
            f"<b>IOC:</b> <code>{_escape_html(ioc.value)}</code>",
            f"<b>Type:</b> {ioc.ioc_type.value}",
            f"<b>Source:</b> {ioc.source}",
            f"<b>Category:</b> {ioc.category.value}",
            f"<b>Confidence:</b> {ioc.confidence}/100",
        ])

        if ioc.description:
            lines.append(f"<b>Description:</b> {_escape_html(ioc.description[:200])}")

        if ioc.tags:
            tag_str = ", ".join(f"#{t}" for t in ioc.tags[:10])
            lines.append(f"<b>Tags:</b> {_escape_html(tag_str)}")

        if ioc.mitre_ttps:
            ttp_str = ", ".join(ioc.mitre_ttps[:5])
            lines.append(f"<b>MITRE ATT&CK:</b> {_escape_html(ttp_str)}")

        if ioc.first_seen:
            lines.append(f"<b>First Seen:</b> {ioc.first_seen.strftime('%Y-%m-%d %H:%M')}")

        if ioc.is_financial_threat:
            lines.append("")
            lines.append("🏦 <i>Financial Sector Threat</i>")

        return "\n".join(lines)

    def alert_watchlist_match(self, ioc: IOC, match_type: str,
                              watchlist_entry: str) -> bool:
        """Send alert for a watchlist match."""
        msg = self._format_ioc_alert(ioc, match_type, watchlist_entry)
        return self._send_message(msg)

    def alert_financial_ioc(self, ioc: IOC) -> bool:
        """Send alert for a high-confidence financial sector IOC."""
        if ioc.confidence < self.min_confidence:
            return False
        msg = self._format_ioc_alert(ioc)
        return self._send_message(msg)

    def alert_batch_matches(self, matches: List[dict]) -> int:
        """Send alerts for a batch of watchlist matches. Returns count sent."""
        sent = 0
        for match in matches:
            ioc = match["ioc"]
            success = self.alert_watchlist_match(
                ioc, match["match_type"], match["watchlist_entry"]
            )
            if success:
                sent += 1
        return sent

    def alert_financial_batch(self, iocs: List[IOC]) -> int:
        """Send alerts for high-confidence financial IOCs. Returns count sent."""
        sent = 0
        for ioc in iocs:
            if ioc.is_financial_threat and ioc.confidence >= self.min_confidence:
                if self.alert_financial_ioc(ioc):
                    sent += 1
        return sent

    def send_scan_summary(self, stats: dict, matches_count: int,
                          financial_count: int) -> bool:
        """Send a summary after a scan run."""
        lines = [
            "📊 <b>FinSec IOC Monitor — Scan Complete</b>",
            "",
            f"<b>Total IOCs in DB:</b> {stats.get('total_iocs', 0)}",
            f"<b>Financial IOCs:</b> {stats.get('financial_iocs', 0)}",
            f"<b>Last 24h:</b> {stats.get('last_24h', 0)}",
        ]

        if matches_count > 0:
            lines.append(f"\n⚠️ <b>Watchlist Matches:</b> {matches_count}")
        if financial_count > 0:
            lines.append(f"🏦 <b>New Financial Threats:</b> {financial_count}")

        sources = stats.get("sources", {})
        if sources:
            lines.append("\n<b>By Source:</b>")
            for source, count in sources.items():
                lines.append(f"  • {source}: {count}")

        return self._send_message("\n".join(lines))


def _escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
