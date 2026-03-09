"""
SQLite-based IOC storage.
Handles deduplication, querying, and statistics.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from ..feeds.base import IOC, IOCType, ThreatCategory


class IOCDatabase:
    """SQLite database for IOC storage and querying."""

    def __init__(self, db_path: str = "iocs.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        """Initialize database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                confidence INTEGER DEFAULT 50,
                first_seen TEXT,
                last_seen TEXT,
                description TEXT,
                tags TEXT DEFAULT '[]',
                mitre_ttps TEXT DEFAULT '[]',
                is_financial INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                UNIQUE(value, source)
            );

            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_ioc_source ON iocs(source);
            CREATE INDEX IF NOT EXISTS idx_ioc_category ON iocs(category);
            CREATE INDEX IF NOT EXISTS idx_ioc_financial ON iocs(is_financial);
            CREATE INDEX IF NOT EXISTS idx_ioc_created ON iocs(created_at);

            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                watchlist_entry TEXT NOT NULL,
                match_type TEXT NOT NULL,
                matched_at TEXT DEFAULT (datetime('now')),
                notified INTEGER DEFAULT 0,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id)
            );

            CREATE TABLE IF NOT EXISTS feed_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT NOT NULL,
                run_at TEXT DEFAULT (datetime('now')),
                iocs_fetched INTEGER DEFAULT 0,
                iocs_new INTEGER DEFAULT 0,
                errors TEXT,
                duration_seconds REAL
            );
        """)
        self.conn.commit()

    def upsert_ioc(self, ioc: IOC) -> Tuple[int, bool]:
        """
        Insert or update an IOC.
        Returns (id, is_new).
        """
        cursor = self.conn.execute(
            "SELECT id FROM iocs WHERE value = ? AND source = ?",
            (ioc.value, ioc.source)
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            self.conn.execute("""
                UPDATE iocs SET
                    confidence = MAX(confidence, ?),
                    last_seen = ?,
                    description = ?,
                    tags = ?,
                    mitre_ttps = ?,
                    is_financial = ?,
                    updated_at = datetime('now')
                WHERE id = ?
            """, (
                ioc.confidence,
                ioc.last_seen.isoformat() if ioc.last_seen else None,
                ioc.description,
                json.dumps(ioc.tags),
                json.dumps(ioc.mitre_ttps),
                1 if ioc.is_financial_threat else 0,
                existing["id"]
            ))
            self.conn.commit()
            return existing["id"], False
        else:
            # Insert new
            cursor = self.conn.execute("""
                INSERT INTO iocs (value, ioc_type, source, category, confidence,
                                  first_seen, last_seen, description, tags,
                                  mitre_ttps, is_financial)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc.value, ioc.ioc_type.value, ioc.source,
                ioc.category.value, ioc.confidence,
                ioc.first_seen.isoformat() if ioc.first_seen else None,
                ioc.last_seen.isoformat() if ioc.last_seen else None,
                ioc.description, json.dumps(ioc.tags),
                json.dumps(ioc.mitre_ttps),
                1 if ioc.is_financial_threat else 0
            ))
            self.conn.commit()
            return cursor.lastrowid, True

    def bulk_upsert(self, iocs: List[IOC]) -> Tuple[int, int]:
        """
        Bulk insert/update IOCs.
        Returns (total_processed, new_count).
        """
        new_count = 0
        for ioc in iocs:
            _, is_new = self.upsert_ioc(ioc)
            if is_new:
                new_count += 1
        return len(iocs), new_count

    def search(self, value: str) -> List[dict]:
        """Search IOCs by value (partial match)."""
        cursor = self.conn.execute(
            "SELECT * FROM iocs WHERE value LIKE ? ORDER BY confidence DESC",
            (f"%{value}%",)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_financial_threats(self, limit: int = 50) -> List[dict]:
        """Get IOCs flagged as financial sector threats."""
        cursor = self.conn.execute(
            """SELECT * FROM iocs WHERE is_financial = 1
               ORDER BY created_at DESC LIMIT ?""",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        """Get database statistics."""
        stats = {}
        stats["total_iocs"] = self.conn.execute(
            "SELECT COUNT(*) FROM iocs"
        ).fetchone()[0]
        stats["financial_iocs"] = self.conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE is_financial = 1"
        ).fetchone()[0]
        stats["sources"] = {}
        for row in self.conn.execute(
            "SELECT source, COUNT(*) as cnt FROM iocs GROUP BY source"
        ):
            stats["sources"][row[0]] = row[1]
        stats["categories"] = {}
        for row in self.conn.execute(
            "SELECT category, COUNT(*) as cnt FROM iocs GROUP BY category"
        ):
            stats["categories"][row[0]] = row[1]
        stats["last_24h"] = self.conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE created_at > datetime('now', '-1 day')"
        ).fetchone()[0]
        return stats

    def log_feed_run(self, feed_name: str, fetched: int, new: int,
                     duration: float, error: str = None):
        """Log a feed collection run."""
        self.conn.execute("""
            INSERT INTO feed_runs (feed_name, iocs_fetched, iocs_new,
                                   duration_seconds, errors)
            VALUES (?, ?, ?, ?, ?)
        """, (feed_name, fetched, new, duration, error))
        self.conn.commit()

    def close(self):
        """Close database connection."""
        self.conn.close()
