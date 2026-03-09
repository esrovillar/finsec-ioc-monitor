"""
CLI Dashboard — Rich terminal UI for IOC monitoring status.
Run: python -m src.core.dashboard
"""

import click
from datetime import datetime
from pathlib import Path

import yaml

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
except ImportError:
    raise SystemExit("Missing 'rich' library. Install with: pip install rich")

from .database import IOCDatabase


console = Console()


def _load_db(config_path: str) -> IOCDatabase:
    """Load database from config."""
    with open(config_path) as f:
        config = yaml.safe_load(f)
    db_path = config.get("database", {}).get("path", "iocs.db")
    return IOCDatabase(db_path)


def render_stats(db: IOCDatabase):
    """Render summary statistics panel."""
    stats = db.get_stats()

    total = Text(str(stats["total_iocs"]), style="bold cyan")
    financial = Text(str(stats["financial_iocs"]), style="bold red")
    last_24h = Text(str(stats["last_24h"]), style="bold green")

    stats_text = Text()
    stats_text.append("Total IOCs: ", style="bold")
    stats_text.append(total)
    stats_text.append("  │  Financial: ", style="bold")
    stats_text.append(financial)
    stats_text.append("  │  Last 24h: ", style="bold")
    stats_text.append(last_24h)

    console.print(Panel(stats_text, title="📊 IOC Summary", border_style="blue"))


def render_recent_iocs(db: IOCDatabase, limit: int = 20):
    """Render table of recent IOCs."""
    cursor = db.conn.execute(
        """SELECT value, ioc_type, source, category, confidence,
                  is_financial, description, created_at
           FROM iocs ORDER BY created_at DESC LIMIT ?""",
        (limit,)
    )
    rows = cursor.fetchall()

    table = Table(
        title="🕐 Recent IOCs",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold magenta",
    )
    table.add_column("IOC", style="cyan", max_width=45, no_wrap=True)
    table.add_column("Type", style="white", width=10)
    table.add_column("Source", style="yellow", width=14)
    table.add_column("Category", style="white", width=16)
    table.add_column("Conf", justify="right", width=5)
    table.add_column("Fin", justify="center", width=4)
    table.add_column("Added", style="dim", width=16)

    for row in rows:
        conf = row[4]
        conf_style = "green" if conf >= 80 else ("yellow" if conf >= 50 else "red")
        fin_marker = "🏦" if row[5] else ""

        table.add_row(
            row[0][:45],
            row[1],
            row[2],
            row[3],
            Text(str(conf), style=conf_style),
            fin_marker,
            row[7][:16] if row[7] else "",
        )

    console.print(table)


def render_financial_threats(db: IOCDatabase, limit: int = 20):
    """Render table of financial sector threats."""
    threats = db.get_financial_threats(limit)

    table = Table(
        title="🏦 Financial Sector Threats",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold red",
    )
    table.add_column("IOC", style="cyan", max_width=45, no_wrap=True)
    table.add_column("Type", style="white", width=10)
    table.add_column("Source", style="yellow", width=14)
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Description", style="dim", max_width=40)

    for t in threats:
        conf = t.get("confidence", 0)
        conf_style = "green" if conf >= 80 else ("yellow" if conf >= 50 else "red")

        table.add_row(
            t["value"][:45],
            t["ioc_type"],
            t["source"],
            Text(str(conf), style=conf_style),
            (t.get("description") or "")[:40],
        )

    console.print(table)


def render_feed_runs(db: IOCDatabase, limit: int = 15):
    """Render feed run history."""
    cursor = db.conn.execute(
        """SELECT feed_name, run_at, iocs_fetched, iocs_new,
                  duration_seconds, errors
           FROM feed_runs ORDER BY run_at DESC LIMIT ?""",
        (limit,)
    )
    rows = cursor.fetchall()

    table = Table(
        title="📡 Feed Run History",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold green",
    )
    table.add_column("Feed", style="yellow", width=16)
    table.add_column("Run At", style="dim", width=19)
    table.add_column("Fetched", justify="right", width=8)
    table.add_column("New", justify="right", width=6)
    table.add_column("Duration", justify="right", width=8)
    table.add_column("Status", width=12)

    for row in rows:
        duration = f"{row[4]:.1f}s" if row[4] is not None else "-"
        status = Text("✅ OK", style="green") if not row[5] else Text("❌ Error", style="red")

        table.add_row(
            row[0],
            row[1][:19] if row[1] else "",
            str(row[2]),
            str(row[3]),
            duration,
            status,
        )

    console.print(table)


@click.command()
@click.option("--config", "-c", default="config/config.yaml", help="Config file path")
def main(config):
    """🏦 FinSec IOC Monitor — CLI Dashboard"""
    config_path = Path(config)
    if not config_path.exists():
        console.print(f"[red]❌ Config file not found: {config}[/red]")
        return

    db = _load_db(str(config_path))

    console.print()
    console.print(
        Panel(
            "[bold cyan]🏦 FinSec IOC Monitor — Dashboard[/bold cyan]",
            border_style="blue",
        )
    )
    console.print()

    try:
        render_stats(db)
        console.print()
        render_recent_iocs(db)
        console.print()
        render_financial_threats(db)
        console.print()
        render_feed_runs(db)
        console.print()
    finally:
        db.close()


if __name__ == "__main__":
    main()
