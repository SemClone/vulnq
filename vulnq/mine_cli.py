"""Command-line interface for mining reference snapshots.

Shipped as a separate ``vulnq-mine`` entry point rather than a subcommand of
``vulnq``. Mining is an operational job run once for a fleet, not something a
``vulnq`` user types, and keeping it separate leaves the released
``vulnq <identifier>`` invocation untouched for callers that shell out to it.

Scheduling, credentials, the publishing target, and retention are deployment
policy and deliberately live outside this tool.
"""

import sys
from datetime import datetime
from typing import Optional

import click
from rich.console import Console

from . import __version__
from .enrichment import mine_epss, mine_kev, write_snapshot

console = Console()


def _report(snapshot_source: str, version: Optional[str], count: int, path: str) -> None:
    """Print a one-line summary of a written snapshot.

    Args:
        snapshot_source: Snapshot source identifier
        version: Catalog version or score date
        count: Number of records written
        path: Path the snapshot was written to
    """
    console.print(
        f"[green]{snapshot_source}[/green] version=[cyan]{version or 'unknown'}[/cyan] "
        f"records=[cyan]{count}[/cyan] -> {path}"
    )


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Mine vulnerability reference snapshots for later enrichment."""


@main.command()
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(file_okay=True, dir_okay=True),
    help="Output file, or directory to write cisa-kev.json.gz into",
)
@click.option("--timeout", default=60, show_default=True, help="HTTP timeout in seconds")
def kev(out: str, timeout: int) -> None:
    """Fetch the CISA KEV catalog and write a snapshot."""
    try:
        snapshot = mine_kev(timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        console.print(f"[red]Failed to mine CISA KEV:[/red] {exc}")
        sys.exit(1)

    path = write_snapshot(snapshot, out)
    _report(snapshot.source, snapshot.version, snapshot.count, path)


@main.command()
@click.option(
    "--out",
    "-o",
    required=True,
    type=click.Path(file_okay=True, dir_okay=True),
    help="Output file, or directory to write first-epss.json.gz into",
)
@click.option("--date", "score_date", help="Score date to fetch (YYYY-MM-DD), defaults to today")
@click.option("--timeout", default=120, show_default=True, help="HTTP timeout in seconds")
def epss(out: str, score_date: Optional[str], timeout: int) -> None:
    """Fetch the daily FIRST EPSS scores and write a snapshot."""
    parsed = None
    if score_date:
        try:
            parsed = datetime.strptime(score_date, "%Y-%m-%d").date()
        except ValueError:
            console.print(f"[red]Invalid date:[/red] {score_date} (expected YYYY-MM-DD)")
            sys.exit(1)

    try:
        snapshot = mine_epss(score_date=parsed, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        console.print(f"[red]Failed to mine FIRST EPSS:[/red] {exc}")
        sys.exit(1)

    path = write_snapshot(snapshot, out)
    _report(snapshot.source, snapshot.version, snapshot.count, path)


if __name__ == "__main__":
    main()
