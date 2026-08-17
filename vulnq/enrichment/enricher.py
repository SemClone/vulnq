"""Applies every configured snapshot join to a query result."""

from typing import List, Optional

from ..models import Configuration, QueryResult
from .epss import EPSSReader
from .kev import KEVReader
from .snapshot import SnapshotReader


class Enricher:
    """Holds the configured snapshot readers and applies them to results.

    Readers keep their snapshots resident, so one enricher is built per process
    and reused across every query rather than rebuilt per call.
    """

    def __init__(self, config: Configuration, verbose: bool = False):
        """Initialize the enricher from configuration.

        Args:
            config: Configuration carrying snapshot locations
            verbose: Enable verbose output
        """
        self.readers: List[SnapshotReader] = []

        if config.kev_snapshot:
            self.readers.append(
                KEVReader(
                    config.kev_snapshot,
                    max_age_days=config.snapshot_max_age_days,
                    timeout=config.timeout,
                    verbose=verbose,
                )
            )

        if config.epss_snapshot:
            self.readers.append(
                EPSSReader(
                    config.epss_snapshot,
                    max_age_days=config.snapshot_max_age_days,
                    timeout=config.timeout,
                    verbose=verbose,
                )
            )

    @property
    def enabled(self) -> bool:
        """Return whether any snapshot is configured."""
        return bool(self.readers)

    def enrich(self, result: QueryResult) -> QueryResult:
        """Stamp snapshot facts onto a result and record their provenance.

        Args:
            result: Query result to enrich in place

        Returns:
            The same result, enriched
        """
        for reader in self.readers:
            # apply() contains its own failures; provenance reports them.
            reader.apply(result.vulnerabilities)
            result.enrichment[reader.source] = reader.provenance()

        return result


def build_enricher(config: Configuration, verbose: bool = False) -> Optional[Enricher]:
    """Build an enricher, or None when no snapshot is configured.

    Args:
        config: Configuration carrying snapshot locations
        verbose: Enable verbose output

    Returns:
        An enricher, or None
    """
    enricher = Enricher(config, verbose=verbose)
    return enricher if enricher.enabled else None
