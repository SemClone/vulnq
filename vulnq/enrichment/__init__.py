"""Snapshot-based enrichment for exploitability signals.

KEV and EPSS are static reference files joined on the CVE id, not per-query
sources. They are mined once, published centrally, and read by every worker,
so they live here rather than behind the ``clients`` fan-out interface.
"""

from .enricher import Enricher, build_enricher
from .epss import EPSS_SOURCE, EPSS_URL_TEMPLATE, EPSSReader, mine_epss
from .kev import KEV_CATALOG_URL, KEV_SOURCE, KEVReader, mine_kev
from .snapshot import SNAPSHOT_SCHEMA, Snapshot, SnapshotReader, cve_keys, write_snapshot

__all__ = [
    "SNAPSHOT_SCHEMA",
    "Snapshot",
    "SnapshotReader",
    "cve_keys",
    "write_snapshot",
    "Enricher",
    "build_enricher",
    "KEVReader",
    "KEV_CATALOG_URL",
    "KEV_SOURCE",
    "mine_kev",
    "EPSSReader",
    "EPSS_URL_TEMPLATE",
    "EPSS_SOURCE",
    "mine_epss",
]
