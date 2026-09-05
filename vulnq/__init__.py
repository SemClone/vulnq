"""vulnq - Vulnerability Query Tool

A lightweight, multi-source vulnerability query tool for software composition analysis.
"""

__version__ = "1.7.0"
__author__ = "Oscar Valenzuela B."
__email__ = "oscar.valenzuela.b@gmail.com"

from .core import NoSourcesConfiguredError, VulnerabilityQuery
from .enrichment import EPSSReader, KEVReader, Snapshot, mine_epss, mine_kev
from .models import QueryResult, SnapshotProvenance, Vulnerability, VulnerabilitySource

__all__ = [
    "VulnerabilityQuery",
    "VulnerabilitySource",
    "NoSourcesConfiguredError",
    "Vulnerability",
    "QueryResult",
    "SnapshotProvenance",
    "KEVReader",
    "EPSSReader",
    "Snapshot",
    "mine_kev",
    "mine_epss",
    "__version__",
]
