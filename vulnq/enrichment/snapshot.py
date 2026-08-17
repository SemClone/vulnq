"""Snapshot format and the shared reader both enrichment sources build on.

A snapshot is a single gzipped JSON document: a header describing where the
data came from and when, followed by records keyed by CVE id so a reader can
load straight into a lookup table without a transform pass.

The format is deliberately shared between CISA KEV and FIRST EPSS. Both are
static reference files joined on the CVE id once per corpus, not per-query
sources, so neither belongs behind the ``clients/base.py`` fan-out interface.
"""

import gzip
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from ..models import SnapshotProvenance, Vulnerability

SNAPSHOT_SCHEMA = "vulnq.snapshot/1"

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def cve_keys(vuln: Vulnerability) -> List[str]:
    """Collect every CVE id a vulnerability can be joined on.

    De-duplication groups on the first CVE alias it finds but keeps the winning
    record's own id, so a GitHub-sourced advisory arrives here with a GHSA in
    ``id`` and the CVE in ``aliases``. A record can also carry more than one
    CVE alias. Looking only at ``id``, or only at the first alias, silently
    half-joins both cases.

    Args:
        vuln: Vulnerability to extract join keys from

    Returns:
        Upper-cased CVE ids, in order, without duplicates
    """
    keys: List[str] = []
    for candidate in [vuln.id] + list(vuln.aliases):
        if candidate and _CVE_PATTERN.match(candidate):
            normalized = candidate.upper()
            if normalized not in keys:
                keys.append(normalized)
    return keys


class Snapshot:
    """A loaded snapshot: header plus records keyed by CVE id."""

    def __init__(
        self,
        source: str,
        version: Optional[str],
        fetched_at: Optional[datetime],
        records: Dict[str, Dict[str, Any]],
    ):
        """Initialize a snapshot.

        Args:
            source: Snapshot source identifier, e.g. ``cisa-kev``
            version: Catalog version or score date the snapshot represents
            fetched_at: When the snapshot was mined
            records: Records keyed by upper-cased CVE id
        """
        self.source = source
        self.version = version
        self.fetched_at = fetched_at
        self.records = records

    @property
    def count(self) -> int:
        """Return the number of records in the snapshot."""
        return len(self.records)

    def age_seconds(self, now: Optional[datetime] = None) -> Optional[float]:
        """Return the snapshot's age in seconds, or None if it is undated.

        Args:
            now: Reference time, defaulting to the current UTC time

        Returns:
            Age in seconds, never negative, or None when ``fetched_at`` is absent
        """
        if not self.fetched_at:
            return None
        reference = now or datetime.now(timezone.utc)
        fetched = self.fetched_at
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        return max(0.0, (reference - fetched).total_seconds())

    def to_document(self) -> Dict[str, Any]:
        """Serialize the snapshot to its on-disk document form."""
        return {
            "schema": SNAPSHOT_SCHEMA,
            "source": self.source,
            "version": self.version,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "count": self.count,
            "records": self.records,
        }

    @classmethod
    def from_document(cls, document: Dict[str, Any]) -> "Snapshot":
        """Build a snapshot from a parsed document.

        Args:
            document: Parsed snapshot JSON

        Returns:
            Snapshot instance

        Raises:
            ValueError: If the document is not a recognized snapshot schema
        """
        schema = document.get("schema")
        if schema != SNAPSHOT_SCHEMA:
            raise ValueError(f"Unsupported snapshot schema: {schema!r}")

        fetched_at = None
        raw_fetched = document.get("fetched_at")
        if raw_fetched:
            try:
                fetched_at = datetime.fromisoformat(str(raw_fetched).replace("Z", "+00:00"))
            except ValueError as exc:
                # An undated snapshot cannot be age-checked, and silently
                # nulling the stamp would let it slip past a configured
                # freshness gate. Refuse it here instead.
                raise ValueError(f"Unparseable snapshot fetched_at: {raw_fetched!r}") from exc

        records = document.get("records") or {}
        if not isinstance(records, dict):
            raise ValueError("Snapshot records must be an object keyed by CVE id")

        # Record values are validated up front so a malformed snapshot fails at
        # load, where unavailability is already non-fatal, rather than raising
        # from inside stamp() and taking the whole query down with it.
        for key, value in records.items():
            if not isinstance(value, dict):
                raise ValueError(
                    f"Snapshot record for {key!r} must be an object, got {type(value)}"
                )

        return cls(
            source=str(document.get("source") or "unknown"),
            version=document.get("version"),
            fetched_at=fetched_at,
            records=records,
        )


def write_snapshot(snapshot: Snapshot, destination: str) -> str:
    """Write a snapshot to a local path.

    Args:
        snapshot: Snapshot to write
        destination: Target file, or a directory to write the default name into

    Returns:
        The path written
    """
    path = destination
    if os.path.isdir(destination) or destination.endswith(os.sep):
        os.makedirs(destination, exist_ok=True)
        path = os.path.join(destination, f"{snapshot.source}.json.gz")
    else:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(snapshot.to_document(), handle)

    return path


def _read_document(location: str, filename: str, timeout: int) -> Dict[str, Any]:
    """Read a snapshot document from a local path or a URL.

    Args:
        location: File path, directory, or URL
        filename: Default file name to append when location names a container
        timeout: HTTP timeout in seconds

    Returns:
        Parsed snapshot document
    """
    if location.startswith("http://") or location.startswith("https://"):
        url = location
        parts = urlsplit(location)
        # Only the path decides whether the URL already names a snapshot file.
        # Appending to the raw string would land after the query string and
        # break presigned S3 and GCS URLs.
        if not parts.path.rstrip("/").endswith(".json.gz"):
            path = f"{parts.path.rstrip('/')}/{filename}"
            url = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        remote: Dict[str, Any] = json.loads(gzip.decompress(response.content).decode("utf-8"))
        return remote

    path = location
    if os.path.isdir(path):
        path = os.path.join(path, filename)

    with gzip.open(path, "rt", encoding="utf-8") as handle:
        local: Dict[str, Any] = json.load(handle)
    return local


class SnapshotReader:
    """Loads a snapshot once and stamps its facts onto vulnerabilities.

    The snapshot is held for the life of the reader. EPSS is roughly 290k rows;
    re-reading it per query would dominate the cost of a corpus run, so a
    process is expected to build one reader and reuse it.
    """

    source = "unknown"
    filename = "unknown.json.gz"

    def __init__(
        self,
        location: str,
        max_age_days: Optional[int] = None,
        timeout: int = 30,
        verbose: bool = False,
    ):
        """Initialize the reader.

        Args:
            location: Snapshot file, directory, or URL
            max_age_days: Age past which the snapshot is refused rather than joined
            timeout: HTTP timeout when the location is a URL
            verbose: Enable verbose output
        """
        self.location = location
        self.max_age_days = max_age_days
        self.timeout = timeout
        self.verbose = verbose
        self._snapshot: Optional[Snapshot] = None
        self._error: Optional[str] = None
        self._loaded = False
        # A reader is shared across a worker's queries, so the first load must
        # not be observable as "absent" by a second thread arriving mid-read.
        self._lock = threading.Lock()

    def load(self) -> Optional[Snapshot]:
        """Load the snapshot, at most once.

        A failure is recorded rather than raised: a missing snapshot must leave
        the facts unknown, not fail the query.

        Returns:
            The loaded snapshot, or None if it was unavailable
        """
        if self._loaded:
            return self._snapshot

        with self._lock:
            if self._loaded:
                return self._snapshot

            try:
                document = _read_document(self.location, self.filename, self.timeout)
                self._snapshot = Snapshot.from_document(document)
            except Exception as exc:  # noqa: BLE001 - unavailability must stay non-fatal
                self._error = str(exc)
                self._snapshot = None
                if self.verbose:
                    print(f"{self.source} snapshot unavailable: {exc}")
            finally:
                self._loaded = True

        return self._snapshot

    def is_stale(self, snapshot: Snapshot) -> bool:
        """Return whether the snapshot is older than the configured maximum.

        Args:
            snapshot: Loaded snapshot

        Returns:
            True when a maximum age is configured and the snapshot exceeds it
        """
        if self.max_age_days is None:
            return False
        age = snapshot.age_seconds()
        if age is None:
            # An operator who configured a freshness gate is asking for proof
            # of freshness. A snapshot that cannot supply it does not pass.
            return True
        return age > self.max_age_days * 86400

    def provenance(self) -> SnapshotProvenance:
        """Describe the snapshot this reader joined against."""
        snapshot = self.load()
        if not snapshot or self._error:
            return SnapshotProvenance(
                source=self.source,
                available=False,
                error=self._error or "snapshot not loaded",
            )

        return SnapshotProvenance(
            source=self.source,
            available=True,
            version=snapshot.version,
            fetched_at=snapshot.fetched_at,
            age_seconds=snapshot.age_seconds(),
            stale=self.is_stale(snapshot),
            record_count=snapshot.count,
        )

    def apply(self, vulnerabilities: List[Vulnerability]) -> None:
        """Stamp snapshot facts onto each vulnerability in place.

        Enrichment is an add-on to the answer, never a precondition for it. An
        unforeseen failure here degrades to "unknown" and is reported through
        provenance rather than taking the whole vulnerability query down.

        Args:
            vulnerabilities: Vulnerabilities to enrich
        """
        try:
            self._apply(vulnerabilities)
        except Exception as exc:  # noqa: BLE001 - enrichment must never be fatal
            self._error = f"enrichment failed: {exc}"
            if self.verbose:
                print(f"{self.source} enrichment failed: {exc}")

    def _apply(self, vulnerabilities: List[Vulnerability]) -> None:
        """Join the snapshot onto each vulnerability.

        Args:
            vulnerabilities: Vulnerabilities to enrich
        """
        snapshot = self.load()
        if not snapshot or self.is_stale(snapshot):
            return

        for vuln in vulnerabilities:
            for key in cve_keys(vuln):
                record = snapshot.records.get(key)
                if record is not None:
                    self.stamp(vuln, record, snapshot)
                    break

    def stamp(self, vuln: Vulnerability, record: Dict[str, Any], snapshot: Snapshot) -> None:
        """Copy a matched record onto a vulnerability.

        Args:
            vuln: Vulnerability to update
            record: Matching snapshot record
            snapshot: The snapshot the record came from
        """
        raise NotImplementedError
