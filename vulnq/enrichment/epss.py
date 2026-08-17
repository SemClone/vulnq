"""FIRST EPSS exploitation-probability enrichment.

KEV answers "is this exploited today". EPSS answers "how likely is exploitation
in the next 30 days", which is what makes a backlog of 400 medium-severity CVEs
rankable instead of a wall.

The daily bulk snapshot is the supported bulk path. FIRST documents
``api.first.org/data/v1/epss`` as a lookup interface for one CVE or a small
batch, explicitly not for bulk download or for keeping a local copy in sync, so
it is deliberately not used here.
"""

import csv
import gzip
import io
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests

from ..models import Vulnerability
from .snapshot import Snapshot, SnapshotReader

EPSS_URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{score_date}.csv.gz"
EPSS_SOURCE = "first-epss"

# How many days back to walk when the requested day has not been published yet.
_MAX_FALLBACK_DAYS = 7


def _parse_date(value: Optional[str]) -> Optional[date]:
    """Parse an ISO date prefix, tolerating anything unexpected.

    Args:
        value: Raw date string

    Returns:
        Parsed date, or None
    """
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _parse_csv(payload: bytes) -> Tuple[Optional[str], Dict[str, Dict[str, Any]]]:
    """Parse a decompressed EPSS CSV into records keyed by CVE id.

    Args:
        payload: Decompressed CSV bytes

    Returns:
        The published score date, and records keyed by upper-cased CVE id
    """
    text = payload.decode("utf-8", errors="replace")
    score_date: Optional[str] = None
    rows: list = []

    for line in text.splitlines():
        if line.startswith("#"):
            # Header comment, e.g. "#model_version:v2025.03.14,score_date:2026-08-16T00:00:00+0000"
            for part in line.lstrip("#").split(","):
                if part.strip().startswith("score_date:"):
                    score_date = part.split("score_date:", 1)[1].strip()[:10]
            continue
        rows.append(line)

    records: Dict[str, Dict[str, Any]] = {}
    reader = csv.DictReader(io.StringIO("\n".join(rows)))
    for row in reader:
        cve_id = str(row.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        try:
            score = float(row["epss"])
            # Preserved as published. The percentile is relative to the full
            # CVE population, which a partial corpus cannot reproduce, so it is
            # never recomputed locally.
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        records[cve_id] = {"score": score, "percentile": percentile}

    return score_date, records


def mine_epss(
    score_date: Optional[date] = None,
    timeout: int = 120,
    url_template: str = EPSS_URL_TEMPLATE,
) -> Snapshot:
    """Fetch and decompress the daily EPSS CSV into a snapshot.

    Scores move once a day, so walking back a few days when today's file is not
    yet published loses nothing and beats failing the mine.

    Args:
        score_date: Day to fetch, defaulting to today in UTC
        timeout: HTTP timeout in seconds
        url_template: URL template, overridable for testing or mirroring

    Returns:
        Snapshot keyed by CVE id

    Raises:
        requests.HTTPError: If no recent day could be fetched
    """
    target = score_date or datetime.now(timezone.utc).date()
    last_error: Optional[Exception] = None

    for offset in range(_MAX_FALLBACK_DAYS + 1):
        day = target - timedelta(days=offset)
        url = url_template.format(score_date=day.isoformat())
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            last_error = exc
            continue

        published_date, records = _parse_csv(gzip.decompress(response.content))
        return Snapshot(
            source=EPSS_SOURCE,
            version=published_date or day.isoformat(),
            fetched_at=datetime.now(timezone.utc),
            records=records,
        )

    raise requests.HTTPError(
        f"No EPSS snapshot published in the {_MAX_FALLBACK_DAYS} days before {target.isoformat()}"
    ) from last_error


class EPSSReader(SnapshotReader):
    """Stamps FIRST EPSS scores onto vulnerabilities."""

    source = EPSS_SOURCE
    filename = f"{EPSS_SOURCE}.json.gz"

    def stamp(self, vuln: Vulnerability, record: Dict[str, Any], snapshot: Snapshot) -> None:
        """Copy an EPSS score onto a vulnerability.

        A CVE absent from the snapshot is left at None. EPSS legitimately
        assigns near-zero scores, so defaulting a miss to 0.0 would silently
        claim "we checked, it is harmless".

        Args:
            vuln: Vulnerability to update
            record: Matching EPSS record
            snapshot: The snapshot the record came from
        """
        score = record.get("score")
        percentile = record.get("percentile")
        if score is None:
            return

        vuln.epss_score = float(score)
        vuln.epss_percentile = float(percentile) if percentile is not None else None
        vuln.epss_score_date = _parse_date(snapshot.version)
