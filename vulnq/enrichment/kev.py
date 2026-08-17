"""CISA KEV known-exploited enrichment.

Answers "is anyone exploiting this right now", the signal that separates a CVE
worth someone's Tuesday from one worth their next quarter.
"""

from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from ..models import Vulnerability
from .snapshot import Snapshot, SnapshotReader, cve_keys

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
KEV_SOURCE = "cisa-kev"


def _parse_date(value: Optional[str]) -> Optional[date]:
    """Parse a KEV date string, tolerating anything unexpected.

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


def mine_kev(timeout: int = 60, url: str = KEV_CATALOG_URL) -> Snapshot:
    """Fetch the KEV catalog and normalize it into a snapshot.

    Args:
        timeout: HTTP timeout in seconds
        url: Catalog URL, overridable for testing or mirroring

    Returns:
        Snapshot keyed by CVE id

    Raises:
        requests.HTTPError: If the catalog cannot be fetched
    """
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    catalog = response.json()

    records: Dict[str, Dict[str, Any]] = {}
    for entry in catalog.get("vulnerabilities") or []:
        cve_id = str(entry.get("cveID") or "").upper()
        if not cve_id:
            continue
        records[cve_id] = {
            "date_added": entry.get("dateAdded"),
            # CISA publishes this as the string "Known" or "Unknown", not a
            # boolean. "Unknown" means unestablished, so it maps to None
            # rather than False.
            "known_ransomware": _ransomware_flag(entry.get("knownRansomwareCampaignUse")),
            "required_action": entry.get("requiredAction"),
        }

    return Snapshot(
        source=KEV_SOURCE,
        version=catalog.get("catalogVersion"),
        fetched_at=datetime.now(timezone.utc),
        records=records,
    )


def _ransomware_flag(value: Optional[str]) -> Optional[bool]:
    """Map CISA's ransomware string to a tri-state boolean.

    Args:
        value: Raw ``knownRansomwareCampaignUse`` value

    Returns:
        True for "Known", False for an explicit negative, None otherwise
    """
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized == "known":
        return True
    if normalized in ("not known", "none", "no"):
        return False
    return None


class KEVReader(SnapshotReader):
    """Stamps CISA KEV facts onto vulnerabilities."""

    source = KEV_SOURCE
    filename = f"{KEV_SOURCE}.json.gz"

    def stamp(self, vuln: Vulnerability, record: Dict[str, Any], snapshot: Snapshot) -> None:
        """Mark a vulnerability as known-exploited.

        Args:
            vuln: Vulnerability to update
            record: Matching KEV record
            snapshot: The snapshot the record came from
        """
        vuln.known_exploited = True
        vuln.kev_date_added = _parse_date(record.get("date_added"))
        vuln.kev_known_ransomware = record.get("known_ransomware")
        vuln.kev_required_action = record.get("required_action")

    def apply(self, vulnerabilities: List[Vulnerability]) -> None:
        """Stamp KEV facts, defaulting matched-nothing to a verified negative.

        Unlike EPSS, a successful KEV join is exhaustive: the catalog is the
        complete list of known-exploited CVEs, so a CVE absent from a fresh
        snapshot really is not on it. That is only true when the snapshot
        loaded and is not stale - otherwise every field stays None.

        Args:
            vulnerabilities: Vulnerabilities to enrich
        """
        snapshot = self.load()
        if not snapshot or self.is_stale(snapshot):
            return

        for vuln in vulnerabilities:
            keys = cve_keys(vuln)
            if not keys:
                # A GHSA-only advisory with no CVE alias can never be looked
                # up, so its exploitation status stays unknown rather than
                # becoming a false negative.
                continue

            matched = False
            for key in keys:
                record = snapshot.records.get(key)
                if record is not None:
                    self.stamp(vuln, record, snapshot)
                    matched = True
                    break

            if not matched:
                vuln.known_exploited = False
