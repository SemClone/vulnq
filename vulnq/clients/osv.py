"""OSV.dev API client."""

from datetime import datetime
import re
from typing import Any, Dict, List, Optional

from packageurl import PackageURL

from ..cvss import base_score, coerce_score
from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from .base import BaseClient, UnsupportedQueryError

# Pages to fetch before giving up. OSV returns up to 1000 records per page and
# hands back a token for the rest; ignoring it reported 3000 of an unknown
# larger total as if that were the whole answer.
MAX_PAGES = 10


# OSV writes a 3.x or 4.0 vector with its CVSS: prefix, but publishes 2.0 as a
# bare metric string like "AV:L/AC:M/Au:N/C:P/I:P/A:P". Matching only on the
# prefix dropped those vectors entirely, so a 2.0 advisory reported neither a
# score nor the vector a consumer could have scored itself.
_VECTOR = re.compile(r"^(CVSS:[\d.]+/)?[A-Za-z]+:[A-Za-z0-9.]+(/[A-Za-z]+:[A-Za-z0-9.]+)+$")


def _is_vector(value: str) -> bool:
    """Return whether a string is a CVSS vector rather than a numeric score.

    Args:
        value: The contents of an OSV severity "score" field

    Returns:
        True if it reads as a metric vector of any CVSS version
    """
    return bool(_VECTOR.match(value.strip()))


class OSVClient(BaseClient):
    """Client for OSV.dev vulnerability database."""

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        return VulnerabilitySource.OSV

    @property
    def base_url(self) -> str:
        """Return the base URL for the API."""
        return "https://api.osv.dev/v1"

    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects
        """
        self._begin_query()

        url = f"{self.base_url}/query"
        vulns: List[Dict[str, Any]] = []
        page_token: Optional[str] = None

        for _ in range(MAX_PAGES):
            data: Dict[str, Any] = {"package": {"purl": purl}}
            if page_token:
                data["page_token"] = page_token

            # Failures propagate: the caller records them as errors and omits
            # the source from sources_checked. Swallowing them here made an
            # outage indistinguishable from a package with no known
            # vulnerabilities.
            response = await self._make_request("POST", url, json=data)
            vulns.extend(response.get("vulns") or [])

            page_token = response.get("next_page_token")
            if not page_token:
                break
        else:
            # Stopping short must not pass for having read everything.
            self.parse_warnings.append(
                f"stopped after {len(vulns)} records for {purl} with more still to come; "
                f"the rest were not fetched (page limit of {MAX_PAGES} reached)"
            )

        return self._parse_vulns(vulns, self._queried_version(purl))

    @staticmethod
    def _queried_version(purl: str) -> Optional[str]:
        """Return the version the PURL pins, if any.

        OSV filters by version server-side, but only when the query carries
        one. A versionless PURL gets every advisory for the package back, and
        claiming those were version-matched would be a claim nobody checked.

        Args:
            purl: Package URL string

        Returns:
            The pinned version, or None
        """
        try:
            return PackageURL.from_string(purl).version
        except Exception:
            return None

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: OSV is keyed by PURL and has no CPE lookup.

        Args:
            cpe: CPE string

        Raises:
            UnsupportedQueryError: Always; OSV is a PURL-keyed database
        """
        self._begin_query()
        raise UnsupportedQueryError("OSV cannot be queried by CPE; use a PURL")

    def _parse_response(
        self, response: Dict[str, Any], queried_version: Optional[str] = None
    ) -> List[Vulnerability]:
        """Parse a single-page OSV API response.

        Args:
            response: Raw API response
            queried_version: Version pinned by the query, if any

        Returns:
            List of Vulnerability objects
        """
        return self._parse_vulns(response.get("vulns") or [], queried_version)

    def _parse_vulns(
        self, vulns: List[Dict[str, Any]], queried_version: Optional[str] = None
    ) -> List[Vulnerability]:
        """Turn OSV records into Vulnerability objects.

        Args:
            vulns: Records, possibly gathered across several pages
            queried_version: Version pinned by the query, if any

        Returns:
            List of Vulnerability objects

        Raises:
            RuntimeError: If records were returned and none could be parsed
        """
        vulnerabilities = []
        parse_failures = 0
        last_error = ""

        for vuln_data in vulns:
            try:
                vuln = self._parse_vulnerability(vuln_data, queried_version)
                if vuln:
                    vulnerabilities.append(vuln)
                else:
                    # _parse_vulnerability returns None only for a record with
                    # no id, which is malformed rather than inapplicable. OSV
                    # has no version filtering here, so unlike the GitHub
                    # client a None is always a failure.
                    parse_failures += 1
            except Exception as e:
                parse_failures += 1
                last_error = str(e)
                if self.verbose:
                    print(f"Error parsing OSV vulnerability: {e}")
                continue

        # Every record failing to parse means the response shape changed, not
        # that the package is clean.
        if vulns and parse_failures == len(vulns):
            raise RuntimeError(f"OSV returned {len(vulns)} records but none could be parsed")

        # Below that threshold the query still has an answer, just not a whole
        # one. Say so rather than handing back a short list that looks complete.
        self._note_dropped_records(parse_failures, len(vulns), last_error)

        return vulnerabilities

    def _parse_vulnerability(
        self, data: Dict[str, Any], queried_version: Optional[str] = None
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry.

        Args:
            data: Raw vulnerability data
            queried_version: Version pinned by the query, if any

        Returns:
            Vulnerability object or None if parsing fails
        """
        # Extract basic information
        vuln_id = data.get("id", "")
        if not vuln_id:
            return None

        # Get aliases (CVE, GHSA, etc.)
        aliases = data.get("aliases", [])

        # Parse severity
        severity = Severity.UNKNOWN
        cvss_score = None
        cvss_vector = None

        # OSV puts the vector in the "score" field, and may carry more than one
        # entry for the same advisory: CVSS_V3 and CVSS_V4 side by side. Prefer
        # whichever can actually be scored, so the vector reported and the score
        # reported describe the same thing.
        for severity_info in data.get("severity") or []:
            if not isinstance(severity_info, dict):
                continue
            score_val = severity_info.get("score")
            if not score_val:
                continue

            if isinstance(score_val, str) and _is_vector(score_val):
                computed = base_score(score_val)
                if computed is not None:
                    cvss_vector = score_val
                    cvss_score = computed
                    severity = self.cvss_to_severity(computed)
                    break
                # 4.0 scores through a lookup table and 2.0 uses different
                # metrics, so neither is computed here. The vector is still
                # worth reporting, because a consumer can score it even if we
                # do not. Keep the first, in case a scorable one follows.
                if cvss_vector is None:
                    cvss_vector = score_val
                continue

            numeric = coerce_score(score_val)
            if numeric is None:
                continue
            cvss_score = numeric
            severity = self.cvss_to_severity(cvss_score)
            break

        # Only consulted when nothing above produced a rating. A score computed
        # from the vector and the severity printed beside it have to agree, so
        # the database's own label does not overrule one.
        if severity == Severity.UNKNOWN:
            db_severity = (data.get("database_specific") or {}).get("severity")
            if isinstance(db_severity, str):
                severity = self.normalize_severity(db_severity)

        # Parse dates
        published_date = None
        modified_date = None

        if "published" in data:
            try:
                published_date = datetime.fromisoformat(data["published"].replace("Z", "+00:00"))
            except Exception:
                pass

        if "modified" in data:
            try:
                modified_date = datetime.fromisoformat(data["modified"].replace("Z", "+00:00"))
            except Exception:
                pass

        # Parse affected versions and fixes
        affected_versions = []
        fixed_versions = []

        for affected in data.get("affected", []):
            # Get affected version ranges
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "introduced" in event:
                        version = event["introduced"]
                        if version and version != "0":
                            affected_versions.append(f">={version}")
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

            # Get specific versions
            for version in affected.get("versions", []):
                affected_versions.append(version)

        # Get summary and details
        summary = data.get("summary", "")
        if not summary:
            summary = (
                data.get("details", "")[:200] if data.get("details") else f"Vulnerability {vuln_id}"
            )

        details = data.get("details", "")

        # Get references
        references = []
        for ref in data.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

        # Create vulnerability object
        return Vulnerability(
            id=vuln_id,
            source=self.source,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            summary=summary,
            details=details,
            affected_versions=list(set(affected_versions)),
            fixed_versions=list(set(fixed_versions)),
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            cwe_ids=[],  # OSV doesn't typically provide CWE IDs
            aliases=aliases,
            version_match=(
                VersionMatch.SOURCE_FILTERED if queried_version else VersionMatch.NOT_EVALUATED
            ),
        )
