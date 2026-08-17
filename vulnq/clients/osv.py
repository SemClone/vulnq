"""OSV.dev API client."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from packageurl import PackageURL

from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from .base import BaseClient, UnsupportedQueryError


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
        data = {"package": {"purl": purl}}

        # Failures propagate: the caller records them as errors and omits the
        # source from sources_checked. Swallowing them here made an outage
        # indistinguishable from a package with no known vulnerabilities.
        response = await self._make_request("POST", url, json=data)
        return self._parse_response(response, self._queried_version(purl))

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
        """Parse OSV API response into Vulnerability objects.

        Args:
            response: Raw API response
            queried_version: Version pinned by the query, if any

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        vulns = response.get("vulns", [])
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

        # Check for severity in different locations
        if "severity" in data:
            severity_data = data["severity"]
            if isinstance(severity_data, list) and severity_data:
                for severity_info in severity_data:
                    # OSV returns CVSS vector string in the "score" field
                    score_val = severity_info.get("score")
                    if score_val and isinstance(score_val, str) and "CVSS" in score_val:
                        cvss_vector = score_val
                        # Calculate score from CVSS v3 vector
                        # This is simplified - just use severity from impact
                        if "/C:H" in score_val or "/I:H" in score_val or "/A:H" in score_val:
                            if "/AC:L" in score_val:  # Low complexity = easier to exploit
                                cvss_score = 9.0  # Critical
                                severity = Severity.CRITICAL
                            else:
                                cvss_score = 7.5  # High
                                severity = Severity.HIGH
                        elif "/C:L" in score_val or "/I:L" in score_val or "/A:L" in score_val:
                            cvss_score = 5.0  # Medium
                            severity = Severity.MEDIUM
                        else:
                            cvss_score = 3.0  # Low
                            severity = Severity.LOW
                        break
                    elif score_val:
                        try:
                            cvss_score = float(score_val)
                            severity = self.cvss_to_severity(cvss_score)
                            break
                        except (ValueError, TypeError):
                            pass

        # Check database_specific for additional severity info
        if "database_specific" in data and "severity" in data["database_specific"]:
            db_severity = data["database_specific"]["severity"]
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
