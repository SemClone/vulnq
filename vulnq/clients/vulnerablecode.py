"""VulnerableCode API client."""

import urllib.parse
from typing import Any, Dict, List, Optional

from ..cvss import coerce_score
from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from ..versions import sort_versions
from .base import BaseClient, UnsupportedQueryError

# Preference order for a CVSS base score. Newest first, because a record
# carrying both is describing the same finding under a newer specification.
# Nothing outside this tuple may fill cvss_score: the identifiers are
# VulnerableCode's own, from vulnerabilities/severity_systems.py.
_CVSS_SYSTEMS = ("cvssv4", "cvssv3.1", "cvssv3", "cvssv2")


class VulnerableCodeClient(BaseClient):
    """Client for VulnerableCode aggregated vulnerability database."""

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        # It aggregates other databases, but it is still the source that was
        # asked and the one that answered. Labelling its findings as OSV
        # contradicted sources_checked in the same envelope and credited data
        # to a database that was never queried.
        return VulnerabilitySource.VULNERABLECODE

    @property
    def base_url(self) -> str:
        """Return the base URL for the API."""
        return "https://public.vulnerablecode.io/api"

    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects
        """
        self._begin_query()

        # URL encode the PURL
        encoded_purl = urllib.parse.quote(purl, safe="")
        url = f"{self.base_url}/packages/?purl={encoded_purl}"

        # Failures propagate: the caller records them as errors and omits the
        # source from sources_checked. Swallowing them here made an outage
        # indistinguishable from a package with no known vulnerabilities.
        response = await self._make_request("GET", url)
        return self._parse_response(response, purl)

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: VulnerableCode is keyed by PURL.

        Args:
            cpe: CPE string

        Raises:
            UnsupportedQueryError: Always; VulnerableCode has no CPE lookup
        """
        self._begin_query()
        raise UnsupportedQueryError("VulnerableCode cannot be queried by CPE; use a PURL")

    def _parse_response(self, response: Dict[str, Any], purl: str) -> List[Vulnerability]:
        """Parse VulnerableCode API response into Vulnerability objects.

        Args:
            response: Raw API response
            purl: Original PURL query

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        # VulnerableCode returns a list of packages
        results = response.get("results", [])
        if not results:
            return vulnerabilities

        # Get the first matching package
        package_data = results[0] if results else {}

        # Process affected_by_vulnerabilities
        affecting = package_data.get("affected_by_vulnerabilities", [])
        parse_failures = 0
        last_error = ""

        for vuln_data in affecting:
            try:
                vuln = self._parse_vulnerability(
                    vuln_data,
                    queried_version=self._queried_version(purl),
                    ecosystem=self._ecosystem_of(purl),
                )
                if vuln:
                    vulnerabilities.append(vuln)
                else:
                    # VulnerableCode has already filtered by version, so a
                    # record that yields nothing here is malformed rather than
                    # inapplicable.
                    parse_failures += 1
            except Exception as e:
                parse_failures += 1
                last_error = str(e)
                if self.verbose:
                    print(f"Error parsing VulnerableCode vulnerability: {e}")
                continue

        # Every record failing to parse means the response shape changed, not
        # that the package is clean.
        if affecting and parse_failures == len(affecting):
            raise RuntimeError(
                f"VulnerableCode returned {len(affecting)} records but none could be parsed"
            )

        # Below that threshold the query still has an answer, just not a whole
        # one. Say so rather than handing back a short list that looks complete.
        self._note_dropped_records(parse_failures, len(affecting), last_error)

        # Also check fixing_vulnerabilities to get fixed version info
        fixed_vulns = {}
        for vuln_data in package_data.get("fixing_vulnerabilities", []):
            vuln_id = vuln_data.get("vulnerability_id")
            if vuln_id:
                fixed_vulns[vuln_id] = package_data.get("version", "")

        # Update fixed versions
        for vuln in vulnerabilities:
            if vuln.id in fixed_vulns:
                vuln.fixed_versions.append(fixed_vulns[vuln.id])

        return vulnerabilities

    def _parse_vulnerability(
        self,
        data: Dict[str, Any],
        queried_version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry.

        Args:
            data: Raw vulnerability data
            queried_version: Version pinned by the query, if any
            ecosystem: PURL type, which decides how versions are ordered

        Returns:
            Vulnerability object or None if parsing fails
        """
        # Get vulnerability ID
        vuln_id = data.get("vulnerability_id", "")
        if not vuln_id:
            return None

        # Get aliases (CVE, GHSA, etc.)
        aliases = data.get("aliases", [])

        # Parse severity
        # VulnerableCode provides severity scores
        severity = Severity.UNKNOWN
        cvss_score = None

        # VulnerableCode carries several scoring systems per vulnerability and
        # names them without an underscore. Matching "cvss_v3" meant the branch
        # below never fired on a real record.
        #
        # Only CVSS systems may fill a CVSS field. The fallback used to take
        # the first system with a positive value, which let an EPSS row - a
        # probability between 0 and 1 - land in cvss_score as if it were a
        # base score, turning a 0.97 likelihood of exploitation into "LOW".
        scores = data.get("scores", [])
        for system in _CVSS_SYSTEMS:
            for score_data in scores:
                if not isinstance(score_data, dict):
                    continue
                if str(score_data.get("scoring_system", "")).lower() != system:
                    continue
                numeric = coerce_score(score_data.get("value"))
                if numeric is None:
                    continue
                cvss_score = numeric
                severity = self.cvss_to_severity(cvss_score)
                break
            if cvss_score is not None:
                break

        # A textual rating from any system is still a rating, and is the only
        # one available when no CVSS row parsed.
        if severity is Severity.UNKNOWN:
            for score_data in scores:
                if not isinstance(score_data, dict):
                    continue
                value = score_data.get("value")
                if isinstance(value, str) and coerce_score(value) is None:
                    rated = self.normalize_severity(value)
                    if rated is not Severity.UNKNOWN:
                        severity = rated
                        break

        # Get summary
        summary = data.get("summary", "")
        if not summary:
            summary = f"Vulnerability {vuln_id}"

        # Get references
        references = []
        for ref in data.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

        # Get affected versions
        affected_versions = []
        for affected_package in data.get("affected_packages", []):
            version = affected_package.get("version", "")
            if version:
                affected_versions.append(version)

        # Get fixed versions
        fixed_versions = []
        for fixed_package in data.get("fixed_packages", []):
            version = fixed_package.get("version", "")
            if version:
                fixed_versions.append(version)

        return Vulnerability(
            id=vuln_id,
            source=self.source,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=None,  # VulnerableCode doesn't provide vector strings
            summary=summary,
            details=data.get("description", ""),
            affected_versions=sort_versions(ecosystem, affected_versions),
            fixed_versions=sort_versions(ecosystem, fixed_versions),
            published_date=None,  # VulnerableCode doesn't provide dates in this endpoint
            modified_date=None,
            references=references,
            version_match=(
                VersionMatch.SOURCE_FILTERED if queried_version else VersionMatch.NOT_EVALUATED
            ),
            # VulnerableCode serializes these as objects carrying a cwe_id.
            cwe_ids=self._normalize_cwe_ids(data.get("weaknesses")),
            aliases=aliases,
        )
