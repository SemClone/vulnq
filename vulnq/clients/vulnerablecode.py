"""VulnerableCode API client."""

import urllib.parse
from typing import Any, Dict, List, Optional

from ..models import Severity, Vulnerability, VulnerabilitySource
from .base import BaseClient


class VulnerableCodeClient(BaseClient):
    """Client for VulnerableCode aggregated vulnerability database."""

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        # VulnerableCode aggregates multiple sources
        # We'll mark it as OSV since it's similar in nature
        return VulnerabilitySource.OSV

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
        # URL encode the PURL
        encoded_purl = urllib.parse.quote(purl, safe="")
        url = f"{self.base_url}/packages/?purl={encoded_purl}"

        try:
            response = await self._make_request("GET", url)
            return self._parse_response(response, purl)
        except Exception as e:
            if self.verbose:
                print(f"VulnerableCode query failed for {purl}: {e}")
            return []

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: VulnerableCode doesn't directly support CPE queries.

        Args:
            cpe: CPE string

        Returns:
            Empty list (VulnerableCode uses PURLs)
        """
        # VulnerableCode doesn't support CPE queries directly
        return []

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
        for vuln_data in package_data.get("affected_by_vulnerabilities", []):
            try:
                vuln = self._parse_vulnerability(vuln_data, is_fixed=False)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing VulnerableCode vulnerability: {e}")
                continue

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
        self, data: Dict[str, Any], is_fixed: bool = False
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry.

        Args:
            data: Raw vulnerability data
            is_fixed: Whether this is from fixing_vulnerabilities

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

        # Check for scores
        scores = data.get("scores", [])
        for score_data in scores:
            if score_data.get("scoring_system") == "cvss_v3":
                try:
                    cvss_score = float(score_data.get("value", 0))
                    severity = self.cvss_to_severity(cvss_score)
                    break
                except Exception:
                    pass

        # If no CVSS v3, try other scoring systems
        if not cvss_score and scores:
            for score_data in scores:
                try:
                    score_value = float(score_data.get("value", 0))
                    if score_value > 0:
                        cvss_score = score_value
                        severity = self.cvss_to_severity(cvss_score)
                        break
                except Exception:
                    pass

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
            affected_versions=list(set(affected_versions)),
            fixed_versions=list(set(fixed_versions)),
            published_date=None,  # VulnerableCode doesn't provide dates in this endpoint
            modified_date=None,
            references=references,
            cwe_ids=[],  # Would need to parse from references or description
            aliases=aliases,
        )
