"""GitHub Advisory Database API client."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import Severity, Vulnerability, VulnerabilitySource
from .base import BaseClient


class GitHubClient(BaseClient):
    """Client for GitHub Advisory Database."""

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        return VulnerabilitySource.GITHUB

    @property
    def base_url(self) -> str:
        """Return the base URL for the API."""
        return "https://api.github.com/graphql"

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers including authentication if available."""
        headers = {"Accept": "application/vnd.github.v4+json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects
        """
        # Parse PURL to extract ecosystem and name
        ecosystem, name, version = self._parse_purl(purl)
        if not ecosystem or not name:
            return []

        # Map PURL type to GitHub ecosystem
        ecosystem_map = {
            "npm": "NPM",
            "pypi": "PIP",
            "maven": "MAVEN",
            "gem": "RUBYGEMS",
            "nuget": "NUGET",
            "cargo": "RUST",
            "composer": "COMPOSER",
            "go": "GO",
        }

        gh_ecosystem = ecosystem_map.get(ecosystem.lower())
        if not gh_ecosystem:
            return []

        # Build GraphQL query
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem, $package: String) {
          securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
            nodes {
              advisory {
                ghsaId
                summary
                description
                severity
                cvss {
                  score
                  vectorString
                }
                identifiers {
                  type
                  value
                }
                references {
                  url
                }
                publishedAt
                updatedAt
                cwes(first: 10) {
                  nodes {
                    cweId
                  }
                }
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """

        variables = {"ecosystem": gh_ecosystem, "package": name}

        try:
            response = await self._make_request(
                "POST",
                self.base_url,
                json={"query": query, "variables": variables},
                headers=self._get_headers(),
            )
            return self._parse_response(response, version)
        except Exception as e:
            if self.verbose:
                print(f"GitHub query failed for {purl}: {e}")
            return []

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: GitHub doesn't directly support CPE queries.

        Args:
            cpe: CPE string

        Returns:
            Empty list (GitHub doesn't support CPE)
        """
        # GitHub doesn't support CPE queries directly
        return []

    def _parse_purl(self, purl: str) -> tuple:
        """Parse PURL into components.

        Args:
            purl: Package URL string

        Returns:
            Tuple of (ecosystem, name, version)
        """
        # Simple PURL parser
        match = re.match(r"pkg:([^/]+)/([^@]+)(?:@(.+))?", purl)
        if match:
            return match.group(1), match.group(2), match.group(3)
        return None, None, None

    def _parse_response(
        self, response: Dict[str, Any], target_version: Optional[str]
    ) -> List[Vulnerability]:
        """Parse GitHub GraphQL response into Vulnerability objects.

        Args:
            response: Raw API response
            target_version: Specific version to check (optional)

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        data = response.get("data", {})
        vulns = data.get("securityVulnerabilities", {}).get("nodes", [])

        for vuln_data in vulns:
            try:
                vuln = self._parse_vulnerability(vuln_data, target_version)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing GitHub vulnerability: {e}")
                continue

        return vulnerabilities

    def _parse_vulnerability(
        self, data: Dict[str, Any], target_version: Optional[str]
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry.

        Args:
            data: Raw vulnerability data
            target_version: Specific version to check

        Returns:
            Vulnerability object or None if not applicable
        """
        advisory = data.get("advisory", {})
        if not advisory:
            return None

        # Get vulnerability ID
        vuln_id = advisory.get("ghsaId", "")
        if not vuln_id:
            return None

        # Check if version is affected (if specified)
        if target_version:
            vulnerable_range = data.get("vulnerableVersionRange", "")
            if not self._is_version_affected(target_version, vulnerable_range):
                return None

        # Parse severity
        severity_str = advisory.get("severity", "UNKNOWN")
        severity = self.normalize_severity(severity_str)

        # Parse CVSS
        cvss_score = None
        cvss_vector = None
        cvss_data = advisory.get("cvss", {})
        if cvss_data:
            cvss_score = cvss_data.get("score")
            cvss_vector = cvss_data.get("vectorString")
            # Use CVSS score for severity if not already set
            if cvss_score and severity == Severity.UNKNOWN:
                severity = self.cvss_to_severity(cvss_score)

        # Get identifiers (CVE, etc.)
        aliases = []
        for identifier in advisory.get("identifiers", []):
            if identifier.get("type") == "CVE":
                aliases.append(identifier.get("value"))

        # Parse dates
        published_date = None
        modified_date = None

        if advisory.get("publishedAt"):
            try:
                published_date = datetime.fromisoformat(
                    advisory["publishedAt"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        if advisory.get("updatedAt"):
            try:
                modified_date = datetime.fromisoformat(advisory["updatedAt"].replace("Z", "+00:00"))
            except Exception:
                pass

        # Parse affected and fixed versions
        affected_versions = []
        vulnerable_range = data.get("vulnerableVersionRange", "")
        if vulnerable_range:
            affected_versions.append(vulnerable_range)

        fixed_versions = []
        first_patched = data.get("firstPatchedVersion", {})
        if first_patched and "identifier" in first_patched:
            fixed_versions.append(first_patched["identifier"])

        # Get CWEs
        cwe_ids = []
        cwes = advisory.get("cwes", {}).get("nodes", [])
        for cwe in cwes:
            if "cweId" in cwe:
                cwe_ids.append(cwe["cweId"])

        # Get references
        references = []
        for ref in advisory.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

        return Vulnerability(
            id=vuln_id,
            source=self.source,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            summary=advisory.get("summary", ""),
            details=advisory.get("description", ""),
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            cwe_ids=cwe_ids,
            aliases=aliases,
        )

    def _is_version_affected(self, version: str, vulnerable_range: str) -> bool:
        """Check if a version is within a vulnerable range.

        Args:
            version: Version to check
            vulnerable_range: Vulnerability range string

        Returns:
            True if version is affected
        """
        # Simple version range check
        # In production, use a proper version comparison library
        if not vulnerable_range:
            return True

        # Parse simple ranges like ">= 1.0.0, < 2.0.0"
        if "<" in vulnerable_range or ">" in vulnerable_range:
            return True  # Simplified - assume affected

        return True
