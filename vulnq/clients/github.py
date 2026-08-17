"""GitHub Advisory Database API client."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import Severity, Vulnerability, VulnerabilitySource
from .base import BaseClient, RateLimitError, UnsupportedQueryError

# PURL type to GitHub SecurityAdvisoryEcosystem. Both spellings of the Go purl
# type are mapped: "golang" is the official one, and only "go" was handled
# before, so every Go query was silently answered with nothing.
ECOSYSTEM_MAP = {
    "npm": "NPM",
    "pypi": "PIP",
    "maven": "MAVEN",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
    "cargo": "RUST",
    "composer": "COMPOSER",
    "go": "GO",
    "golang": "GO",
    "hex": "ERLANG",
    "pub": "PUB",
    "swift": "SWIFT",
    "githubactions": "ACTIONS",
}


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
            # Unparseable input was never asked about. utils defaults an
            # unrecognised identifier to PURL, so a bare typo like "express"
            # lands here - and must not come back as a clean scan.
            raise UnsupportedQueryError(f"Not a parseable Package URL: {purl}")

        gh_ecosystem = ECOSYSTEM_MAP.get(ecosystem.lower())
        if not gh_ecosystem:
            raise UnsupportedQueryError(
                f"GitHub Advisory Database has no ecosystem mapping for '{ecosystem}'"
            )

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

        # Failures propagate: the caller records them as errors and omits the
        # source from sources_checked. Swallowing them here made an outage
        # indistinguishable from a package with no known vulnerabilities.
        response = await self._make_request(
            "POST",
            self.base_url,
            json={"query": query, "variables": variables},
            headers=self._get_headers(),
        )
        return self._parse_response(response, version)

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: the GitHub Advisory Database is keyed by ecosystem and package
        name, with no CPE lookup.

        Args:
            cpe: CPE string

        Raises:
            UnsupportedQueryError: Always; GitHub has no CPE lookup
        """
        raise UnsupportedQueryError("GitHub Advisory Database cannot be queried by CPE; use a PURL")

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
        # GraphQL reports failures - including rate limiting - as HTTP 200 with
        # an errors array and, when the request failed before execution, no
        # data at all. Treating that as an empty answer was a clean scan out of
        # a refused request.
        errors = response.get("errors")
        if errors:
            messages = "; ".join(
                str(error.get("message") or error.get("type") or error)
                for error in errors
                if isinstance(error, dict)
            ) or str(errors)
            if "RATE_LIMITED" in str(errors) or "rate limit" in messages.lower():
                raise RateLimitError(messages)
            raise RuntimeError(f"GitHub GraphQL error: {messages}")

        if "data" not in response or response.get("data") is None:
            raise RuntimeError("GitHub GraphQL response contained no data")

        vulnerabilities = []
        vulns = response["data"].get("securityVulnerabilities", {}).get("nodes", [])
        parse_failures = 0

        for vuln_data in vulns:
            try:
                vuln = self._parse_vulnerability(vuln_data, target_version)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                # Counted, not just skipped. A returned None means the record
                # legitimately does not apply - a version outside the affected
                # range - and must stay distinct from a record that broke.
                parse_failures += 1
                if self.verbose:
                    print(f"Error parsing GitHub vulnerability: {e}")
                continue

        # Every record failing to parse means the response shape changed, not
        # that the package is clean.
        if vulns and parse_failures == len(vulns):
            raise RuntimeError(f"GitHub returned {len(vulns)} advisories but none could be parsed")

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
