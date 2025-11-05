"""NIST NVD API client."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import Severity, Vulnerability, VulnerabilitySource
from .base import BaseClient


class NVDClient(BaseClient):
    """Client for NIST National Vulnerability Database."""

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        return VulnerabilitySource.NVD

    @property
    def base_url(self) -> str:
        """Return the base URL for the API."""
        return "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers including API key if available."""
        headers = {
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Note: NVD doesn't directly support PURL queries.
        We convert PURL to CPE if possible.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects
        """
        # Try to convert PURL to CPE
        cpe = self._purl_to_cpe(purl)
        if cpe:
            return await self.query_cpe(cpe)
        return []

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Args:
            cpe: CPE string

        Returns:
            List of normalized Vulnerability objects
        """
        # Clean CPE string
        if not cpe.startswith("cpe:"):
            cpe = f"cpe:{cpe}"

        params = {"cpeName": cpe, "resultsPerPage": 100}

        try:
            response = await self._make_request(
                "GET", self.base_url, params=params, headers=self._get_headers()
            )
            return self._parse_response(response)
        except Exception as e:
            if self.verbose:
                print(f"NVD query failed for {cpe}: {e}")
            return []

    def _purl_to_cpe(self, purl: str) -> Optional[str]:
        """Convert PURL to CPE if possible.

        Args:
            purl: Package URL string

        Returns:
            CPE string or None
        """
        # Simple mapping for common packages
        # In production, use a comprehensive mapping database

        match = re.match(r"pkg:([^/]+)/([^@]+)(?:@(.+))?", purl)
        if not match:
            return None

        ecosystem, name, version = match.groups()

        # Map common packages to CPE
        # This is a simplified example - real implementation would need
        # a comprehensive mapping database
        cpe_mappings = {
            ("npm", "express"): "cpe:2.3:a:expressjs:express",
            ("npm", "lodash"): "cpe:2.3:a:lodash:lodash",
            ("pypi", "django"): "cpe:2.3:a:djangoproject:django",
            ("pypi", "flask"): "cpe:2.3:a:palletsprojects:flask",
            ("maven", "log4j-core"): "cpe:2.3:a:apache:log4j",
        }

        key = (ecosystem.lower(), name.lower())
        cpe_prefix = cpe_mappings.get(key)

        if cpe_prefix and version:
            return f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"

        return None

    def _parse_response(self, response: Dict[str, Any]) -> List[Vulnerability]:
        """Parse NVD API response into Vulnerability objects.

        Args:
            response: Raw API response

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        for item in response.get("vulnerabilities", []):
            try:
                cve_data = item.get("cve", {})
                vuln = self._parse_vulnerability(cve_data)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing NVD vulnerability: {e}")
                continue

        return vulnerabilities

    def _parse_vulnerability(self, data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse a single CVE entry.

        Args:
            data: Raw CVE data

        Returns:
            Vulnerability object or None if parsing fails
        """
        # Get CVE ID
        vuln_id = data.get("id", "")
        if not vuln_id:
            return None

        # Parse descriptions
        summary = ""
        details = ""
        descriptions = data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                details = desc.get("value", "")
                summary = details[:200] if len(details) > 200 else details
                break

        # Parse metrics (CVSS)
        severity = Severity.UNKNOWN
        cvss_score = None
        cvss_vector = None

        metrics = data.get("metrics", {})

        # Try CVSS v3 first
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0] if metrics["cvssMetricV31"] else {}
            cvss_v3 = cvss_data.get("cvssData", {})
            cvss_score = cvss_v3.get("baseScore")
            cvss_vector = cvss_v3.get("vectorString")
            severity = self.normalize_severity(cvss_v3.get("baseSeverity", ""))

        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0] if metrics["cvssMetricV30"] else {}
            cvss_v3 = cvss_data.get("cvssData", {})
            cvss_score = cvss_v3.get("baseScore")
            cvss_vector = cvss_v3.get("vectorString")
            severity = self.normalize_severity(cvss_v3.get("baseSeverity", ""))

        # Fall back to CVSS v2
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0] if metrics["cvssMetricV2"] else {}
            cvss_v2 = cvss_data.get("cvssData", {})
            cvss_score = cvss_v2.get("baseScore")
            cvss_vector = cvss_v2.get("vectorString")
            severity = self.normalize_severity(cvss_v2.get("baseSeverity", ""))

        # Use score to determine severity if needed
        if cvss_score and severity == Severity.UNKNOWN:
            severity = self.cvss_to_severity(cvss_score)

        # Parse dates
        published_date = None
        modified_date = None

        if "published" in data:
            try:
                published_date = datetime.fromisoformat(data["published"].replace("Z", "+00:00"))
            except Exception:
                pass

        if "lastModified" in data:
            try:
                modified_date = datetime.fromisoformat(data["lastModified"].replace("Z", "+00:00"))
            except Exception:
                pass

        # Parse affected versions from configurations
        affected_versions = []
        configurations = data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        version_start = cpe_match.get("versionStartIncluding")
                        version_end = cpe_match.get("versionEndExcluding")

                        if version_start and version_end:
                            affected_versions.append(f">={version_start}, <{version_end}")
                        elif version_start:
                            affected_versions.append(f">={version_start}")
                        elif version_end:
                            affected_versions.append(f"<{version_end}")

        # Get CWE IDs
        cwe_ids = []
        weaknesses = data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id and cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)

        # Get references
        references = []
        for ref in data.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

        return Vulnerability(
            id=vuln_id,
            source=self.source,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            summary=summary,
            details=details,
            affected_versions=list(set(affected_versions)),
            fixed_versions=[],  # NVD doesn't typically provide fixed versions
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            cwe_ids=cwe_ids,
            aliases=[],
        )
