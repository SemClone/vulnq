"""NIST NVD API client."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from .base import BaseClient, UnsupportedQueryError


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
        self._begin_query()

        # Try to convert PURL to CPE
        cpe = self._purl_to_cpe(purl)
        if not cpe:
            # NVD is CPE-keyed. An ecosystem with no CPE mapping cannot be
            # asked at all, which is not the same as being asked and coming
            # back clean.
            raise UnsupportedQueryError(f"NVD cannot resolve {purl} to a CPE")
        return await self.query_cpe(cpe)

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Args:
            cpe: CPE string

        Returns:
            List of normalized Vulnerability objects
        """
        self._begin_query()

        # Clean CPE string
        if not cpe.startswith("cpe:"):
            cpe = f"cpe:{cpe}"

        params = {"cpeName": cpe, "resultsPerPage": 100}

        # Failures propagate: the caller records them as errors and omits the
        # source from sources_checked. Swallowing them here made an outage
        # indistinguishable from a package with no known vulnerabilities.
        response = await self._make_request(
            "GET", self.base_url, params=params, headers=self._get_headers()
        )
        # NVD caps a page at 100 and rate-limits hard enough that paging a
        # 6000-result CPE is not viable inside one query. Reporting the
        # shortfall is: 100 of 6332 presented as a whole answer is the same
        # false-complete result this client exists to avoid.
        total = response.get("totalResults")
        returned = len(response.get("vulnerabilities") or [])
        if isinstance(total, int) and total > returned:
            self.parse_warnings.append(
                f"nvd returned only {returned} of {total} records for {cpe}; the rest were "
                "not fetched. Narrow the CPE to see them"
            )

        return self._parse_response(response, self._cpe_version(cpe))

    @staticmethod
    def _cpe_version(cpe: str) -> Optional[str]:
        """Return the version a CPE pins, if it pins one.

        NVD matches cpeName server-side, so a versioned CPE is version-filtered
        by NVD itself. A wildcard version is not, and reporting those findings
        as version-matched would claim a check nobody ran.

        Args:
            cpe: CPE string, 2.3 or legacy

        Returns:
            The pinned version, or None for a wildcard or malformed CPE
        """
        parts = cpe.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>
        if len(parts) > 5 and parts[1] == "2.3":
            version = parts[5]
        elif len(parts) > 4 and parts[1].startswith("/"):
            # Legacy cpe:/a:vendor:product:version
            version = parts[4]
        else:
            return None
        return version if version and version not in ("*", "-") else None

    def _purl_to_cpe(self, purl: str) -> Optional[str]:
        """Convert PURL to CPE if possible.

        Args:
            purl: Package URL string

        Returns:
            CPE string or None
        """
        # A hardcoded table that returns a *wrong* CPE is worse than one that
        # returns nothing: NVD accepts the bogus name, answers with zero
        # results, and the source counts as checked. Every entry below is
        # verified against live NVD data; add nothing here unverified.

        match = re.match(r"pkg:([^/]+)/([^@]+)(?:@(.+))?", purl)
        if not match:
            return None

        ecosystem, name, version = match.groups()

        # Map common packages to CPE
        # This is a simplified example - real implementation would need
        # a comprehensive mapping database
        cpe_mappings = {
            ("npm", "express"): "cpe:2.3:a:openjsf:express",
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

    def _parse_response(
        self, response: Dict[str, Any], queried_version: Optional[str] = None
    ) -> List[Vulnerability]:
        """Parse NVD API response into Vulnerability objects.

        Args:
            response: Raw API response
            queried_version: Version pinned by the queried CPE, if any

        Returns:
            List of Vulnerability objects

        Raises:
            RuntimeError: If NVD returned records and none could be parsed
        """
        vulnerabilities = []
        items = response.get("vulnerabilities", [])
        parse_failures = 0
        last_error = ""

        for item in items:
            try:
                cve_data = item.get("cve", {})
                vuln = self._parse_vulnerability(cve_data, queried_version)
                if vuln:
                    vulnerabilities.append(vuln)
                else:
                    # _parse_vulnerability returns None only for a CVE with no
                    # id, which is malformed rather than inapplicable. NVD
                    # filters by version server-side, so nothing that reaches
                    # here is legitimately skippable.
                    parse_failures += 1
            except Exception as e:
                parse_failures += 1
                last_error = str(e)
                if self.verbose:
                    print(f"Error parsing NVD vulnerability: {e}")
                continue

        # Every record failing to parse means the response shape changed, not
        # that the package is clean.
        if items and parse_failures == len(items):
            raise RuntimeError(f"NVD returned {len(items)} records but none could be parsed")

        # Below that threshold the query still has an answer, just not a whole
        # one. Say so rather than handing back a short list that looks complete.
        self._note_dropped_records(parse_failures, len(items), last_error)

        return vulnerabilities

    def _parse_vulnerability(
        self, data: Dict[str, Any], queried_version: Optional[str] = None
    ) -> Optional[Vulnerability]:
        """Parse a single CVE entry.

        Args:
            data: Raw CVE data
            queried_version: Version pinned by the queried CPE, if any

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
            version_match=(
                VersionMatch.SOURCE_FILTERED if queried_version else VersionMatch.NOT_EVALUATED
            ),
        )
