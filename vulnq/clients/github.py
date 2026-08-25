"""GitHub Advisory Database API client."""

from typing import Any, Dict, List, Optional, Tuple

from packageurl import PackageURL

from ..cvss import coerce_score
from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from ..versions import evaluate_range
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

# How a PURL's namespace and name combine into the package name GitHub's
# advisory database is keyed by. Passing the PURL name through unchanged asked
# GitHub about packages that cannot exist - "org.apache.logging.log4j/log4j-core"
# for every canonical Maven coordinate - and GitHub answered honestly with zero
# advisories, which the caller then read as a clean scan.
#
# - "colon": Maven's group:artifact
# - "slash": a path-shaped name, already correct once percent-decoding is done
# - "name": namespace is not part of the key
_NAME_STYLE = {
    "maven": "colon",
    "npm": "slash",
    "go": "slash",
    "golang": "slash",
    "composer": "slash",
    "swift": "slash",
    "githubactions": "slash",
    "pypi": "name",
    "gem": "name",
    "nuget": "name",
    "cargo": "name",
    "hex": "name",
    "pub": "name",
}

# Pages of 100 advisories to fetch before giving up. GitHub holds more than a
# thousand for some packages, and stopping at the first page reported 27 of
# 1324 as if that were all of them. Reaching this cap is reported as an
# incomplete answer rather than passed off as a whole one.
MAX_PAGES = 25


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
        self._begin_query()

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

        # Build GraphQL query. totalCount and pageInfo are requested so a
        # package with more advisories than one page can hold is paged through
        # rather than cut off at 100 with nothing said about it.
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem, $package: String, $after: String) {
          securityVulnerabilities(
            first: 100, ecosystem: $ecosystem, package: $package, after: $after
          ) {
            totalCount
            pageInfo {
              hasNextPage
              endCursor
            }
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

        nodes: List[Dict[str, Any]] = []
        total_count: Optional[int] = None
        cursor: Optional[str] = None

        for _ in range(MAX_PAGES):
            variables = {"ecosystem": gh_ecosystem, "package": name, "after": cursor}

            # Failures propagate: the caller records them as errors and omits
            # the source from sources_checked. Swallowing them here made an
            # outage indistinguishable from a package with no known
            # vulnerabilities.
            response = await self._make_request(
                "POST",
                self.base_url,
                json={"query": query, "variables": variables},
                headers=self._get_headers(),
            )

            connection = self._connection(response)
            nodes.extend(connection.get("nodes") or [])
            if total_count is None:
                total_count = connection.get("totalCount")

            page_info = connection.get("pageInfo") or {}
            cursor = page_info.get("endCursor")
            if not page_info.get("hasNextPage") or not cursor:
                break

        # A short list that looks complete is the failure this client keeps
        # being bitten by. If the page cap stopped us, say how much is missing.
        if total_count is not None and len(nodes) < total_count:
            self.parse_warnings.append(
                f"returned only {len(nodes)} of {total_count} advisories for {name}; "
                f"the rest were not fetched (page limit of {MAX_PAGES} reached)"
            )

        return self._parse_nodes(nodes, version, ecosystem)

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Note: the GitHub Advisory Database is keyed by ecosystem and package
        name, with no CPE lookup.

        Args:
            cpe: CPE string

        Raises:
            UnsupportedQueryError: Always; GitHub has no CPE lookup
        """
        self._begin_query()
        raise UnsupportedQueryError("GitHub Advisory Database cannot be queried by CPE; use a PURL")

    def _parse_purl(self, purl: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse a PURL into (ecosystem, GitHub package name, version).

        The name is the one GitHub's advisory database is keyed by, which is
        not always the PURL name: Maven uses "group:artifact", and npm scopes
        arrive percent-encoded and have to be decoded.

        Args:
            purl: Package URL string

        Returns:
            Tuple of (purl type, GitHub package name, version), all None if the
            PURL cannot be parsed

        Raises:
            UnsupportedQueryError: If the name cannot be built for the
                ecosystem, which is a question GitHub cannot be asked rather
                than one it answered with nothing
        """
        try:
            parsed = PackageURL.from_string(purl)
        except Exception:
            return None, None, None

        if not parsed.type or not parsed.name:
            return None, None, None

        # packageurl-python percent-decodes for us, so "%40scope" is already
        # "@scope" by the time it reaches here.
        style = _NAME_STYLE.get(parsed.type.lower())

        if style == "colon":
            if not parsed.namespace:
                # A Maven coordinate without a group cannot be looked up: the
                # key GitHub holds is always "group:artifact". Asking for the
                # bare artifact returns a confident zero.
                raise UnsupportedQueryError(
                    f"Maven PURL has no group, so no GitHub package name exists: {purl}"
                )
            name = f"{parsed.namespace}:{parsed.name}"
        elif style == "slash":
            name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
        elif style == "name":
            name = parsed.name
        else:
            # An unmapped type is caught by the ECOSYSTEM_MAP check in the
            # caller, which reports it as unsupported. Falling back to the
            # PURL's own shape here keeps that the single place it is decided.
            name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name

        return parsed.type, name, parsed.version

    def _connection(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Validate one GraphQL page and return its connection object.

        Args:
            response: Raw API response for a single page

        Returns:
            The securityVulnerabilities connection

        Raises:
            RateLimitError: If GitHub refused the request for rate limiting
            RuntimeError: If the response carries errors or no data
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

        return response["data"].get("securityVulnerabilities") or {}

    def _parse_nodes(
        self,
        vulns: List[Dict[str, Any]],
        target_version: Optional[str],
        ecosystem: Optional[str] = None,
    ) -> List[Vulnerability]:
        """Turn advisory nodes into Vulnerability objects.

        Args:
            vulns: Advisory nodes, possibly gathered across several pages
            target_version: Specific version to check (optional)
            ecosystem: PURL type, used to order versions correctly

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
                vuln = self._parse_vulnerability(vuln_data, target_version, ecosystem)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                # Counted, not just skipped. A returned None means the record
                # legitimately does not apply - a version outside the affected
                # range - and must stay distinct from a record that broke.
                parse_failures += 1
                last_error = str(e)
                if self.verbose:
                    print(f"Error parsing GitHub vulnerability: {e}")
                continue

        # Every record failing to parse means the response shape changed, not
        # that the package is clean.
        if vulns and parse_failures == len(vulns):
            raise RuntimeError(f"GitHub returned {len(vulns)} advisories but none could be parsed")

        # Below that threshold the query still has an answer, just not a whole
        # one. Say so rather than handing back a short list that looks complete.
        self._note_dropped_records(parse_failures, len(vulns), last_error)

        return vulnerabilities

    def _parse_vulnerability(
        self,
        data: Dict[str, Any],
        target_version: Optional[str],
        ecosystem: Optional[str] = None,
    ) -> Optional[Vulnerability]:
        """Parse a single vulnerability entry.

        Args:
            data: Raw vulnerability data
            target_version: Specific version to check
            ecosystem: PURL type, used to order versions correctly

        Returns:
            Vulnerability object or None if not applicable
        """
        advisory = data.get("advisory") or {}
        if not advisory:
            # Malformed, not inapplicable: GitHub declares advisory non-null,
            # so its absence is a shape change. Raising keeps it countable by
            # the all-records-failed guard, which only sees exceptions.
            raise ValueError("GitHub advisory node has no advisory")

        # Get vulnerability ID
        vuln_id = advisory.get("ghsaId", "")
        if not vuln_id:
            # Also malformed rather than inapplicable.
            raise ValueError("GitHub advisory has no ghsaId")

        # Check if version is affected (if specified)
        version_match = VersionMatch.NOT_EVALUATED
        if target_version:
            in_range = evaluate_range(
                ecosystem, target_version, data.get("vulnerableVersionRange", "") or ""
            )
            if in_range is False:
                # The only legitimate None: the record parsed fine and simply
                # does not apply to the version asked about.
                return None
            version_match = VersionMatch.AFFECTED if in_range else VersionMatch.UNCONFIRMED

        # Parse severity
        severity_str = advisory.get("severity", "UNKNOWN")
        severity = self.normalize_severity(severity_str)

        # Parse CVSS
        cvss_score = None
        cvss_vector = None
        cvss_data = advisory.get("cvss", {})
        if cvss_data:
            cvss_score = coerce_score(cvss_data.get("score"))
            cvss_vector = cvss_data.get("vectorString")

            # GitHub returns score 0.0 with a null vector for an advisory it
            # never scored, and around one PIP advisory in eight arrives that
            # way. A genuine 0.0 always carries the vector it was computed
            # from, so a bare 0.0 is an absent score rather than "no impact".
            # Left as a real score it prints as 0.0, blocks another source's
            # real score during the merge, and reads to any downstream gate as
            # harmless.
            if cvss_score == 0.0 and not cvss_vector:
                cvss_score = None

            # Use CVSS score for severity if not already set
            if cvss_score is not None and severity == Severity.UNKNOWN:
                severity = self.cvss_to_severity(cvss_score)

        # Get identifiers (CVE, etc.)
        aliases = []
        for identifier in advisory.get("identifiers", []):
            if identifier.get("type") == "CVE":
                aliases.append(identifier.get("value"))

        # Parse dates
        published_date = self._parse_timestamp(advisory.get("publishedAt"))
        modified_date = self._parse_timestamp(advisory.get("updatedAt"))

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
            version_match=version_match,
        )
