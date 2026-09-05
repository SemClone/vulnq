"""OSV.dev API client."""

import re
from typing import Any, Dict, List, Optional

from packageurl import PackageURL

from ..cvss import base_score, coerce_score
from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from ..versions import sort_versions
from .base import BaseClient, UnsupportedQueryError

# Pages to fetch before giving up. OSV returns up to 1000 records per page and
# hands back a token for the rest; ignoring it reported 3000 of an unknown
# larger total as if that were the whole answer.
MAX_PAGES = 10


# OSV keys its Alpine advisories by release branch - the ecosystem is
# "Alpine:v3.16", never a bare "Alpine" - and its PURL index does not reach
# pkg:apk at all. An apk coordinate therefore comes back as {} rather than an
# error, which is indistinguishable from a package with nothing against it:
#
#     pkg:apk/alpine/openssl@1.1.1q-r0                    0 records
#     name=openssl, ecosystem=Alpine:v3.16, version=...   9 records
#
# Asking by name and ecosystem is the only way to see that data. Only Alpine
# needs it: pkg:apk/wolfi and pkg:apk/chainguard resolve through the PURL index
# today, and their advisories sit under a bare "Wolfi" and "Chainguard" with no
# branch to name, so they must keep going out as PURLs.
_ALPINE_NAMESPACE = "alpine"

# The branch lives in the distro qualifier, which tools spell differently:
# syft writes "alpine-3.16.2", trivy "3.16.2", others "v3.16". OSV names a
# branch with two components and no more - "Alpine:v3.16.2" matches nothing -
# so a third is read and dropped.
_ALPINE_BRANCH = re.compile(r"(\d+)\.(\d+)")


# OSV writes a 3.x or 4.0 vector with its CVSS: prefix. The schema also allows
# CVSS_V2, which has no prefix and looks like "AV:L/AC:M/Au:N/C:P/I:P/A:P", so
# matching on the prefix alone would drop it. No live OSV record carries one
# today - a census of six ecosystems found CVSS_V3, CVSS_V4 and nothing else -
# so this is defensive rather than a fix for observed data loss.
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

        # Alpine is asked by name and branch; everything else by PURL.
        query = self._alpine_query(purl) or {"package": {"purl": purl}}

        for _ in range(MAX_PAGES):
            data: Dict[str, Any] = dict(query)
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

        return self._parse_vulns(vulns, self._queried_version(purl), self._ecosystem_of(purl))

    def _alpine_query(self, purl: str) -> Optional[Dict[str, Any]]:
        """Return an Alpine name-and-branch query body for an apk PURL.

        Args:
            purl: Package URL string, of any type

        Returns:
            A request body naming the package and its Alpine branch, or None
            for anything that should go out as a PURL instead
        """
        try:
            parsed = PackageURL.from_string(purl)
        except Exception:
            return None

        if parsed.type != "apk" or (parsed.namespace or "").lower() != _ALPINE_NAMESPACE:
            return None

        branch = _ALPINE_BRANCH.search((parsed.qualifiers or {}).get("distro") or "")
        if not branch:
            # There is no branch to ask about, so the PURL query runs and comes
            # back empty. Saying why keeps that apart from a clean package.
            self.parse_warnings.append(
                f"no Alpine release named in a distro= qualifier on {purl}; OSV keys its "
                "Alpine advisories by release, so none were checked"
            )
            return None

        query: Dict[str, Any] = {
            "package": {
                "name": parsed.name,
                "ecosystem": f"Alpine:v{branch.group(1)}.{branch.group(2)}",
            }
        }
        # A versionless PURL asks for every advisory against the package, and
        # OSV filters by version only when the query carries one.
        if parsed.version:
            query["version"] = parsed.version

        return query

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

    def _parse_vulns(
        self,
        vulns: List[Dict[str, Any]],
        queried_version: Optional[str] = None,
        ecosystem: Optional[str] = None,
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
                vuln = self._parse_vulnerability(vuln_data, queried_version, ecosystem)
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
        self,
        data: Dict[str, Any],
        queried_version: Optional[str] = None,
        ecosystem: Optional[str] = None,
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

        published_date = self._parse_timestamp(data.get("published"))

        modified_date = self._parse_timestamp(data.get("modified"))

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
            # sorted, not list(set(...)): Python randomizes string hashing
            # per process, so the same advisory came back in a different order
            # on every run. Two scans of one package could not be diffed
            # without phantom changes, and nothing downstream could checksum
            # the envelope.
            affected_versions=sort_versions(ecosystem, affected_versions),
            fixed_versions=sort_versions(ecosystem, fixed_versions),
            published_date=published_date,
            modified_date=modified_date,
            references=references,
            # OSV does carry these, in the block GitHub-sourced advisories use.
            # Declared and hardcoded empty, the field read as "this advisory
            # has no classification" rather than "we did not extract one", and
            # CWE-506 and CWE-912 are what separate a package that is malware
            # from one whose description merely mentions malicious input.
            cwe_ids=self._normalize_cwe_ids((data.get("database_specific") or {}).get("cwe_ids")),
            aliases=aliases,
            version_match=(
                VersionMatch.SOURCE_FILTERED if queried_version else VersionMatch.NOT_EVALUATED
            ),
        )
