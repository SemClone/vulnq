"""VulnerableCode API client.

Written against the v3 API, which is the only one the public instance serves.
The v1 endpoints this client used to call are gone: `/api/packages/` answers
404, and the 403 seen before that is a missing `User-Agent: VCIO_API_AGENT`
rather than a missing token. Anonymous access works and is throttled at ten
requests a minute; a token raises that.

Two requests are needed per query, because the two endpoints carry different
halves of the answer. `/api/v3/packages/` says which advisories affect the
package and which versions fix it; `/api/v3/advisories/` carries the
severities, the CVSS vectors and the weaknesses. Every shape below was
recorded from the live API into tests/fixtures/vulnerablecode.
"""

from typing import Any, Dict, List, Optional

import aiohttp
from packageurl import PackageURL

from ..cvss import base_score, coerce_score
from ..models import Severity, VersionMatch, Vulnerability, VulnerabilitySource
from ..versions import sort_versions
from .base import BaseClient, MissingCredentialError, RateLimitError, UnsupportedQueryError

DEFAULT_BASE_URL = "https://public.vulnerablecode.io/api"

# Enough for the largest package I could find; tensorflow needs eight.
MAX_PAGES = 25

# The public instance rejects any other value, whatever the token says, so it
# is not optional and not a courtesy.
REQUIRED_USER_AGENT = "VCIO_API_AGENT"

# Distribution packages are stored qualified here: a Debian package comes back
# as ...?distro=trixie and a Red Hat one as five per-arch variants. Their
# advisories are reachable only under those spellings, and the package endpoint
# reports nothing for them either way, so this client would answer a confident
# clean for exactly the SBOM inputs VulnerableCode exists to cover. Answering
# them properly also needs telling an affected relation from a fixing one,
# which the advisory endpoint does not distinguish. Until that is done, the
# question is refused rather than answered wrongly.
_DISTRO_ECOSYSTEMS = frozenset(
    {"deb", "debian", "ubuntu", "rpm", "redhat", "suse", "opensuse", "alpine", "apk"}
)

# Which scoring systems may fill cvss_score, newest specification first. The
# identifiers are VulnerableCode's own, from vulnerabilities/severity_systems.py.
# Nothing outside this tuple qualifies: an EPSS row is a probability between
# zero and one, and reporting 0.97 as a CVSS score reads as LOW.
_CVSS_SYSTEMS = ("cvssv4", "cvssv3.1", "cvssv3", "cvssv2")


class VulnerableCodeClient(BaseClient):
    """Client for the VulnerableCode aggregated vulnerability database."""

    def __init__(self, *args: Any, base_url: Optional[str] = None, **kwargs: Any) -> None:
        """Initialize the client.

        Args:
            *args: Passed to BaseClient
            base_url: API root, for an instance other than the public one
            **kwargs: Passed to BaseClient
        """
        super().__init__(*args, **kwargs)
        self._base_url = base_url.rstrip("/") if base_url else None

    @property
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier.

        It aggregates other databases, but it is still the source that was
        asked and the one that answered. Labelling its findings as OSV
        contradicted sources_checked in the same envelope.
        """
        return VulnerabilitySource.VULNERABLECODE

    @property
    def base_url(self) -> str:
        """Return the API root to query.

        Returns:
            The configured instance, or the public one
        """
        return self._base_url or DEFAULT_BASE_URL

    def _get_headers(self) -> Dict[str, str]:
        """Return request headers.

        The User-Agent is required by the public instance and is what the
        earlier 403 was actually about. The token is optional and raises the
        rate limit; VulnerableCode authenticates with Django REST Framework's
        TokenAuthentication, so the scheme is "Token", not "Bearer".

        Returns:
            Headers for the request
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": REQUIRED_USER_AGENT,
        }
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"
        return headers

    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects

        Raises:
            MissingCredentialError: If the instance refuses the request and no
                token is configured
            RateLimitError: If the instance is throttling us
        """
        self._begin_query()

        parsed = self._parsed(purl)

        if parsed is not None and (parsed.type or "").lower() in _DISTRO_ECOSYSTEMS:
            # The instance stores these qualified: a Debian package comes back
            # echoed as ...?distro=trixie, and its advisories are reachable
            # only under that spelling. Asking bare, as this client does,
            # would report a confident clean scan for a package the instance
            # holds CVEs about.
            raise UnsupportedQueryError(
                f"VulnerableCode stores {parsed.type} packages under distribution and "
                "architecture qualifiers this client cannot yet resolve, so asking it "
                "would report a clean scan for a package it holds advisories about"
            )

        if parsed is not None and not parsed.version:
            # Both endpoints answer nothing for a versionless PURL, which is
            # not the same as the package having nothing.
            raise UnsupportedQueryError(
                "VulnerableCode answers nothing for a PURL with no version; "
                "give the version you are asking about"
            )

        # The instance matches the PURL it was given, verbatim. A qualifier or
        # subpath an SBOM routinely carries turns a hit into a miss:
        # log4j-core@2.14.1?type=jar returns nothing where the bare coordinate
        # returns twelve advisories, Log4Shell among them. Percent-encoding
        # matters too: pkg:npm/@babel/traverse finds nothing, %40babel finds
        # the advisory. So the canonical spelling is sent, and the instance is
        # asked to disregard the parts that only narrow the match.
        # The advisory endpoint has no ignore_qualifiers_subpath option, and
        # matches verbatim, so a qualifier costs the severities rather than
        # the findings: log4j-core@2.14.1?type=jar returned seven findings
        # with no score and no classification at all. Both endpoints are given
        # the same bare coordinate.
        bare = self._bare(purl)

        query = {
            "purls": [bare],
            "details": True,
            "ignore_qualifiers_subpath": True,
        }

        packages = await self._post("/v3/packages/", query)
        affected = self._affected_records(packages)
        if not affected:
            # Nothing to describe, so the second request would spend one of
            # ten requests a minute to learn nothing.
            return []

        advisories = await self._collect("/v3/advisories/", {"purls": [bare]})

        return self._parse(affected, advisories, purl)

    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Args:
            cpe: CPE string

        Raises:
            UnsupportedQueryError: Always; VulnerableCode is keyed by PURL
        """
        self._begin_query()
        raise UnsupportedQueryError("VulnerableCode cannot be queried by CPE; use a PURL")

    @staticmethod
    def _parsed(purl: str) -> Optional[PackageURL]:
        """Return the parsed PURL, or None if it is not one.

        Args:
            purl: Package URL string

        Returns:
            The parsed PURL, or None
        """
        try:
            return PackageURL.from_string(purl)
        except Exception:
            return None

    @staticmethod
    def _bare(purl: str) -> str:
        """Return the coordinate the instance stores, without the trimmings.

        Two separate spellings cost data. Percent-encoding: pkg:npm/@babel/x
        finds nothing where %40babel finds the advisory. And qualifiers or a
        subpath, which an SBOM routinely carries: the package endpoint can be
        told to disregard them, but the advisory endpoint cannot and matches
        verbatim, so a qualified PURL returns findings stripped of every
        severity. Both are handled by sending the canonical name, version and
        namespace alone.

        Args:
            purl: Package URL as the caller wrote it

        Returns:
            The bare canonical coordinate, or the input if it does not parse
        """
        try:
            parsed = PackageURL.from_string(purl)
        except Exception:
            return purl

        return str(
            PackageURL(
                type=parsed.type,
                namespace=parsed.namespace,
                name=parsed.name,
                version=parsed.version,
            )
        )

    @staticmethod
    def _affected_records(packages: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return the advisory records the package response carries.

        Args:
            packages: Response from /v3/packages/

        Returns:
            The affected-by entries, across every result
        """
        records = []
        for result in packages.get("results") or []:
            if not isinstance(result, dict):
                # Without details the endpoint returns bare PURL strings.
                continue
            for affected in result.get("affected_by_vulnerabilities") or []:
                if isinstance(affected, dict):
                    records.append(affected)
        return records

    async def _collect(self, path: str, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Read every page of a paginated response.

        The advisory endpoint pages at a hundred, and tensorflow alone has
        796. Reading only the first page left four findings in five with no
        severity, no score and no classification, reported as though the
        advisories simply had none.

        Paged by asking for a page number rather than by following the `next`
        link the response carries: that link answers 405 to both POST and GET,
        and points at http rather than https.

        Args:
            path: Path below the API root
            body: JSON request body

        Returns:
            Every result, across all pages
        """
        results: List[Dict[str, Any]] = []

        for page in range(1, MAX_PAGES + 1):
            request = dict(body) if page == 1 else {**body, "page": page}
            response = await self._post(path, request)
            results.extend(
                record for record in response.get("results") or [] if isinstance(record, dict)
            )
            if not response.get("next"):
                return results

        self.parse_warnings.append(
            f"stopped after {MAX_PAGES} pages of advisories; the rest were not fetched"
        )
        return results

    async def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Send one request, translating a refusal into something actionable.

        Args:
            path: Path below the API root
            body: JSON request body

        Returns:
            The decoded response

        Raises:
            MissingCredentialError: If refused and no token is configured
            RateLimitError: If throttled
        """
        return await self._post_url(f"{self.base_url}{path}", body)

    async def _post_url(self, url: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Send one request to an absolute URL, translating a refusal.

        Args:
            url: Absolute URL, which is what the pagination cursor gives
            body: JSON request body

        Returns:
            The decoded response

        Raises:
            MissingCredentialError: If refused and no token is configured
            RateLimitError: If throttled
        """
        try:
            return await self._make_request("POST", url, json=body, headers=self._get_headers())
        except RateLimitError as e:
            # The base client already recognises a 429. Renaming it here says
            # what would lift the limit, which the status alone does not.
            remedy = (
                "this token's rate limit has been reached"
                if self.api_key
                else "anonymous access is limited to ten requests a minute; set "
                "VULNERABLECODE_API_KEY to raise it"
            )
            raise RateLimitError(
                f"{self.base_url} is throttling this client ({e}): {remedy}."
            ) from e
        except aiohttp.ClientResponseError as e:
            if e.status in (401, 403) and not self.api_key:
                raise MissingCredentialError(
                    f"{self.base_url} refused this request. If the instance requires a "
                    "token, set VULNERABLECODE_API_KEY or pass --vulnerablecode-api-key."
                ) from e
            raise

    def _parse(
        self, affected: List[Dict[str, Any]], advisories: List[Dict[str, Any]], purl: str
    ) -> List[Vulnerability]:
        """Join the two responses into findings.

        Args:
            affected: Advisory records from /v3/packages/
            advisories: Advisory records from /v3/advisories/, all pages
            purl: The PURL that was queried

        Returns:
            List of Vulnerability objects

        Raises:
            RuntimeError: If records were returned and none could be parsed,
                which means the response shape moved rather than the package
                being clean
        """
        detail = {
            record["advisory_id"]: record
            for record in advisories
            if isinstance(record, dict) and record.get("advisory_id")
        }

        ecosystem = self._ecosystem_of(purl)
        queried_version = self._queried_version(purl)

        findings = []
        for record in affected:
            vuln = self._build(record, detail, ecosystem, queried_version)
            if vuln:
                findings.append(vuln)

        if affected and not findings:
            # Every record refused to parse. The package is not clean; the
            # shape moved, as it did when v1 was withdrawn.
            raise RuntimeError(
                f"VulnerableCode returned {len(affected)} records but none could be parsed"
            )

        # A record the advisory endpoint did not detail is still a real
        # finding, it just has no severity. Say how many, or a consumer reads
        # UNKNOWN as "nobody rated this".
        undetailed = sum(1 for record in affected if record.get("advisory_id") not in detail)
        if undetailed:
            self.parse_warnings.append(
                f"{undetailed} of {len(affected)} advisories carry no severity detail"
            )

        return findings

    def _build(
        self,
        affected: Dict[str, Any],
        detail: Dict[str, Dict[str, Any]],
        ecosystem: Optional[str],
        queried_version: Optional[str],
    ) -> Optional[Vulnerability]:
        """Turn one affected-advisory record into a finding.

        Args:
            affected: An entry from affected_by_vulnerabilities
            detail: Advisory records from /v3/advisories/, keyed by advisory_id
            ecosystem: PURL type, which decides how versions are ordered
            queried_version: The version asked about, if any

        Returns:
            A Vulnerability, or None if the record carries no identifier
        """
        advisory_id = affected.get("advisory_id")
        if not advisory_id:
            return None

        full = detail.get(advisory_id, {})
        severity, score, vector = self._rate(full.get("severities") or [])

        return Vulnerability(
            id=advisory_id,
            source=self.source,
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            summary=(affected.get("summary") or full.get("summary") or "")[:200],
            details=affected.get("summary") or full.get("summary") or "",
            affected_versions=[],
            fixed_versions=sort_versions(ecosystem, self._fixed(affected)),
            references=[
                reference["url"]
                for reference in full.get("references") or []
                if isinstance(reference, dict) and reference.get("url")
            ],
            cwe_ids=self._normalize_cwe_ids(full.get("weaknesses")),
            aliases=list(affected.get("aliases") or full.get("aliases") or []),
            # VulnerableCode answers for the exact PURL it was given, so a
            # finding it returns is about the version that was asked about.
            version_match=(
                VersionMatch.SOURCE_FILTERED if queried_version else VersionMatch.NOT_EVALUATED
            ),
        )

    @staticmethod
    def _fixed(affected: Dict[str, Any]) -> List[str]:
        """Return the versions that fix this advisory.

        `fixed_by_packages` is a list of PURL strings rather than versions.

        Args:
            affected: An entry from affected_by_vulnerabilities

        Returns:
            The fixing versions
        """
        versions = []
        for entry in affected.get("fixed_by_packages") or []:
            if not isinstance(entry, str):
                continue
            try:
                version = PackageURL.from_string(entry).version
            except Exception:
                continue
            if version:
                versions.append(version)
        return versions

    def _rate(self, severities: List[Any]) -> tuple:
        """Choose the rating to report, and the vector it came from.

        Only CVSS systems may fill a CVSS field, newest specification first.
        An EPSS row is a probability between zero and one, and reporting 0.97
        as a base score reads as LOW.

        Args:
            severities: The advisory's severities array

        Returns:
            Tuple of (severity, score, vector)
        """
        rows = [row for row in severities if isinstance(row, dict)]

        # A vector kept in case nothing scores: a 4.0 vector cannot be scored
        # here, but a consumer can, and reporting it beats reporting nothing.
        # Held rather than returned, because returning it early would let an
        # unscoreable 4.0 row hide a perfectly good 3.1 score below it.
        fallback_vector = None

        for system in _CVSS_SYSTEMS:
            for row in rows:
                if str(row.get("scoring_system", "")).lower() != system:
                    continue
                vector = row.get("scoring_elements") or None
                score = coerce_score(row.get("value"))
                if score is None and vector:
                    # The vector is authoritative when a value is missing or
                    # unusable, and computing it is better than reporting none.
                    score = base_score(vector)
                if score is not None:
                    return self.cvss_to_severity(score), score, vector
                if vector and fallback_vector is None:
                    fallback_vector = vector

        # No CVSS row parsed, so a textual rating is the only one available.
        for row in rows:
            value = row.get("value")
            if isinstance(value, str) and coerce_score(value) is None:
                rated = self.normalize_severity(value)
                if rated is not Severity.UNKNOWN:
                    return rated, None, None

        return Severity.UNKNOWN, None, fallback_vector
