"""Base client for vulnerability database APIs."""

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from packageurl import PackageURL

from ..models import Severity, Vulnerability, VulnerabilitySource


class RateLimitError(Exception):
    """Raised when API rate limit is exceeded."""

    pass


class UnsupportedQueryError(Exception):
    """Raised when a source structurally cannot answer a given identifier.

    Distinct from a failure: nothing went wrong, the question simply cannot be
    put to this source. OSV and GitHub take PURLs but not CPEs; NVD takes CPEs
    and only the PURLs it can convert. Returning an empty list for these made
    "cannot ask" indistinguishable from "asked, found nothing".
    """

    pass


class MissingCredentialError(Exception):
    """Raised when a source refused the request for want of a credential.

    Distinct from a failure and from an unsupported query: the source is
    reachable and the question is answerable, but not by this caller. The fix
    is a token, and saying so is more use than relaying a bare 403.
    """

    pass


class BaseClient(ABC):
    """Abstract base class for vulnerability API clients."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        verbose: bool = False,
        max_concurrent: int = 5,
    ):
        """Initialize the client.

        Args:
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verbose: Enable verbose output
            max_concurrent: Requests this client may have in flight at once

        Raises:
            ValueError: If max_concurrent is below 1, which would deadlock
        """
        if max_concurrent < 1:
            # asyncio.Semaphore(0) blocks forever rather than erroring, so a
            # zero here would hang the query instead of failing it.
            raise ValueError(f"max_concurrent must be at least 1, got {max_concurrent}")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        # Built on first use rather than here. Before Python 3.10 a Semaphore
        # binds to the current event loop at construction, so constructing a
        # client outside a running loop raised "there is no current event
        # loop" - which any caller that had already used asyncio.run() hit -
        # and a client reused across loops kept a semaphore bound to a closed
        # one.
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._semaphore_loop: Optional[asyncio.AbstractEventLoop] = None
        # Populated per query with records the source returned but this client
        # could not turn into a finding. Below the all-records-failed threshold
        # those used to disappear into a verbose print, so a result short a few
        # advisories was indistinguishable from a complete one.
        self.parse_warnings: List[str] = []

    def _concurrency_guard(self) -> asyncio.Semaphore:
        """Return a semaphore bound to the loop currently running.

        Called from inside the loop, so there is always one to bind to, and
        rebuilt when the loop changes because the engine creates a fresh loop
        per query while reusing its clients.

        Returns:
            The semaphore limiting concurrent requests for this client
        """
        try:
            loop: Optional[asyncio.AbstractEventLoop] = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
            self._semaphore_loop = loop

        return self._semaphore

    @staticmethod
    def _queried_version(purl: str) -> Optional[str]:
        """Return the version the PURL pins, if any.

        Sources that filter by version do so only when the query carries one.
        A versionless PURL gets every advisory for the package back, and
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

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        """Parse a source timestamp, or return nothing.

        Every source writes UTC as a trailing Z, which fromisoformat did not
        accept before Python 3.11. This was copied into six places across three
        clients, each in a bare try/except, so a fix to one left the rest as
        they were. That is how the naive-versus-aware crash arrived the first
        time: one client returning a shape the others did not.

        Args:
            value: Whatever the source put in its date field

        Returns:
            The timestamp, or None if it is absent or unparseable
        """
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _ecosystem_of(purl: Optional[str]) -> Optional[str]:
        """Return the PURL type, which decides how versions are ordered.

        Args:
            purl: Package URL string, or None for a CPE or hash query

        Returns:
            The type, or None when there is no package to speak of
        """
        if not purl:
            return None
        try:
            return PackageURL.from_string(purl).type
        except Exception:
            return None

    @staticmethod
    def _normalize_cwe_ids(values: Any) -> List[str]:
        """Return CWE identifiers from whatever shape a source used.

        Sources disagree: OSV writes a list of strings under
        database_specific.cwe_ids, NVD a nested weakness description, and some
        feeds a list of objects with a cwe_id that may be a bare integer.
        Anything that is not a CWE identifier is dropped rather than reported
        as one.

        Args:
            values: The source's weakness field, in any of its shapes

        Returns:
            Deduplicated CWE identifiers, in the order the source gave them
        """
        found: List[str] = []
        for value in values if isinstance(values, list) else []:
            if isinstance(value, dict):
                value = value.get("cwe_id") or value.get("cweId") or value.get("id")
            if isinstance(value, int):
                value = f"CWE-{value}"
            if not isinstance(value, str):
                continue
            candidate = value.strip().upper()
            if candidate.isdigit():
                # A bare number is a CWE too: "89", not "CWE-89".
                candidate = f"CWE-{candidate}"
            if not candidate.startswith("CWE-"):
                continue
            if candidate not in found:
                found.append(candidate)
        return found

    def _begin_query(self) -> None:
        """Clear per-query state before a new lookup.

        Called at the top of every query method so warnings describe the query
        being answered rather than accumulating across a client's lifetime.
        """
        self.parse_warnings = []

    def _note_dropped_records(self, dropped: int, total: int, detail: str = "") -> None:
        """Record that part of a source's answer could not be parsed.

        Args:
            dropped: Number of records that failed to parse
            total: Number of records the source returned
            detail: Optional last error message for context
        """
        if dropped <= 0:
            return
        message = (
            f"{dropped} of {total} records returned could not be parsed and are "
            "missing from this result"
        )
        if detail:
            message += f" (last error: {detail})"
        self.parse_warnings.append(message)

    @property
    @abstractmethod
    def source(self) -> VulnerabilitySource:
        """Return the vulnerability source identifier."""
        pass

    @property
    @abstractmethod
    def base_url(self) -> str:
        """Return the base URL for the API."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_session()

    async def start_session(self):
        """Start the aiohttp session."""
        if not self.session:
            timeout_config = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout_config)

    async def close_session(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    @staticmethod
    def _retry_hint(headers: Any) -> str:
        """Describe when a rate-limited request may be retried.

        Retry-After is a delay in seconds, but X-RateLimit-Reset is an epoch
        timestamp - reporting it as a delay produced advice like "retry after
        1786958411 seconds".

        Args:
            headers: Response headers

        Returns:
            A human-readable retry hint
        """
        retry_after = headers.get("Retry-After")
        if retry_after:
            return f"Retry after {retry_after} seconds."

        reset = headers.get("X-RateLimit-Reset")
        if reset:
            try:
                seconds = int(float(reset)) - int(time.time())
            except (TypeError, ValueError, OverflowError):
                return "Retry later."
            if seconds > 0:
                return f"Resets in {seconds} seconds."
            return "Resets shortly."

        return "Retry later."

    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make an HTTP request with retries.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            **kwargs: Additional arguments for the request

        Returns:
            Response data as dictionary

        Raises:
            RateLimitError: If rate limit is exceeded
            aiohttp.ClientError: For other HTTP errors
        """
        if not self.session:
            await self.start_session()

        async with self._concurrency_guard():  # Rate limiting
            last_error = None

            for attempt in range(self.max_retries):
                try:
                    if self.verbose and attempt > 0:
                        print(f"Retry attempt {attempt + 1} for {url}")

                    async with self.session.request(method, url, **kwargs) as response:
                        # Check for rate limiting
                        # GitHub signals its primary rate limit with 403 and
                        # a remaining-count of zero, not 429, so a 429-only
                        # check leaves the common case in the generic branch.
                        rate_limited = response.status == 429 or (
                            response.status == 403
                            and response.headers.get("X-RateLimit-Remaining") == "0"
                        )
                        if rate_limited:
                            raise RateLimitError(
                                f"Rate limit exceeded. {self._retry_hint(response.headers)}"
                            )

                        response.raise_for_status()

                        # Return JSON response
                        return await response.json()

                except RateLimitError:
                    raise  # Don't retry rate limit errors
                except aiohttp.ClientError as e:
                    last_error = e
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(2**attempt)  # Exponential backoff
                    continue

            if last_error:
                raise last_error

    @abstractmethod
    async def query_purl(self, purl: str) -> List[Vulnerability]:
        """Query vulnerabilities for a Package URL.

        Args:
            purl: Package URL string

        Returns:
            List of normalized Vulnerability objects
        """
        pass

    @abstractmethod
    async def query_cpe(self, cpe: str) -> List[Vulnerability]:
        """Query vulnerabilities for a CPE string.

        Args:
            cpe: CPE string

        Returns:
            List of normalized Vulnerability objects
        """
        pass

    def normalize_severity(self, severity: str) -> Severity:
        """Normalize severity string to standard enum.

        Args:
            severity: Raw severity string

        Returns:
            Normalized Severity enum value
        """
        if not severity:
            return Severity.UNKNOWN

        severity = severity.upper()

        # Common mappings
        mappings = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "NONE": Severity.NONE,
            "INFO": Severity.NONE,
            "INFORMATIONAL": Severity.NONE,
        }

        return mappings.get(severity, Severity.UNKNOWN)

    def cvss_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to severity level.

        Args:
            score: CVSS score (0-10)

        Returns:
            Severity enum value
        """
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        else:
            return Severity.NONE
