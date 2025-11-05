"""Base client for vulnerability database APIs."""

import asyncio
import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import aiohttp

from ..models import Severity, Vulnerability, VulnerabilitySource


class RateLimitError(Exception):
    """Raised when API rate limit is exceeded."""

    pass


class BaseClient(ABC):
    """Abstract base class for vulnerability API clients."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        verbose: bool = False,
    ):
        """Initialize the client.

        Args:
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verbose: Enable verbose output
        """
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose
        self.session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(5)  # Limit concurrent requests

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

        async with self._semaphore:  # Rate limiting
            last_error = None

            for attempt in range(self.max_retries):
                try:
                    if self.verbose and attempt > 0:
                        print(f"Retry attempt {attempt + 1} for {url}")

                    async with self.session.request(method, url, **kwargs) as response:
                        # Check for rate limiting
                        if response.status == 429:
                            retry_after = response.headers.get("Retry-After", "60")
                            raise RateLimitError(
                                f"Rate limit exceeded. Retry after {retry_after} seconds"
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

    def generate_vuln_id(self, vuln_data: Dict[str, Any]) -> str:
        """Generate a consistent ID for deduplication.

        Args:
            vuln_data: Vulnerability data dictionary

        Returns:
            Hashed identifier string
        """
        # Create a consistent hash from key fields
        key_parts = [
            str(vuln_data.get("id", "")),
            str(vuln_data.get("cve", "")),
            str(vuln_data.get("summary", "")),
            str(self.source.value),
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]
