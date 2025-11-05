"""Core functionality for vulnq."""

import asyncio
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .clients import GitHubClient, NVDClient, OSVClient, RateLimitError, VulnerableCodeClient
from .models import (
    Configuration,
    IdentifierType,
    PackageInfo,
    QueryResult,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from .utils import detect_identifier_type, parse_identifier


class VulnerabilityQuery:
    """Main vulnerability query engine."""

    def __init__(self, config: Optional[Configuration] = None, verbose: bool = False):
        """Initialize the vulnerability query engine.

        Args:
            config: Configuration object
            verbose: Enable verbose output
        """
        self.config = config or self._load_config()
        self.verbose = verbose
        self._clients = self._initialize_clients()

    def _load_config(self) -> Configuration:
        """Load configuration from environment variables."""
        config = Configuration()

        # Load API keys from environment
        config.github_token = os.environ.get("GITHUB_TOKEN")
        config.nvd_api_key = os.environ.get("NVD_API_KEY")

        # Check if VulnerableCode should be used
        if os.environ.get("USE_VULNERABLECODE", "").lower() == "true":
            config.use_vulnerablecode = True

        return config

    def _initialize_clients(self) -> Dict[VulnerabilitySource, Any]:
        """Initialize API clients based on configuration."""
        clients = {}

        # Initialize VulnerableCode if enabled
        if self.config.use_vulnerablecode:
            clients[VulnerabilitySource.VULNERABLECODE] = VulnerableCodeClient(
                timeout=self.config.timeout, verbose=self.verbose
            )
            # If using VulnerableCode, it's the only source
            return clients

        # Otherwise, initialize individual sources
        if VulnerabilitySource.OSV in self.config.sources:
            clients[VulnerabilitySource.OSV] = OSVClient(
                timeout=self.config.timeout, verbose=self.verbose
            )

        if VulnerabilitySource.GITHUB in self.config.sources:
            clients[VulnerabilitySource.GITHUB] = GitHubClient(
                api_key=self.config.github_token, timeout=self.config.timeout, verbose=self.verbose
            )

        if VulnerabilitySource.NVD in self.config.sources:
            clients[VulnerabilitySource.NVD] = NVDClient(
                api_key=self.config.nvd_api_key, timeout=self.config.timeout, verbose=self.verbose
            )

        return clients

    def query(self, identifier: str) -> QueryResult:
        """Query vulnerability databases for the given identifier.

        Args:
            identifier: Software identifier (PURL, CPE, hash, etc.)

        Returns:
            QueryResult with vulnerability information
        """
        # Run async query in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._async_query(identifier))
        finally:
            loop.close()

    async def _async_query(self, identifier: str) -> QueryResult:
        """Async query implementation.

        Args:
            identifier: Software identifier

        Returns:
            QueryResult with vulnerability information
        """
        # Detect identifier type
        id_type = detect_identifier_type(identifier)

        # Parse identifier
        package_info = parse_identifier(identifier, id_type)

        # Create result object
        result = QueryResult(
            query=identifier,
            query_type=id_type,
            package_info=package_info,
            query_time=datetime.utcnow(),
        )

        # If using VulnerableCode, query it and return
        if self.config.use_vulnerablecode:
            return await self._query_vulnerablecode(identifier, id_type, package_info, result)

        # Otherwise, query all enabled sources in parallel
        vulnerabilities = await self._query_all_sources(identifier, id_type, package_info, result)

        # Deduplicate and consolidate vulnerabilities
        result.vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        return result

    async def _query_vulnerablecode(
        self,
        identifier: str,
        id_type: IdentifierType,
        package_info: Optional[PackageInfo],
        result: QueryResult,
    ) -> QueryResult:
        """Query VulnerableCode only.

        Args:
            identifier: Software identifier
            id_type: Type of identifier
            package_info: Parsed package information
            result: Result object to populate

        Returns:
            Updated QueryResult
        """
        client = self._clients.get(VulnerabilitySource.VULNERABLECODE)
        if not client:
            return result

        try:
            # Start session
            await client.start_session()

            if id_type == IdentifierType.PURL:
                vulnerabilities = await client.query_purl(identifier)
            elif id_type == IdentifierType.CPE:
                vulnerabilities = await client.query_cpe(identifier)
            else:
                vulnerabilities = []

            result.vulnerabilities = vulnerabilities
            result.sources_checked.append(VulnerabilitySource.VULNERABLECODE)

        except Exception as e:
            result.errors.append(f"VulnerableCode: {str(e)}")
            if self.verbose:
                print(f"VulnerableCode error: {e}")
        finally:
            # Clean up session
            await client.close_session()

        return result

    async def _query_all_sources(
        self,
        identifier: str,
        id_type: IdentifierType,
        package_info: Optional[PackageInfo],
        result: QueryResult,
    ) -> List[Vulnerability]:
        """Query all enabled sources in parallel.

        Args:
            identifier: Software identifier
            id_type: Type of identifier
            package_info: Parsed package information
            result: Result object to update

        Returns:
            List of all vulnerabilities from all sources
        """
        tasks = []
        source_map = {}
        clients_to_close = []

        for source, client in self._clients.items():
            # Start session for each client
            await client.start_session()
            clients_to_close.append(client)

            if id_type == IdentifierType.PURL:
                task = client.query_purl(identifier)
            elif id_type == IdentifierType.CPE:
                task = client.query_cpe(identifier)
            else:
                continue

            tasks.append(task)
            source_map[id(task)] = source

        if not tasks:
            # Clean up sessions even if no queries
            for client in clients_to_close:
                await client.close_session()
            return []

        # Execute all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_vulnerabilities = []
        for i, task_result in enumerate(results):
            task = tasks[i]
            source = source_map[id(task)]

            if isinstance(task_result, Exception):
                if isinstance(task_result, RateLimitError):
                    result.errors.append(f"{source.value}: Rate limit exceeded")
                else:
                    result.errors.append(f"{source.value}: {str(task_result)}")

                if self.verbose:
                    print(f"Error from {source.value}: {task_result}")
            else:
                all_vulnerabilities.extend(task_result)
                result.sources_checked.append(source)

        # Clean up all sessions
        for client in clients_to_close:
            await client.close_session()

        return all_vulnerabilities

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Deduplicate and consolidate vulnerability list.

        This method:
        1. Groups vulnerabilities by ID (CVE, GHSA, etc.)
        2. Merges information from multiple sources
        3. Prioritizes data based on source reliability

        Args:
            vulnerabilities: List of vulnerabilities from all sources

        Returns:
            Deduplicated and consolidated list
        """
        if not vulnerabilities:
            return []

        # Group by primary ID (CVE if available, otherwise vulnerability ID)
        vuln_groups = defaultdict(list)

        for vuln in vulnerabilities:
            # Use CVE as primary key if available
            primary_id = None
            for alias in vuln.aliases:
                if alias.startswith("CVE-"):
                    primary_id = alias
                    break

            if not primary_id:
                primary_id = vuln.id

            vuln_groups[primary_id].append(vuln)

        # Consolidate each group
        consolidated = []
        for primary_id, group in vuln_groups.items():
            if len(group) == 1:
                consolidated.append(group[0])
            else:
                merged = self._merge_vulnerabilities(group)
                consolidated.append(merged)

        # Sort by severity and ID
        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.NONE: 1,
            Severity.UNKNOWN: 0,
        }

        consolidated.sort(key=lambda v: (-severity_order.get(v.severity, 0), v.id))

        return consolidated

    def _merge_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Vulnerability:
        """Merge multiple vulnerability records into one.

        Priority order for data sources:
        1. NVD (authoritative for CVEs)
        2. GitHub (good for GitHub-hosted packages)
        3. OSV (comprehensive)
        4. Others

        Args:
            vulnerabilities: List of vulnerability records to merge

        Returns:
            Merged vulnerability record
        """
        # Sort by source priority
        source_priority = {
            VulnerabilitySource.NVD: 1,
            VulnerabilitySource.GITHUB: 2,
            VulnerabilitySource.OSV: 3,
            VulnerabilitySource.VULNERABLECODE: 4,
        }

        sorted_vulns = sorted(vulnerabilities, key=lambda v: source_priority.get(v.source, 99))

        # Start with the highest priority vulnerability
        merged = sorted_vulns[0].model_copy(deep=True)

        # Merge additional data from other sources
        for vuln in sorted_vulns[1:]:
            # Add any missing aliases
            for alias in vuln.aliases:
                if alias not in merged.aliases:
                    merged.aliases.append(alias)

            # Add any missing references
            for ref in vuln.references:
                if ref not in merged.references:
                    merged.references.append(ref)

            # Add any missing CWE IDs
            for cwe in vuln.cwe_ids:
                if cwe not in merged.cwe_ids:
                    merged.cwe_ids.append(cwe)

            # Merge affected versions
            for version in vuln.affected_versions:
                if version not in merged.affected_versions:
                    merged.affected_versions.append(version)

            # Merge fixed versions
            for version in vuln.fixed_versions:
                if version not in merged.fixed_versions:
                    merged.fixed_versions.append(version)

            # Use more detailed summary/description if available
            if not merged.details and vuln.details:
                merged.details = vuln.details

            if not merged.summary and vuln.summary:
                merged.summary = vuln.summary

            # Use CVSS score if not present
            if not merged.cvss_score and vuln.cvss_score:
                merged.cvss_score = vuln.cvss_score
                merged.cvss_vector = vuln.cvss_vector

            # Use earliest published date
            if vuln.published_date and (
                not merged.published_date or vuln.published_date < merged.published_date
            ):
                merged.published_date = vuln.published_date

        return merged

    def query_purl(self, purl: str) -> QueryResult:
        """Query using a Package URL.

        Args:
            purl: Package URL string

        Returns:
            QueryResult with vulnerability information
        """
        return self.query(purl)

    def query_cpe(self, cpe: str) -> QueryResult:
        """Query using a CPE string.

        Args:
            cpe: CPE string

        Returns:
            QueryResult with vulnerability information
        """
        if not cpe.startswith("cpe:"):
            cpe = f"cpe:{cpe}"
        return self.query(cpe)

    def query_hash(self, hash_type: str, hash_value: str) -> QueryResult:
        """Query using a file hash.

        Args:
            hash_type: Type of hash (sha256, sha1, md5)
            hash_value: Hash value

        Returns:
            QueryResult with vulnerability information
        """
        return self.query(f"{hash_type}:{hash_value}")

    async def __aenter__(self):
        """Async context manager entry."""
        for client in self._clients.values():
            await client.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        for client in self._clients.values():
            await client.close_session()
