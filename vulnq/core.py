"""Core functionality for vulnq."""

import asyncio
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .clients import (
    RateLimitError,
    UnsupportedQueryError,
)
from .enrichment import Enricher, build_enricher
from .models import (
    SEVERITY_ORDER,
    Configuration,
    IdentifierType,
    PackageInfo,
    QueryResult,
    VersionMatch,
    Vulnerability,
    VulnerabilitySource,
)
from .sources import (
    BY_SOURCE,
    MERGE_PRIORITY,
    RETIRED_SOURCES,
    SELECTABLE_SOURCES,
    RetiredSourceError,
    parse_disabled,
    warn_about_deprecated,
)
from .utils import detect_identifier_type, parse_identifier
from .versions import sort_versions

# How strong a claim each version-match state represents. Merging two records
# for the same CVE keeps the strongest: if one source actually checked the
# queried version against the affected range, that check is not lost because a
# higher-priority source could not run it.
_VERSION_MATCH_STRENGTH = {
    VersionMatch.NOT_EVALUATED: 0,
    VersionMatch.UNCONFIRMED: 1,
    VersionMatch.SOURCE_FILTERED: 2,
    VersionMatch.AFFECTED: 2,
}


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware datetime, assuming UTC when none is given.

    Sources disagree about offsets: NVD publishes naive timestamps, OSV and
    GitHub publish them with a Z. Comparing the two raises, so anything that
    orders dates across sources has to normalize first.

    Args:
        value: A naive or aware datetime

    Returns:
        The same instant, timezone-aware
    """
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _unsupported_identifier_error(id_type: IdentifierType) -> str:
    """Describe an identifier type no configured client can answer.

    Args:
        id_type: The detected identifier type

    Returns:
        An error string for the result envelope
    """
    return (
        f"No configured source can be queried by {id_type.value}; "
        "no lookup was performed. Use a PURL or a CPE."
    )


class NoSourcesConfiguredError(RuntimeError):
    """Raised when a configuration yields no queryable vulnerability sources.

    Returning an empty result instead would be indistinguishable from a clean
    bill of health, and would fail in the dangerous direction.
    """


class VulnerabilityQuery:
    """Main vulnerability query engine."""

    def __init__(self, config: Optional[Configuration] = None, verbose: bool = False):
        """Initialize the vulnerability query engine.

        Args:
            config: Configuration object
            verbose: Enable verbose output
        """
        self.config = config or self.load_config()
        self._disabled_sources = set(self.config.disabled_sources)
        self.verbose = verbose
        self._clients = self._initialize_clients()
        # Built once and reused: the readers hold their snapshots resident, and
        # the EPSS snapshot is far too large to re-read per query.
        self._enricher: Optional[Enricher] = build_enricher(self.config, verbose=verbose)

    @staticmethod
    def load_config() -> Configuration:
        """Load configuration from environment variables.

        Public so callers that build a configuration themselves - the CLI
        included - can start from the environment instead of bypassing it.
        """
        config = Configuration()

        # Load API keys from environment
        config.github_token = os.environ.get("GITHUB_TOKEN")
        config.nvd_api_key = os.environ.get("NVD_API_KEY")
        # USE_VULNERABLECODE meant "query only VulnerableCode". The source is
        # gone, so that cannot be honoured, and carrying on would answer from
        # three sources the caller did not name - the same job, a different
        # answer, reported as if nothing had changed. It is read here so that
        # os.environ.get cannot skip it in silence, and refused for the same
        # reason --sources refuses the name.
        if os.environ.get("USE_VULNERABLECODE", "").lower() == "true":
            raise RetiredSourceError(
                "USE_VULNERABLECODE selects a source that was removed in "
                f"{RETIRED_SOURCES['vulnerablecode']}. Unset it to query "
                f"{', '.join(source.value for source in SELECTABLE_SOURCES)}."
            )

        # An operator switches a source off here when its terms change, its
        # API is withdrawn, or it starts refusing them. A code change should
        # not be the only way to stop querying something.
        config.disabled_sources = list(parse_disabled(os.environ.get("VULNQ_DISABLED_SOURCES")))

        # Snapshot locations come from the environment because the primary
        # integration path is a subprocess call - a caller running
        # "vulnq <purl> --format json" cannot hand over a Configuration object.
        config.kev_snapshot = os.environ.get("VULNQ_KEV_SNAPSHOT") or None
        config.epss_snapshot = os.environ.get("VULNQ_EPSS_SNAPSHOT") or None

        # Documented in the README, so it has to be read here or the README is
        # describing a knob that does not exist.
        max_concurrent = os.environ.get("VULNQ_MAX_CONCURRENT")
        if max_concurrent:
            try:
                config.max_concurrent = int(max_concurrent)
            except ValueError:
                raise ValueError(f"VULNQ_MAX_CONCURRENT must be an integer, got {max_concurrent!r}")

        max_age = os.environ.get("VULNQ_SNAPSHOT_MAX_AGE_DAYS")
        if max_age:
            try:
                config.snapshot_max_age_days = int(max_age)
            except ValueError as exc:
                # Swallowing this would silently disable a freshness gate the
                # operator believes is switched on, and a stale snapshot would
                # then be trusted. Fail where it can be seen.
                raise ValueError(
                    f"VULNQ_SNAPSHOT_MAX_AGE_DAYS must be an integer, got {max_age!r}"
                ) from exc

        return config

    def _initialize_clients(self) -> Dict[VulnerabilitySource, Any]:
        """Initialize API clients based on configuration.

        Returns:
            One client per selected, enabled source

        Raises:
            NoSourcesConfiguredError: If nothing is left to query, because an
                empty client set would return an empty result that reads as a
                clean bill of health
        """
        clients = {}
        self._disabled: Dict[str, str] = {}

        for source in self.config.sources:
            spec = BY_SOURCE.get(source)
            if spec is None:
                continue
            if source in self._disabled_sources:
                # Switched off by whoever runs vulnq. Recorded rather than
                # dropped: a source that was asked for and not queried has to
                # show up in the envelope, or the answer reads as complete.
                self._disabled[source.value] = "disabled by configuration (VULNQ_DISABLED_SOURCES)"
                continue
            clients[source] = spec.build(self.config, self.verbose)

        if not clients:
            requested = ", ".join(source.value for source in self.config.sources) or "none"
            selectable = ", ".join(source.value for source in SELECTABLE_SOURCES)
            hint = ""
            if self._disabled:
                hint = f" Disabled by configuration: {', '.join(sorted(self._disabled))}."
            raise NoSourcesConfiguredError(
                f"No queryable vulnerability sources configured (requested: {requested}). "
                f"Selectable sources: {selectable}.{hint}"
            )

        # Warned here rather than at each of the three CLI surfaces that can
        # select a source, because this is where they converge - and because a
        # library caller passing Configuration(sources=[...]) reaches none of
        # them and would otherwise be the one caller told nothing. Only sources
        # actually about to be queried warn: one switched off through
        # VULNQ_DISABLED_SOURCES is already not being used.
        warn_about_deprecated(clients)

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

        # Switched off is a reason a source was not checked, so it belongs
        # beside the others. Left out, a query with every source disabled but
        # one would read as a complete answer from that one.
        result.sources_skipped.update(self._disabled)

        # The sources are asked the spelling that was given, not the PEP 503
        # form. Normalization is an identity rule, not a transport one: GitHub
        # keys GHSA by the as-published PyPI name and folds case but not dots,
        # so asking it for plone-namedfile instead of plone.namedfile returns a
        # confident zero. package_info carries the canonical name for identity.
        # One path for every source. A source that took its own duplicated this
        # logic and drifted from it, which is how findings from one were once
        # labelled as coming from another.
        vulnerabilities = await self._query_all_sources(identifier, id_type, package_info, result)
        result.vulnerabilities = self._deduplicate_vulnerabilities(
            vulnerabilities, package_info.ecosystem if package_info else None
        )

        # Sources disagree about offsets, so without this one envelope can
        # carry NVD's naive timestamps beside OSV's offset-aware ones and a
        # consumer has to handle both shapes.
        for vuln in result.vulnerabilities:
            if vuln.published_date:
                vuln.published_date = _as_utc(vuln.published_date)
            if vuln.modified_date:
                vuln.modified_date = _as_utc(vuln.modified_date)

        # Enrich after both branches converge, so a CVE found by three sources
        # is stamped once and no single-source path is skipped.
        if self._enricher:
            result = self._enricher.enrich(result)

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
            # No client could answer this identifier type. Say so, rather than
            # handing back an empty list that reads as "nothing found".
            result.errors.append(_unsupported_identifier_error(id_type))
            return []

        # Execute all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_vulnerabilities = []
        for i, task_result in enumerate(results):
            task = tasks[i]
            source = source_map[id(task)]

            if isinstance(task_result, Exception):
                if isinstance(task_result, UnsupportedQueryError):
                    # Nothing went wrong; this source simply cannot be asked
                    # this question. Kept out of errors so a genuine failure
                    # stays visible among them.
                    result.sources_skipped[source.value] = str(task_result)
                elif isinstance(task_result, RateLimitError):
                    # Keep the message: it carries when the limit resets.
                    result.errors.append(f"{source.value}: {task_result}")
                else:
                    result.errors.append(f"{source.value}: {str(task_result)}")

                if self.verbose:
                    print(f"{source.value} did not answer: {task_result}")
            else:
                all_vulnerabilities.extend(task_result)
                result.sources_checked.append(source)
                # An answer can be complete enough to count as an answer and
                # still be short a few records. Surface that here, or a partial
                # list is indistinguishable from a whole one.
                for warning in getattr(self._clients[source], "parse_warnings", []):
                    result.warnings.append(f"{source.value}: {warning}")

        # Clean up all sessions
        for client in clients_to_close:
            await client.close_session()

        return all_vulnerabilities

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: List[Vulnerability], ecosystem: Optional[str] = None
    ) -> List[Vulnerability]:
        """Deduplicate and consolidate vulnerability list.

        This method:
        1. Groups vulnerabilities by ID (CVE, GHSA, etc.)
        2. Merges information from multiple sources
        3. Prioritizes data based on source reliability

        Args:
            vulnerabilities: List of vulnerabilities from all sources
            ecosystem: PURL type, so merged version lists keep their order

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
                merged = self._merge_vulnerabilities(group, ecosystem)
                consolidated.append(merged)

        # Sort by severity and ID
        consolidated.sort(key=lambda v: (-SEVERITY_ORDER[v.severity], v.id))

        return consolidated

    def _merge_vulnerabilities(
        self, vulnerabilities: List[Vulnerability], ecosystem: Optional[str] = None
    ) -> Vulnerability:
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
        sorted_vulns = sorted(vulnerabilities, key=lambda v: MERGE_PRIORITY.get(v.source, 99))

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

            # Keep the strongest version-match claim across the group. Without
            # this, a CVE that NVD version-filtered would be reported as
            # unconfirmed just because GitHub could not parse its range.
            if _VERSION_MATCH_STRENGTH.get(vuln.version_match, 0) > _VERSION_MATCH_STRENGTH.get(
                merged.version_match, 0
            ):
                merged.version_match = vuln.version_match

            # Take the score, its vector and its severity together, or the
            # merged record ends up carrying one source's 9.8 beside another
            # source's UNKNOWN. Both are printed side by side and counted
            # separately downstream, so they have to describe the same rating.
            # `is None` rather than falsy: 0.0 is a real score.
            if merged.cvss_score is None and vuln.cvss_score is not None:
                merged.cvss_score = vuln.cvss_score
                merged.cvss_vector = vuln.cvss_vector
                merged.severity = vuln.severity
            elif merged.cvss_score is None:
                # Neither carries a score, so there is nothing to derive a
                # rating from and the records simply disagree. Take the higher:
                # an under-rated finding is one a severity filter removes, and
                # that is the direction that hurts.
                if SEVERITY_ORDER[vuln.severity] > SEVERITY_ORDER[merged.severity]:
                    merged.severity = vuln.severity

            # Use earliest published date. NVD publishes timestamps without an
            # offset while OSV and GitHub publish them with one, so comparing
            # them raw raises the moment a CVE is found by both - which takes
            # the whole query down, findings from every source included.
            if vuln.published_date and (
                not merged.published_date
                or _as_utc(vuln.published_date) < _as_utc(merged.published_date)
            ):
                # Stored normalized, so a merged record does not present one
                # source's naive timestamp beside another's offset-aware one.
                merged.published_date = _as_utc(vuln.published_date)

        # Each source ordered its own list, but merging appends one onto the
        # other, so the result is ordered only by which source answered first.
        # The consumer reads the first entry as the earliest fix, so the whole
        # thing is ordered again once everything has been folded in.
        merged.affected_versions = sort_versions(ecosystem, merged.affected_versions)
        merged.fixed_versions = sort_versions(ecosystem, merged.fixed_versions)

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

    async def __aenter__(self):
        """Async context manager entry."""
        for client in self._clients.values():
            await client.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        for client in self._clients.values():
            await client.close_session()
