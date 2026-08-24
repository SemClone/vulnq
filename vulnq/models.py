"""Data models for vulnq."""

from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field, field_serializer


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class IdentifierType(str, Enum):
    """Types of software identifiers."""

    PURL = "purl"
    CPE = "cpe"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    SWID = "swid"


class VersionMatch(str, Enum):
    """How a reported advisory relates to the version that was queried.

    Recorded per finding because a consumer ranking a backlog needs to know
    whether "this affects you" was checked or assumed. UNCONFIRMED exists so an
    unevaluable range can be reported rather than dropped: over-reporting is
    the safe direction, but only when it is visible as such.
    """

    NOT_EVALUATED = "not_evaluated"
    SOURCE_FILTERED = "source_filtered"
    AFFECTED = "affected"
    UNCONFIRMED = "unconfirmed"


class VulnerabilitySource(str, Enum):
    """Vulnerability data sources.

    Every member here has a working client. A source that cannot be queried
    must not be nameable: configuring one produced no client, no error, and an
    empty result, which reads as "this package has no known vulnerabilities".
    """

    OSV = "osv"
    GITHUB = "github"
    NVD = "nvd"
    VULNERABLECODE = "vulnerablecode"


class Vulnerability(BaseModel):
    """Vulnerability data model."""

    id: str = Field(..., description="Vulnerability identifier (CVE, GHSA, etc.)")
    source: VulnerabilitySource = Field(..., description="Data source")
    severity: Severity = Field(Severity.UNKNOWN, description="Severity level")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    summary: str = Field(..., description="Vulnerability summary")
    details: Optional[str] = Field(None, description="Detailed description")
    affected_versions: List[str] = Field(default_factory=list, description="Affected versions")
    fixed_versions: List[str] = Field(default_factory=list, description="Fixed versions")
    published_date: Optional[datetime] = Field(None, description="Publication date")
    modified_date: Optional[datetime] = Field(None, description="Last modification date")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    cwe_ids: List[str] = Field(default_factory=list, description="CWE identifiers")
    aliases: List[str] = Field(default_factory=list, description="Alternative identifiers")

    # Whether the queried version was actually checked against this advisory's
    # affected range, and by whom. A finding reported without that check is
    # still worth reporting, but a consumer must be able to tell the two apart.
    version_match: VersionMatch = Field(
        VersionMatch.NOT_EVALUATED,
        description="How this advisory was matched against the queried version",
    )

    # Exploitability facts joined from published snapshots. None always means
    # "unknown" - no snapshot, or no row for this CVE - and never "verified
    # negative". A consumer that reads False or 0.0 out of a failed join will
    # confidently under-rate a live threat.
    known_exploited: Optional[bool] = Field(
        None, description="Listed in the CISA KEV catalog (None if unknown)"
    )
    kev_date_added: Optional[date] = Field(None, description="Date added to the CISA KEV catalog")
    kev_known_ransomware: Optional[bool] = Field(
        None, description="Known use in ransomware campaigns per CISA KEV"
    )
    kev_required_action: Optional[str] = Field(
        None, description="Remediation action required by CISA KEV"
    )
    epss_score: Optional[float] = Field(
        None, description="FIRST EPSS probability of exploitation (None if unknown)"
    )
    epss_percentile: Optional[float] = Field(
        None, description="FIRST EPSS percentile as published, never recomputed"
    )
    epss_score_date: Optional[date] = Field(None, description="Date of the EPSS score snapshot")

    @field_serializer("published_date", "modified_date", when_used="json")
    def _serialize_datetime(self, value: Optional[datetime]) -> Optional[str]:
        """Emit timestamps the way this envelope has always emitted them.

        Replaces a class-based Config with json_encoders, both of which go away
        in pydantic v3. Pydantic's own default would be valid ISO 8601 but
        spells UTC as "Z" where every release so far has written "+00:00",
        which is a wire change consumers did not ask for.

        json-mode only, matching the reach of the json_encoders it replaces.
        A plain model_dump() still hands back real datetime objects, which is
        what in-process callers have always got.
        """
        return value.isoformat() if value else None


class PackageInfo(BaseModel):
    """Package information model."""

    ecosystem: Optional[str] = Field(None, description="Package ecosystem")
    name: str = Field(..., description="Package name")
    version: Optional[str] = Field(None, description="Package version")
    purl: Optional[str] = Field(None, description="Package URL")
    cpe: Optional[str] = Field(None, description="CPE string")


class SnapshotProvenance(BaseModel):
    """Provenance for a snapshot joined against during enrichment.

    Recorded per enrichment source so a caller can reproduce or explain an
    answer later, and can tell a fresh join from a stale or failed one.
    """

    source: str = Field(..., description="Snapshot source identifier")
    available: bool = Field(..., description="Whether the snapshot was loaded")
    version: Optional[str] = Field(
        None, description="Catalog version or score date the join ran against"
    )
    fetched_at: Optional[datetime] = Field(None, description="When the snapshot was mined")
    age_seconds: Optional[float] = Field(None, description="Snapshot age at query time")
    stale: bool = Field(False, description="Age exceeded the configured maximum")
    record_count: Optional[int] = Field(None, description="Rows in the snapshot")
    error: Optional[str] = Field(None, description="Why the snapshot was unavailable")


class QueryResult(BaseModel):
    """Query result model."""

    query: str = Field(..., description="Original query string")
    query_type: IdentifierType = Field(..., description="Type of identifier used")
    package_info: Optional[PackageInfo] = Field(None, description="Package information")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Found vulnerabilities"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Query metadata")
    enrichment: Dict[str, SnapshotProvenance] = Field(
        default_factory=dict, description="Snapshot provenance keyed by source"
    )
    query_time: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")
    sources_checked: List[VulnerabilitySource] = Field(
        default_factory=list, description="Sources that ran and returned an answer"
    )
    sources_skipped: Dict[str, str] = Field(
        default_factory=dict,
        description="Sources that could not be asked, mapped to why",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Sources that answered, but whose answer was incomplete",
    )
    errors: List[str] = Field(default_factory=list, description="Any errors encountered")

    @property
    def vulnerability_count(self) -> int:
        """Get total vulnerability count."""
        return len(self.vulnerabilities)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_conclusive(self) -> bool:
        """Whether any source actually ran and answered.

        An empty result is only meaningful when this is True. If no source
        could be asked - every one unsupported for this identifier, or every
        one failing - then zero vulnerabilities means "nobody looked", not
        "nothing found", and must not be read as a clean scan.
        """
        return bool(self.sources_checked)

    @property
    def critical_count(self) -> int:
        """Get critical vulnerability count."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Get high severity vulnerability count."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def filter_by_severity(self, min_severity: Severity) -> List[Vulnerability]:
        """Filter vulnerabilities by minimum severity."""
        severity_order = {
            Severity.NONE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        min_level = severity_order.get(min_severity, 0)
        return [v for v in self.vulnerabilities if severity_order.get(v.severity, 0) >= min_level]


class Configuration(BaseModel):
    """Configuration model for vulnq."""

    github_token: Optional[str] = Field(None, description="GitHub API token")
    nvd_api_key: Optional[str] = Field(None, description="NVD API key")
    max_concurrent: int = Field(5, description="Max concurrent requests per source")
    timeout: int = Field(30, description="Request timeout in seconds")
    use_vulnerablecode: bool = Field(False, description="Use VulnerableCode as primary source")
    kev_snapshot: Optional[str] = Field(
        None, description="Path, directory, or URL of a published CISA KEV snapshot"
    )
    epss_snapshot: Optional[str] = Field(
        None, description="Path, directory, or URL of a published FIRST EPSS snapshot"
    )
    snapshot_max_age_days: Optional[int] = Field(
        None,
        description=(
            "Age past which a snapshot is refused rather than joined. "
            "None reports age as advisory and still joins."
        ),
    )
    sources: List[VulnerabilitySource] = Field(
        default_factory=lambda: [
            VulnerabilitySource.OSV,
            VulnerabilitySource.GITHUB,
            VulnerabilitySource.NVD,
        ],
        description="Enabled vulnerability sources",
    )
