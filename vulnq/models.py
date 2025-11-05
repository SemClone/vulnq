"""Data models for vulnq."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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


class VulnerabilitySource(str, Enum):
    """Vulnerability data sources."""

    OSV = "osv"
    GITHUB = "github"
    NVD = "nvd"
    SNYK = "snyk"
    SONATYPE = "sonatype"
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

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class PackageInfo(BaseModel):
    """Package information model."""

    ecosystem: Optional[str] = Field(None, description="Package ecosystem")
    name: str = Field(..., description="Package name")
    version: Optional[str] = Field(None, description="Package version")
    purl: Optional[str] = Field(None, description="Package URL")
    cpe: Optional[str] = Field(None, description="CPE string")


class QueryResult(BaseModel):
    """Query result model."""

    query: str = Field(..., description="Original query string")
    query_type: IdentifierType = Field(..., description="Type of identifier used")
    package_info: Optional[PackageInfo] = Field(None, description="Package information")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Found vulnerabilities"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Query metadata")
    query_time: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")
    sources_checked: List[VulnerabilitySource] = Field(
        default_factory=list, description="Sources that were checked"
    )
    errors: List[str] = Field(default_factory=list, description="Any errors encountered")

    @property
    def vulnerability_count(self) -> int:
        """Get total vulnerability count."""
        return len(self.vulnerabilities)

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
    cache_enabled: bool = Field(True, description="Enable caching")
    cache_dir: str = Field("~/.vulnq/cache", description="Cache directory")
    cache_ttl: int = Field(3600, description="Cache TTL in seconds")
    max_concurrent: int = Field(5, description="Max concurrent requests")
    timeout: int = Field(30, description="Request timeout in seconds")
    use_vulnerablecode: bool = Field(False, description="Use VulnerableCode as primary source")
    sources: List[VulnerabilitySource] = Field(
        default_factory=lambda: [
            VulnerabilitySource.OSV,
            VulnerabilitySource.GITHUB,
            VulnerabilitySource.NVD,
        ],
        description="Enabled vulnerability sources",
    )
