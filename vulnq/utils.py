"""Utility functions for vulnq."""

import re
from typing import Optional

from packageurl import PackageURL

from .models import IdentifierType, PackageInfo


def detect_identifier_type(identifier: str) -> IdentifierType:
    """Detect the type of software identifier.

    Args:
        identifier: The identifier string

    Returns:
        IdentifierType enum value
    """
    identifier = identifier.strip()

    # Check for explicit type prefix
    if identifier.startswith("pkg:"):
        return IdentifierType.PURL
    elif identifier.startswith("cpe:"):
        return IdentifierType.CPE
    elif identifier.startswith("sha256:"):
        return IdentifierType.SHA256
    elif identifier.startswith("sha1:"):
        return IdentifierType.SHA1
    elif identifier.startswith("md5:"):
        return IdentifierType.MD5
    elif identifier.startswith("swid:"):
        return IdentifierType.SWID

    # Try to detect by pattern
    # CPE 2.3 format
    if re.match(r"^cpe:2\.[23]:[aoh]:.*", identifier):
        return IdentifierType.CPE

    # CPE 2.2 format (legacy)
    if re.match(r"^cpe:/[aoh]:.*", identifier):
        return IdentifierType.CPE

    # SHA256 (64 hex chars)
    if re.match(r"^[a-fA-F0-9]{64}$", identifier):
        return IdentifierType.SHA256

    # SHA1 (40 hex chars)
    if re.match(r"^[a-fA-F0-9]{40}$", identifier):
        return IdentifierType.SHA1

    # MD5 (32 hex chars)
    if re.match(r"^[a-fA-F0-9]{32}$", identifier):
        return IdentifierType.MD5

    # Try to parse as PURL
    try:
        PackageURL.from_string(identifier)
        return IdentifierType.PURL
    except Exception:
        pass

    # Default to PURL if unclear
    return IdentifierType.PURL


def parse_identifier(identifier: str, id_type: IdentifierType) -> Optional[PackageInfo]:
    """Parse identifier and extract package information.

    Args:
        identifier: The identifier string
        id_type: The type of identifier

    Returns:
        PackageInfo if parseable, None otherwise
    """
    if id_type == IdentifierType.PURL:
        return parse_purl(identifier)
    elif id_type == IdentifierType.CPE:
        return parse_cpe(identifier)
    else:
        # Hashes don't have package info
        return None


def parse_purl(purl_string: str) -> Optional[PackageInfo]:
    """Parse a Package URL string.

    Args:
        purl_string: PURL string

    Returns:
        PackageInfo object or None if parsing fails
    """
    try:
        purl = PackageURL.from_string(purl_string)
        return PackageInfo(
            ecosystem=purl.type, name=purl.name, version=purl.version, purl=str(purl)
        )
    except Exception:
        return None


def parse_cpe(cpe_string: str) -> Optional[PackageInfo]:
    """Parse a CPE string.

    Args:
        cpe_string: CPE string

    Returns:
        PackageInfo object or None if parsing fails
    """
    # Remove prefix if present
    if cpe_string.startswith("cpe:"):
        cpe_string = cpe_string[4:]

    try:
        # CPE 2.3 format
        if cpe_string.startswith("2.3:") or cpe_string.startswith("2.2:"):
            parts = cpe_string.split(":")
            if len(parts) >= 5:
                vendor = parts[2]
                product = parts[3]
                version = parts[4] if len(parts) > 4 and parts[4] != "*" else None

                return PackageInfo(
                    ecosystem=None,
                    name=f"{vendor}/{product}" if vendor != "*" else product,
                    version=version,
                    cpe=f"cpe:{cpe_string}",
                )

        # CPE 2.2 format (legacy)
        elif cpe_string.startswith("/"):
            parts = cpe_string.split(":")
            if len(parts) >= 3:
                vendor = parts[1]
                product = parts[2]
                version = parts[3] if len(parts) > 3 else None

                return PackageInfo(
                    ecosystem=None,
                    name=f"{vendor}/{product}",
                    version=version,
                    cpe=f"cpe:{cpe_string}",
                )

    except Exception:
        pass

    return None


def normalize_version(version: str) -> str:
    """Normalize version string for comparison.

    Args:
        version: Version string

    Returns:
        Normalized version string
    """
    # Remove common prefixes
    version = re.sub(r"^v", "", version, flags=re.IGNORECASE)
    return version.strip()


def severity_to_score(severity: str) -> float:
    """Convert severity string to numeric score.

    Args:
        severity: Severity string

    Returns:
        Numeric score (0-10)
    """
    severity = severity.upper()
    mapping = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 2.0, "NONE": 0.0, "UNKNOWN": 5.0}
    return mapping.get(severity, 5.0)


def score_to_severity(score: float) -> str:
    """Convert numeric score to severity string.

    Args:
        score: CVSS score (0-10)

    Returns:
        Severity string
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 0.1:
        return "LOW"
    else:
        return "NONE"
