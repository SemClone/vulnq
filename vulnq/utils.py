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


# PEP 503 collapses any run of dot, hyphen and underscore to a single hyphen
# and lowercases the result. PyPI is the identity authority here and resolves
# every such spelling to one distribution.
#
# This deliberately goes further than the purl spec, whose pypi type folds
# underscore and case but leaves the dot alone (its only dot rule is for sdist
# and wheel filenames). So pkg:pypi/zope.interface is spec-canonical, and a
# purl vulnq reports may not string-match one emitted by a spec-conformant
# tool. PyPI treating the two as one package is the property that matters for
# deduplicating findings, which is what this identity is for.
_PEP503_SEPARATOR_RUN = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """Return a PyPI distribution name in its PEP 503 normalized form.

    Args:
        name: Distribution name as written

    Returns:
        The canonical name PyPI compares against
    """
    return _PEP503_SEPARATOR_RUN.sub("-", name).lower()


def canonical_purl(purl_string: str) -> str:
    """Return a PURL in the form its ecosystem compares names in.

    Only pkg:pypi is rewritten, and only to the PEP 503 rule, which is PyPI's
    own. packageurl lowercases pypi names and folds underscores but leaves dots
    alone, so without it zope.interface and zope_interface are one distribution
    spelled two ways that produce two purls and two sets of records.

    This is an identity rule, for reporting and comparison. Do not normalize
    before querying a source. GitHub keys its advisory database by the
    as-published PyPI name and folds case but not separators, so asking it
    about products-pluggableauthservice instead of
    products.pluggableauthservice drops three real advisories and reports the
    source as checked.

    Idempotent, and returns the input unchanged if it does not parse, so a
    caller can normalize without having to first decide whether it is safe.

    Args:
        purl_string: PURL string as written

    Returns:
        The canonical PURL, or the input unchanged
    """
    try:
        purl = PackageURL.from_string(purl_string)
    except Exception:
        return purl_string

    if purl.type != "pypi" or not purl.name:
        return purl_string

    # Reserialize rather than comparing against purl.name and handing back the
    # input. packageurl has already folded underscores and case by this point,
    # so that comparison reports "nothing to do" for pkg:pypi/zope_interface
    # and returns the underscore spelling untouched.
    return str(purl._replace(name=normalize_pypi_name(purl.name)))


def parse_purl(purl_string: str) -> Optional[PackageInfo]:
    """Parse a Package URL string.

    Args:
        purl_string: PURL string

    Returns:
        PackageInfo object or None if parsing fails
    """
    try:
        purl = PackageURL.from_string(canonical_purl(purl_string))
    except Exception:
        return None

    return PackageInfo(ecosystem=purl.type, name=purl.name, version=purl.version, purl=str(purl))


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
