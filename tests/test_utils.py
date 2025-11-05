"""Tests for utility functions."""

import pytest
from vulnq.utils import (
    detect_identifier_type,
    parse_purl,
    parse_cpe,
    normalize_version,
    score_to_severity
)
from vulnq.models import IdentifierType


class TestDetectIdentifierType:
    """Test identifier type detection."""

    def test_detect_purl(self):
        """Test PURL detection."""
        assert detect_identifier_type("pkg:npm/express@4.17.1") == IdentifierType.PURL
        assert detect_identifier_type("pkg:pypi/django@3.2.0") == IdentifierType.PURL

    def test_detect_cpe(self):
        """Test CPE detection."""
        assert detect_identifier_type("cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*") == IdentifierType.CPE
        assert detect_identifier_type("cpe:/a:apache:tomcat:9.0.0") == IdentifierType.CPE

    def test_detect_hashes(self):
        """Test hash detection."""
        # SHA256
        assert detect_identifier_type("a" * 64) == IdentifierType.SHA256
        assert detect_identifier_type("sha256:" + "a" * 64) == IdentifierType.SHA256

        # SHA1
        assert detect_identifier_type("a" * 40) == IdentifierType.SHA1
        assert detect_identifier_type("sha1:" + "a" * 40) == IdentifierType.SHA1

        # MD5
        assert detect_identifier_type("a" * 32) == IdentifierType.MD5
        assert detect_identifier_type("md5:" + "a" * 32) == IdentifierType.MD5


class TestParsePurl:
    """Test PURL parsing."""

    def test_parse_npm_purl(self):
        """Test parsing npm PURL."""
        info = parse_purl("pkg:npm/express@4.17.1")
        assert info is not None
        assert info.ecosystem == "npm"
        assert info.name == "express"
        assert info.version == "4.17.1"

    def test_parse_pypi_purl(self):
        """Test parsing PyPI PURL."""
        info = parse_purl("pkg:pypi/django@3.2.0")
        assert info is not None
        assert info.ecosystem == "pypi"
        assert info.name == "django"
        assert info.version == "3.2.0"

    def test_parse_invalid_purl(self):
        """Test parsing invalid PURL."""
        info = parse_purl("not-a-purl")
        assert info is None


class TestParseCpe:
    """Test CPE parsing."""

    def test_parse_cpe23(self):
        """Test parsing CPE 2.3 format."""
        info = parse_cpe("cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*")
        assert info is not None
        assert info.name == "nodejs/node.js"
        assert info.version == "14.17.0"

    def test_parse_cpe22(self):
        """Test parsing CPE 2.2 format."""
        info = parse_cpe("cpe:/a:apache:tomcat:9.0.0")
        assert info is not None
        assert info.name == "apache/tomcat"
        assert info.version == "9.0.0"

    def test_parse_invalid_cpe(self):
        """Test parsing invalid CPE."""
        info = parse_cpe("not-a-cpe")
        assert info is None


class TestNormalizeVersion:
    """Test version normalization."""

    def test_remove_v_prefix(self):
        """Test removing 'v' prefix."""
        assert normalize_version("v1.2.3") == "1.2.3"
        assert normalize_version("V1.2.3") == "1.2.3"
        assert normalize_version("1.2.3") == "1.2.3"


class TestScoreToSeverity:
    """Test CVSS score to severity conversion."""

    def test_critical(self):
        """Test critical severity."""
        assert score_to_severity(9.0) == "CRITICAL"
        assert score_to_severity(10.0) == "CRITICAL"

    def test_high(self):
        """Test high severity."""
        assert score_to_severity(7.0) == "HIGH"
        assert score_to_severity(8.9) == "HIGH"

    def test_medium(self):
        """Test medium severity."""
        assert score_to_severity(4.0) == "MEDIUM"
        assert score_to_severity(6.9) == "MEDIUM"

    def test_low(self):
        """Test low severity."""
        assert score_to_severity(0.1) == "LOW"
        assert score_to_severity(3.9) == "LOW"

    def test_none(self):
        """Test none severity."""
        assert score_to_severity(0.0) == "NONE"