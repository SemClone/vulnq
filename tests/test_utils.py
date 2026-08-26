"""Tests for utility functions."""

import pytest

from vulnq.models import IdentifierType
from vulnq.utils import (
    detect_identifier_type,
    parse_cpe,
    parse_purl,
)


class TestDetectIdentifierType:
    """Test identifier type detection."""

    def test_detect_purl(self):
        """Test PURL detection."""
        assert detect_identifier_type("pkg:npm/express@4.17.1") == IdentifierType.PURL
        assert detect_identifier_type("pkg:pypi/django@3.2.0") == IdentifierType.PURL

    def test_detect_cpe(self):
        """Test CPE detection."""
        assert (
            detect_identifier_type("cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*")
            == IdentifierType.CPE
        )
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
