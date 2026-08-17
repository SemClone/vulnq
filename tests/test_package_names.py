"""Tests for the package name vulnq asks each source about.

A structurally wrong question is the most dangerous shape of empty result:
GitHub answers honestly with zero advisories for a package that cannot exist,
and the source is counted as checked. These tests assert the name that reaches
the API, not merely that a query happened.
"""

import pytest

from vulnq.clients.base import UnsupportedQueryError
from vulnq.clients.github import GitHubClient


def sent_package(monkeypatch, purl):
    """Run a PURL through the client and capture the package name it sends.

    Args:
        monkeypatch: pytest monkeypatch fixture
        purl: Package URL to query

    Returns:
        Tuple of (ecosystem, package name) sent to GitHub
    """
    captured = {}

    async def capture(self, method, url, **kwargs):
        captured.update(kwargs["json"]["variables"])
        return {"data": {"securityVulnerabilities": {"nodes": []}}}

    async def no_session(self):
        return None

    monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", capture)
    monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
    monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)

    import asyncio

    asyncio.run(GitHubClient().query_purl(purl))
    return captured["ecosystem"], captured["package"]


class TestGitHubPackageNames:
    """Verified against the live advisory database before being pinned here."""

    def test_maven_uses_group_colon_artifact(self, monkeypatch):
        """The canonical Maven PURL was being sent with a slash, matching nothing."""
        ecosystem, package = sent_package(
            monkeypatch, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        )
        assert ecosystem == "MAVEN"
        assert package == "org.apache.logging.log4j:log4j-core"

    def test_scoped_npm_is_percent_decoded(self, monkeypatch):
        """ "%40scope/pkg" is not a package name any registry holds."""
        _, package = sent_package(monkeypatch, "pkg:npm/%40babel/traverse@7.0.0")
        assert package == "@babel/traverse"

    def test_literal_scoped_npm_also_works(self, monkeypatch):
        _, package = sent_package(monkeypatch, "pkg:npm/@babel/traverse@7.0.0")
        assert package == "@babel/traverse"

    def test_unscoped_npm_is_unchanged(self, monkeypatch):
        _, package = sent_package(monkeypatch, "pkg:npm/express@4.17.1")
        assert package == "express"

    def test_go_module_path_is_kept_whole(self, monkeypatch):
        ecosystem, package = sent_package(monkeypatch, "pkg:golang/github.com/gin-gonic/gin@v1.6.0")
        assert ecosystem == "GO"
        assert package == "github.com/gin-gonic/gin"

    def test_swift_module_path_is_kept_whole(self, monkeypatch):
        _, package = sent_package(monkeypatch, "pkg:swift/github.com/vapor/vapor@4.0.0")
        assert package == "github.com/vapor/vapor"

    def test_composer_vendor_package(self, monkeypatch):
        _, package = sent_package(monkeypatch, "pkg:composer/symfony/http-kernel@5.0.0")
        assert package == "symfony/http-kernel"

    def test_pypi_drops_no_namespace(self, monkeypatch):
        ecosystem, package = sent_package(monkeypatch, "pkg:pypi/django@3.2.1")
        assert ecosystem == "PIP"
        assert package == "django"

    def test_maven_without_a_group_is_skipped_not_queried(self, monkeypatch):
        """A name that cannot be built is unanswerable, not answered clean."""
        with pytest.raises(UnsupportedQueryError) as excinfo:
            sent_package(monkeypatch, "pkg:maven/log4j-core@2.14.1")
        assert "group" in str(excinfo.value)

    def test_bare_typo_is_still_unsupported(self, monkeypatch):
        """Regression guard: "express" must not become a clean scan."""
        with pytest.raises(UnsupportedQueryError):
            sent_package(monkeypatch, "express")
