"""Tests that a source which did not answer is never counted as having answered."""

import pytest

from vulnq.clients import RateLimitError, UnsupportedQueryError
from vulnq.clients.github import GitHubClient
from vulnq.clients.nvd import NVDClient
from vulnq.clients.osv import OSVClient
from vulnq.clients.vulnerablecode import VulnerableCodeClient
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, VulnerabilitySource

PURL = "pkg:npm/express@4.17.1"
CPE = "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"


def engine(*sources):
    """Build an engine over the given fan-out sources."""
    return VulnerabilityQuery(config=Configuration(sources=list(sources)))


def fail_with(monkeypatch, exception):
    """Make every client request raise the given exception."""

    async def boom(self, method, url, **kwargs):
        raise exception

    monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", boom)

    async def no_session(self):
        return None

    monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
    monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)


class TestUnsupportedCombinations:
    """A source that cannot be asked must say so, not return an empty answer."""

    @pytest.mark.asyncio
    async def test_osv_rejects_cpe(self):
        """OSV is PURL-keyed and has no CPE lookup."""
        with pytest.raises(UnsupportedQueryError):
            await OSVClient().query_cpe(CPE)

    @pytest.mark.asyncio
    async def test_github_rejects_cpe(self):
        """The GitHub Advisory Database has no CPE lookup."""
        with pytest.raises(UnsupportedQueryError):
            await GitHubClient().query_cpe(CPE)

    @pytest.mark.asyncio
    async def test_vulnerablecode_rejects_cpe(self):
        """VulnerableCode is PURL-keyed."""
        with pytest.raises(UnsupportedQueryError):
            await VulnerableCodeClient().query_cpe(CPE)

    @pytest.mark.asyncio
    async def test_nvd_rejects_unmappable_purl(self):
        """NVD is CPE-keyed; an ecosystem with no CPE mapping cannot be asked."""
        client = NVDClient()
        with pytest.raises(UnsupportedQueryError):
            await client.query_purl("pkg:unknownecosystem/thing@1.0.0")


class TestSkippedVersusFailed:
    """Cannot-ask, asked-and-broke, and asked-and-found-nothing are distinct."""

    def test_cpe_query_skips_purl_only_sources(self, monkeypatch):
        """OSV and GitHub must not appear as checked on a CPE query."""

        async def no_session(self):
            return None

        async def empty(self, method, url, **kwargs):
            return {}

        monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", empty)

        result = engine(
            VulnerabilitySource.OSV, VulnerabilitySource.GITHUB, VulnerabilitySource.NVD
        ).query(CPE)

        assert result.sources_checked == [VulnerabilitySource.NVD]
        assert set(result.sources_skipped) == {"osv", "github"}
        assert "CPE" in result.sources_skipped["osv"]
        # A source that could not be asked is not an error.
        assert result.errors == []

    def test_network_failure_is_an_error_not_a_clean_scan(self, monkeypatch):
        """The bug this change exists to remove."""
        fail_with(monkeypatch, ConnectionError("network down"))

        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert result.vulnerabilities == []
        assert result.sources_checked == []
        assert any("network down" in error for error in result.errors)
        assert result.is_conclusive is False

    def test_rate_limit_surfaces_as_a_rate_limit(self, monkeypatch):
        """The RateLimitError branch in core was unreachable dead code."""
        fail_with(monkeypatch, RateLimitError("Retry after 60 seconds"))

        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert result.sources_checked == []
        assert any("Rate limit exceeded" in error for error in result.errors)

    def test_partial_failure_keeps_the_working_source(self, monkeypatch):
        """One source failing must not discard another's answer."""

        async def no_session(self):
            return None

        async def selective(self, method, url, **kwargs):
            if "osv.dev" in url:
                return {"vulns": []}
            raise ConnectionError("github unreachable")

        monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", selective)

        result = engine(VulnerabilitySource.OSV, VulnerabilitySource.GITHUB).query(PURL)

        assert result.sources_checked == [VulnerabilitySource.OSV]
        assert any("github" in error for error in result.errors)
        # OSV answered, so the empty finding list is meaningful.
        assert result.is_conclusive is True

    def test_vulnerablecode_failure_is_reported(self, monkeypatch):
        """The single-source path needs the same honesty."""
        fail_with(monkeypatch, ConnectionError("vulnerablecode unreachable"))

        result = VulnerabilityQuery(config=Configuration(use_vulnerablecode=True)).query(PURL)

        assert result.sources_checked == []
        assert any("vulnerablecode" in error for error in result.errors)
        assert result.is_conclusive is False

    def test_vulnerablecode_skip_is_not_an_error(self, monkeypatch):
        """A CPE against VulnerableCode is unaskable, not broken."""

        async def no_session(self):
            return None

        monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)

        result = VulnerabilityQuery(config=Configuration(use_vulnerablecode=True)).query(CPE)

        assert result.sources_checked == []
        assert "vulnerablecode" in result.sources_skipped
        assert result.errors == []
        assert result.is_conclusive is False


class TestIsConclusive:
    """An empty result is only meaningful when something actually ran."""

    def test_empty_result_from_a_working_source_is_conclusive(self, monkeypatch):
        """Asked and found nothing."""

        async def no_session(self):
            return None

        async def empty(self, method, url, **kwargs):
            return {"vulns": []}

        monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)
        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", empty)

        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert result.vulnerabilities == []
        assert result.is_conclusive is True

    def test_total_failure_is_not_conclusive(self, monkeypatch):
        """Nobody looked, so zero findings proves nothing."""
        fail_with(monkeypatch, ConnectionError("everything is down"))

        result = engine(VulnerabilitySource.OSV, VulnerabilitySource.GITHUB).query(PURL)

        assert result.vulnerabilities == []
        assert result.is_conclusive is False

    def test_conclusiveness_survives_json(self, monkeypatch):
        """A subprocess consumer must be able to tell the two apart."""
        import json

        fail_with(monkeypatch, ConnectionError("down"))
        result = engine(VulnerabilitySource.OSV).query(PURL)
        payload = json.loads(json.dumps(result.model_dump(mode="json")))

        assert payload["sources_checked"] == []
        assert payload["errors"]
