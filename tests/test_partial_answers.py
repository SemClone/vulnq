"""Tests for answers that arrive incomplete rather than not at all.

The all-records-failed guard catches a source whose response shape changed
wholesale. Below that threshold, records used to be dropped into a verbose
print: nine of ten advisories could vanish and the result looked complete. This
is the safe direction of failure - under-reporting, not a false clean bill -
but only if the caller can see it happened.
"""

import pytest

from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, VersionMatch, VulnerabilitySource

PURL = "pkg:npm/express@4.17.1"


@pytest.fixture
def offline(monkeypatch):
    """Stop the clients from opening real sessions."""

    async def no_session(self):
        return None

    monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
    monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)


def engine(source):
    """Build a query engine limited to one source.

    Args:
        source: The only source to enable

    Returns:
        A configured VulnerabilityQuery
    """
    return VulnerabilityQuery(config=Configuration(sources=[source]))


class TestPartialParseIsReported:
    """Some records parsed, some did not."""

    def test_osv_reports_the_records_it_dropped(self, monkeypatch, offline):
        async def half_broken(self, method, url, **kwargs):
            return {
                "vulns": [
                    {"id": "OSV-1", "summary": "real"},
                    {"summary": "no id, unusable"},
                    {"summary": "also no id"},
                ]
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", half_broken)
        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert len(result.vulnerabilities) == 1
        # The source answered, so this is not an error - but the answer is short.
        assert result.sources_checked == [VulnerabilitySource.OSV]
        assert result.errors == []
        assert len(result.warnings) == 1
        assert "2 of 3" in result.warnings[0]
        assert "osv" in result.warnings[0]

    def test_github_reports_the_advisories_it_dropped(self, monkeypatch, offline):
        async def half_broken(self, method, url, **kwargs):
            return {
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "summary": "real"},
                                "vulnerableVersionRange": "< 5.0.0",
                            },
                            {"advisory": None},
                        ]
                    }
                }
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", half_broken)
        result = engine(VulnerabilitySource.GITHUB).query(PURL)

        assert len(result.vulnerabilities) == 1
        assert result.errors == []
        assert len(result.warnings) == 1
        assert "1 of 2" in result.warnings[0]

    def test_nvd_reports_the_records_it_dropped(self, monkeypatch, offline):
        async def half_broken(self, method, url, **kwargs):
            return {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2020-0001", "descriptions": []}},
                    {"cve": {"descriptions": []}},
                ]
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", half_broken)
        result = engine(VulnerabilitySource.NVD).query(PURL)

        assert len(result.vulnerabilities) == 1
        assert len(result.warnings) == 1
        assert "1 of 2" in result.warnings[0]

    def test_nvd_all_records_broken_is_an_error_not_a_clean_scan(self, monkeypatch, offline):
        """NVD had no all-failed guard at all: 100 broken records read as clean."""

        async def all_broken(self, method, url, **kwargs):
            return {"vulnerabilities": [{"cve": {}}, {"cve": {}}]}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", all_broken)
        result = engine(VulnerabilitySource.NVD).query(PURL)

        assert result.vulnerabilities == []
        assert result.sources_checked == []
        assert result.is_conclusive is False
        assert any("none could be parsed" in error for error in result.errors)

    def test_a_clean_answer_carries_no_warning(self, monkeypatch, offline):
        async def clean(self, method, url, **kwargs):
            return {"vulns": [{"id": "OSV-1", "summary": "real"}]}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", clean)
        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert result.warnings == []

    def test_warnings_do_not_leak_between_queries(self, monkeypatch, offline):
        """parse_warnings is per-query state on a client reused across queries."""
        responses = [
            {"vulns": [{"id": "OSV-1", "summary": "real"}, {"summary": "broken"}]},
            {"vulns": [{"id": "OSV-2", "summary": "real"}]},
        ]

        async def sequenced(self, method, url, **kwargs):
            return responses.pop(0)

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", sequenced)
        query = engine(VulnerabilitySource.OSV)

        assert len(query.query(PURL).warnings) == 1
        assert query.query(PURL).warnings == []


class TestVersionMatchIsRecorded:
    """A finding must say whether the queried version was actually checked."""

    def test_github_confirms_a_version_inside_the_range(self, monkeypatch, offline):
        async def advisory(self, method, url, **kwargs):
            return {
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "summary": "s"},
                                "vulnerableVersionRange": "< 5.0.0",
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", advisory)
        result = engine(VulnerabilitySource.GITHUB).query(PURL)

        assert result.vulnerabilities[0].version_match == VersionMatch.AFFECTED

    def test_github_marks_an_unevaluable_range_unconfirmed(self, monkeypatch, offline):
        """Included, not dropped - and visibly not a confirmed match."""

        async def advisory(self, method, url, **kwargs):
            return {
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "summary": "s"},
                                "vulnerableVersionRange": "~> 4.0",
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", advisory)
        result = engine(VulnerabilitySource.GITHUB).query(PURL)

        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].version_match == VersionMatch.UNCONFIRMED

    def test_github_drops_a_version_outside_the_range(self, monkeypatch, offline):
        async def advisory(self, method, url, **kwargs):
            return {
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "summary": "s"},
                                "vulnerableVersionRange": "< 1.0.0",
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", advisory)
        result = engine(VulnerabilitySource.GITHUB).query(PURL)

        assert result.vulnerabilities == []
        assert result.warnings == []

    def test_a_versionless_purl_is_not_version_filtered(self, monkeypatch, offline):
        """No version to check means no claim that one was checked."""

        async def advisory(self, method, url, **kwargs):
            return {
                "data": {
                    "securityVulnerabilities": {
                        "nodes": [
                            {
                                "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "summary": "s"},
                                "vulnerableVersionRange": "< 1.0.0",
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", advisory)
        result = engine(VulnerabilitySource.GITHUB).query("pkg:npm/express")

        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].version_match == VersionMatch.NOT_EVALUATED

    def test_osv_credits_its_own_server_side_filter(self, monkeypatch, offline):
        async def clean(self, method, url, **kwargs):
            return {"vulns": [{"id": "OSV-1", "summary": "real"}]}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", clean)
        result = engine(VulnerabilitySource.OSV).query(PURL)

        assert result.vulnerabilities[0].version_match == VersionMatch.SOURCE_FILTERED

    def test_osv_makes_no_claim_for_a_versionless_purl(self, monkeypatch, offline):
        async def clean(self, method, url, **kwargs):
            return {"vulns": [{"id": "OSV-1", "summary": "real"}]}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", clean)
        result = engine(VulnerabilitySource.OSV).query("pkg:npm/express")

        assert result.vulnerabilities[0].version_match == VersionMatch.NOT_EVALUATED
