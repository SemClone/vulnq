"""What the tool says about a finding has to match what it knows.

Three separate defects lived here: an unrated finding was filtered out as if
it were harmless, a score was invented from a partial reading of the vector,
and VulnerableCode findings were labelled as coming from OSV.
"""

import asyncio
import datetime

import pytest

from vulnq.clients.osv import OSVClient
from vulnq.clients.vulnerablecode import VulnerableCodeClient
from vulnq.models import (
    SEVERITY_ORDER,
    IdentifierType,
    QueryResult,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)


def _result(*severities):
    vulns = [
        Vulnerability(id=f"V-{i}", source=VulnerabilitySource.OSV, summary="x", severity=s)
        for i, s in enumerate(severities)
    ]
    return QueryResult(
        query="pkg:pypi/django@3.2.0",
        query_type=IdentifierType.PURL,
        vulnerabilities=vulns,
        query_time=datetime.datetime.now(),
    )


@pytest.mark.parametrize("floor", list(Severity))
def test_unrated_findings_survive_every_filter(floor):
    """UNKNOWN means nobody scored it, so it cannot be ruled out.

    OSV makes this common rather than exotic: PYSEC records routinely carry no
    severity at all, so a filtered run was dropping a large share of real
    findings with nothing said about it.
    """
    result = _result(Severity.UNKNOWN, Severity.CRITICAL)
    kept, _ = result.filter_by_severity(floor)
    assert "V-0" in [v.id for v in kept]


def test_unrated_is_not_ranked_below_scored_zero():
    """NONE was scored and came out at zero. UNKNOWN was never scored."""
    assert SEVERITY_ORDER[Severity.UNKNOWN] < SEVERITY_ORDER[Severity.NONE]


def test_the_filter_reports_what_it_withheld():
    """A shortened list handed back silently reads as the whole answer."""
    result = _result(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM)
    kept, withheld = result.filter_by_severity(Severity.HIGH)
    assert [v.id for v in kept] == ["V-1"]
    assert withheld == 2


def test_nothing_withheld_reports_zero():
    result = _result(Severity.CRITICAL, Severity.HIGH)
    kept, withheld = result.filter_by_severity(Severity.HIGH)
    assert len(kept) == 2
    assert withheld == 0


def test_one_severity_ordering_serves_the_filter_and_the_sort():
    """Two copies of this drifted apart once, which is how UNKNOWN got lost."""
    import vulnq.core as core

    assert core.SEVERITY_ORDER is SEVERITY_ORDER
    assert set(SEVERITY_ORDER) == set(Severity)


def _osv_severity(entries, database_specific=None):
    data = {"id": "TEST-1", "summary": "x", "severity": entries}
    if database_specific:
        data["database_specific"] = database_specific
    return OSVClient()._parse_vulnerability(data)


def test_osv_score_is_computed_not_guessed():
    """Both of these carry /C:H and /AC:L, which the old code called 9.0."""
    high = _osv_severity(
        [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
    )
    low = _osv_severity(
        [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N"}]
    )
    assert (high.cvss_score, high.severity) == (7.5, Severity.HIGH)
    assert (low.cvss_score, low.severity) == (4.2, Severity.MEDIUM)


def test_a_vector_that_cannot_be_scored_is_still_reported():
    """A consumer can score 4.0 even though this does not."""
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    vuln = _osv_severity([{"type": "CVSS_V4", "score": v4}])
    assert vuln.cvss_vector == v4
    assert vuln.cvss_score is None


def test_the_scorable_vector_wins_when_both_are_offered():
    """OSV often carries V3 and V4 together, in either order.

    The vector reported and the score reported have to describe the same thing.
    """
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    for entries in ([{"score": v4}, {"score": v3}], [{"score": v3}, {"score": v4}]):
        vuln = _osv_severity(entries)
        assert vuln.cvss_vector == v3
        assert vuln.cvss_score == 9.8


def test_a_computed_score_is_not_overruled_by_the_database_label():
    """Score and severity sit side by side, so they have to agree."""
    vuln = _osv_severity(
        [{"score": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N"}],
        database_specific={"severity": "CRITICAL"},
    )
    assert vuln.cvss_score == 4.2
    assert vuln.severity is Severity.MEDIUM


def test_the_database_label_still_rates_an_unscorable_finding():
    """It is the only rating available when no vector can be scored."""
    vuln = _osv_severity([], database_specific={"severity": "HIGH"})
    assert vuln.cvss_score is None
    assert vuln.severity is Severity.HIGH


def test_vulnerablecode_findings_say_vulnerablecode():
    """Labelling them OSV credited a database that was never queried."""
    assert VulnerableCodeClient().source is VulnerabilitySource.VULNERABLECODE


def test_vulnerablecode_findings_carry_the_label_into_the_envelope():
    """The envelope contradicted itself: sources_checked said one thing.

    Asserted on a parsed finding rather than on the request, because the
    request never carried the label that was wrong.
    """
    payload = {
        "results": [
            {
                "purl": "pkg:pypi/django@3.2.0",
                "affected_by_vulnerabilities": [
                    {"vulnerability_id": "VCID-1", "summary": "x", "references": []}
                ],
            }
        ]
    }
    findings = VulnerableCodeClient()._parse_response(payload, "pkg:pypi/django@3.2.0")
    assert findings
    assert all(f.source is VulnerabilitySource.VULNERABLECODE for f in findings)


def test_github_unscored_advisories_do_not_become_a_zero(monkeypatch):
    """GitHub sends score 0.0 with a null vector for what it never scored.

    Around one PIP advisory in eight arrives that way. Kept as a real score it
    prints as 0.0, blocks another source's real score in the merge, and reads
    to a downstream gate as harmless.
    """
    from vulnq.clients.github import GitHubClient

    def _node(score, vector):
        return {
            "advisory": {
                "ghsaId": "GHSA-test",
                "summary": "x",
                "severity": "HIGH",
                "cvss": {"score": score, "vectorString": vector},
                "identifiers": [],
                "references": [],
            }
        }

    client = GitHubClient()
    real_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    assert client._parse_vulnerability(_node(0.0, None), None).cvss_score is None
    # A genuine zero always carries the vector it was computed from.
    assert client._parse_vulnerability(_node(0.0, real_vector), None).cvss_score == 0.0
    assert client._parse_vulnerability(_node(9.8, real_vector), None).cvss_score == 9.8


def test_a_zero_score_is_not_treated_as_a_missing_one(capsys):
    """0.0 is computed and means no impact. None means nobody scored it.

    Falsy checks conflated the two in the table, the markdown, and in three
    clients' severity fallbacks.
    """
    from vulnq.cli import print_markdown
    from vulnq.cvss import base_score

    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0

    result = QueryResult(
        query="q",
        query_type=IdentifierType.PURL,
        vulnerabilities=[
            Vulnerability(id="ZERO", source=VulnerabilitySource.OSV, summary="x", cvss_score=0.0),
            Vulnerability(id="UNSCORED", source=VulnerabilitySource.OSV, summary="x"),
        ],
        query_time=datetime.datetime.now(),
    )
    print_markdown(result)
    out = capsys.readouterr().out
    assert "**CVSS Score:** 0.0" in out
    assert "**CVSS Score:** N/A" in out


def test_a_merged_record_does_not_mix_one_score_with_another_severity():
    """Adopting a score without its severity printed 9.8 beside UNKNOWN."""
    from vulnq.core import VulnerabilityQuery

    unrated = Vulnerability(
        id="CVE-1", source=VulnerabilitySource.GITHUB, summary="x", severity=Severity.UNKNOWN
    )
    scored = Vulnerability(
        id="CVE-1",
        source=VulnerabilitySource.OSV,
        summary="x",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )

    merged = VulnerabilityQuery(config=None)._merge_vulnerabilities([unrated, scored])
    assert merged.cvss_score == 9.8
    assert merged.severity is Severity.CRITICAL


def test_a_merged_zero_score_is_not_overwritten():
    """`not merged.cvss_score` treated a real 0.0 as absent."""
    from vulnq.core import VulnerabilityQuery

    zero = Vulnerability(
        id="CVE-2",
        source=VulnerabilitySource.NVD,
        summary="x",
        severity=Severity.NONE,
        cvss_score=0.0,
    )
    other = Vulnerability(
        id="CVE-2",
        source=VulnerabilitySource.OSV,
        summary="x",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
    )

    merged = VulnerabilityQuery(config=None)._merge_vulnerabilities([zero, other])
    assert merged.cvss_score == 0.0
    assert merged.severity is Severity.NONE


def test_a_bare_cvss_2_vector_is_kept():
    """OSV publishes 2.0 without the CVSS: prefix, so prefix matching lost it."""
    vuln = _osv_severity([{"type": "CVSS_V2", "score": "AV:L/AC:M/Au:N/C:P/I:P/A:P"}])
    assert vuln.cvss_vector == "AV:L/AC:M/Au:N/C:P/I:P/A:P"
    assert vuln.cvss_score is None


def test_a_numeric_score_is_still_read_as_a_number():
    """The vector test must not swallow a plain numeric severity entry."""
    vuln = _osv_severity([{"type": "CVSS_V3", "score": "7.5"}])
    assert vuln.cvss_score == 7.5
    assert vuln.severity is Severity.HIGH
