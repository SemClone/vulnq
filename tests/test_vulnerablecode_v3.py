"""The VulnerableCode client, against responses recorded from the live API.

Every payload in tests/fixtures/vulnerablecode was captured from
public.vulnerablecode.io, not written by hand. The previous version of this
client read a `scores` key at a level the API has never served, and its tests
passed because they fed it that invented shape. Recording the real thing is
the only way those two can disagree out loud.

What the recordings establish, all verified live:
  - the v1 endpoints are gone; `/api/packages/` answers 404
  - the 403 seen without a User-Agent is that header missing, not a token
  - `User-Agent: VCIO_API_AGENT` is required and anonymous access then works,
    throttled at ten requests a minute
  - `/v3/packages/` with details carries which advisories apply and
    `fixed_by_packages`, a list of PURL strings
  - `/v3/advisories/` carries `severities` (with `scoring_elements` holding
    the CVSS vector) and `weaknesses` (whose `cwe_id` is a bare number)
"""

import asyncio
import json
import pathlib

import aiohttp
import pytest

from vulnq.clients.base import MissingCredentialError, RateLimitError
from vulnq.clients.vulnerablecode import (
    _CVSS_SYSTEMS,
    DEFAULT_BASE_URL,
    REQUIRED_USER_AGENT,
    VulnerableCodeClient,
)
from vulnq.models import Severity, VulnerabilitySource

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "vulnerablecode"


def recorded(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def run(client, purl="pkg:npm/lodash@4.17.20"):
    return asyncio.run(client.query_purl(purl))


def wired(packages, advisories):
    """A client answering from two recorded responses, in call order."""
    client = VulnerableCodeClient()
    sent = []

    async def _request(method, url, **kwargs):
        sent.append({"method": method, "url": url, **kwargs})
        return packages if "/packages/" in url else advisories

    client._make_request = _request
    client.sent = sent
    return client


class TestTheRequest:
    """The shape of what goes out, which is where the old client was wrong."""

    def test_the_required_user_agent_is_sent(self):
        """The public instance answers 403 for any other value, whatever the
        token says. That header, not a missing token, was the original 403.

        The literal is written out rather than compared against the constant:
        asserting `== REQUIRED_USER_AGENT` passes whatever the constant says,
        including a value the instance rejects.
        """
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        run(client)
        assert client.sent, "no request was made"
        for request in client.sent:
            assert request["headers"]["User-Agent"] == "VCIO_API_AGENT"

    def test_the_constant_holds_the_value_the_instance_demands(self):
        assert REQUIRED_USER_AGENT == "VCIO_API_AGENT"

    def test_both_endpoints_are_asked(self):
        """They carry different halves: one has the advisories and the fixing
        versions, the other the severities and weaknesses."""
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        run(client)
        paths = [request["url"].replace(DEFAULT_BASE_URL, "") for request in client.sent]
        assert paths == ["/v3/packages/", "/v3/advisories/"]

    def test_the_purl_is_sent_as_a_list_in_the_body(self):
        """v3 takes a POST body. v1 took a query string, and that endpoint is
        gone: /api/packages/ answers 404."""
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        run(client, "pkg:npm/lodash@4.17.20")
        assert client.sent[0]["json"] == {"purls": ["pkg:npm/lodash@4.17.20"], "details": True}
        assert client.sent[1]["json"] == {"purls": ["pkg:npm/lodash@4.17.20"]}

    def test_details_is_requested_or_the_response_is_bare_purls(self):
        """Without it the endpoint returns strings, not records."""
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        run(client)
        assert client.sent[0]["json"]["details"] is True

    def test_a_token_is_sent_the_way_django_rest_framework_expects(self):
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        client.api_key = "secret-token"
        run(client)
        assert client.sent[0]["headers"]["Authorization"] == "Token secret-token"

    def test_no_token_still_sends_the_user_agent(self):
        """Anonymous access works; it is only throttled."""
        client = wired(recorded("lodash"), recorded("lodash-advisories"))
        run(client)
        assert "Authorization" not in client.sent[0]["headers"]
        assert client.sent[0]["headers"]["User-Agent"] == REQUIRED_USER_AGENT


class TestParsingRecordedResponses:
    """Read from what the API actually returned."""

    def test_findings_come_back_with_their_identifiers(self):
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        assert findings
        assert all(f.source is VulnerabilitySource.VULNERABLECODE for f in findings)
        assert all(f.id for f in findings)

    def test_a_cvss_score_and_its_vector_come_from_the_advisory(self):
        """`severities` holds the value and `scoring_elements` the vector."""
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        scored = [f for f in findings if f.cvss_score is not None]
        assert scored, "no finding carried a score"
        for finding in scored:
            assert 0.0 <= finding.cvss_score <= 10.0
            if finding.cvss_vector:
                assert finding.cvss_vector.startswith("CVSS:")

    def test_the_severity_agrees_with_the_score(self):
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        for finding in findings:
            if finding.cvss_score is None:
                continue
            assert finding.severity is VulnerableCodeClient().cvss_to_severity(finding.cvss_score)

    def test_weaknesses_become_cwe_identifiers(self):
        """VulnerableCode writes the number alone: "89", not "CWE-89"."""
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        classified = [f for f in findings if f.cwe_ids]
        assert classified, "no finding carried a classification"
        for finding in classified:
            assert all(cwe.startswith("CWE-") for cwe in finding.cwe_ids)

    def test_fixed_versions_are_read_out_of_the_fixing_purls(self):
        """`fixed_by_packages` is a list of PURL strings, not versions."""
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        fixed = [f for f in findings if f.fixed_versions]
        assert fixed, "no finding carried a fixing version"
        for finding in fixed:
            assert all("pkg:" not in version for version in finding.fixed_versions)
            assert (
                finding.fixed_versions
                == sorted(
                    finding.fixed_versions,
                    key=lambda v: [int(p) for p in v.split(".") if p.isdigit()],
                )
                or len(finding.fixed_versions) == 1
            )

    def test_aliases_survive(self):
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        assert any(f.aliases for f in findings)

    def test_a_package_with_nothing_recorded_returns_nothing(self):
        """And not an error: an empty answer to a real question."""
        findings = run(
            wired(recorded("no-such-package"), recorded("no-such-package-advisories")),
            "pkg:npm/there-is-no-such-package-xyzzy@9.9.9",
        )
        assert findings == []

    def test_a_maven_package_parses_too(self):
        findings = run(
            wired(recorded("log4j-core"), recorded("log4j-core-advisories")),
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        )
        assert findings
        assert all(f.id for f in findings)

    def test_an_advisory_with_no_detail_record_still_becomes_a_finding(self):
        """The two endpoints do not return identical sets: for lodash the
        package endpoint lists seven advisories and the advisory endpoint
        details five. The two without detail are still real findings, they
        simply carry no severity."""
        findings = run(wired(recorded("lodash"), recorded("lodash-advisories")))
        detailed = {r["advisory_id"] for r in recorded("lodash-advisories")["results"]}
        undetailed = [f for f in findings if f.id not in detailed]
        assert undetailed, "the recordings no longer exercise this case"
        for finding in undetailed:
            assert finding.severity is Severity.UNKNOWN
            assert finding.cvss_score is None


class TestRefusals:
    """A refusal has to say which one it is."""

    def _refusing(self, status):
        client = VulnerableCodeClient()

        async def _refuse(method, url, **kwargs):
            raise aiohttp.ClientResponseError(None, (), status=status, message="no")

        client._make_request = _refuse
        return client

    def test_throttling_says_so_and_names_the_remedy(self):
        """Anonymous access is ten requests a minute; a token lifts it."""
        with pytest.raises(RateLimitError, match="throttling"):
            run(self._refusing(429))

    @pytest.mark.parametrize("status", [401, 403])
    def test_a_refusal_without_a_token_names_the_token(self, status):
        with pytest.raises(MissingCredentialError, match="VULNERABLECODE_API_KEY"):
            run(self._refusing(status))

    def test_a_refusal_while_holding_a_token_is_not_relabelled(self):
        """It means something else, and masking it would be the same defect."""
        client = self._refusing(403)
        client.api_key = "secret-token"
        with pytest.raises(aiohttp.ClientResponseError):
            run(client)

    def test_other_errors_are_not_relabelled(self):
        with pytest.raises(aiohttp.ClientResponseError):
            run(self._refusing(500))

    def test_a_cpe_cannot_be_asked(self):
        from vulnq.clients.base import UnsupportedQueryError

        with pytest.raises(UnsupportedQueryError):
            asyncio.run(VulnerableCodeClient().query_cpe("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"))


class TestScoringSystems:
    """Only a CVSS system may fill a CVSS field."""

    def _rate(self, severities):
        return VulnerableCodeClient()._rate(severities)

    def test_an_epss_probability_is_not_a_cvss_score(self):
        """EPSS runs zero to one, so 0.97 reported as a base score reads LOW."""
        severity, score, vector = self._rate([{"scoring_system": "epss", "value": "0.97"}])
        assert score is None
        assert severity is Severity.UNKNOWN

    def test_the_newest_cvss_specification_wins(self):
        _, score, _ = self._rate(
            [
                {"scoring_system": "cvssv3.1", "value": "7.0"},
                {"scoring_system": "cvssv4", "value": "9.8"},
            ]
        )
        assert score == 9.8

    def test_a_cvss_row_is_found_past_a_non_cvss_one(self):
        _, score, _ = self._rate(
            [
                {"scoring_system": "epss", "value": "0.97"},
                {"scoring_system": "cvssv3.1", "value": "9.8"},
            ]
        )
        assert score == 9.8

    def test_the_vector_is_used_when_the_value_is_unusable(self):
        """Computing it beats reporting nothing."""
        _, score, vector = self._rate(
            [
                {
                    "scoring_system": "cvssv3.1",
                    "value": "not a number",
                    "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        )
        assert score == 9.8
        assert vector.startswith("CVSS:3.1")

    def test_a_textual_rating_rates_when_no_cvss_row_parses(self):
        severity, score, _ = self._rate([{"scoring_system": "generic_textual", "value": "HIGH"}])
        assert severity is Severity.HIGH
        assert score is None

    def test_a_recorded_advisory_rates_from_its_own_severities(self):
        """Read from what the API returned, not from a shape I invented."""
        for advisory in recorded("log4j-core-advisories")["results"]:
            severities = advisory.get("severities") or []
            systems = {str(row.get("scoring_system", "")).lower() for row in severities}
            if not systems & set(_CVSS_SYSTEMS):
                continue
            severity, score, vector = self._rate(severities)
            assert score is not None or vector is not None
            if score is not None:
                assert 0.0 <= score <= 10.0
                assert severity is not Severity.UNKNOWN
            return
        pytest.fail("the recordings no longer carry a CVSS severity")
