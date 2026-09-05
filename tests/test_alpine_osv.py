"""Alpine apk coordinates, against a response recorded from the live OSV API.

OSV's PURL index does not reach pkg:apk, so an Alpine coordinate has always
come back as {} - not an error, and not distinguishable from a package with
nothing against it. Its Alpine advisories are there; they are keyed by release
branch and reachable only by name and ecosystem.

Verified live against api.osv.dev while writing this:
  - pkg:apk/alpine/openssl@1.1.1q-r0            0 records, with or without distro=
  - ecosystem "Alpine", version 1.1.1q-r0       0 records; the branch is required
  - ecosystem "Alpine:v3.16.2"                  0 records; two components, no more
  - ecosystem "Alpine:v3.16", version 1.1.1q-r0 9 records (tests/fixtures/osv)
  - ecosystem "Alpine:v3.16", no version        28 records; OSV filters, we do not
  - ecosystem "Alpine:v3.16", version 1.1.1w-r1 0 records; the fix is recognised
  - pkg:apk/wolfi/... and pkg:apk/chainguard/... resolve as PURLs, 71 records each
"""

import asyncio
import json
import pathlib

import pytest

from vulnq.clients.osv import OSVClient

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "osv"


def recorded(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def run(purl, response=None):
    """Send one PURL through the client and return (request body, result)."""
    sent = []
    client = OSVClient()

    async def _capture(method, url, **kwargs):
        sent.append(kwargs["json"])
        return response if response is not None else {"vulns": []}

    client._make_request = _capture
    vulns = asyncio.run(client.query_purl(purl))
    return sent[0], vulns, client


class TestAlpineGoesOutByBranch:
    def test_distro_qualifier_becomes_the_ecosystem(self):
        body, _, _ = run("pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16.2")

        assert body == {
            "package": {"name": "openssl", "ecosystem": "Alpine:v3.16"},
            "version": "1.1.1q-r0",
        }

    @pytest.mark.parametrize(
        "distro",
        ["alpine-3.16.2", "alpine-3.16", "3.16.2", "3.16", "v3.16", "alpine_3.16"],
    )
    def test_every_spelling_of_the_distro_qualifier_lands_on_one_branch(self, distro):
        """syft, trivy and hand-written PURLs each write this differently."""
        body, _, _ = run(f"pkg:apk/alpine/openssl@1.1.1q-r0?distro={distro}")

        assert body["package"]["ecosystem"] == "Alpine:v3.16"

    def test_a_third_component_is_dropped_rather_than_sent(self):
        """"Alpine:v3.16.2" matches nothing. Verified against the live API."""
        body, _, _ = run("pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16.2")

        assert body["package"]["ecosystem"] == "Alpine:v3.16"

    def test_a_versionless_purl_asks_for_the_whole_package(self):
        """OSV filters by version only when the query carries one."""
        body, _, _ = run("pkg:apk/alpine/openssl?distro=alpine-3.16")

        assert "version" not in body
        assert body["package"] == {"name": "openssl", "ecosystem": "Alpine:v3.16"}

    def test_arch_and_other_qualifiers_do_not_confuse_the_branch(self):
        purl = "pkg:apk/alpine/openssl@1.1.1q-r0?arch=x86_64&distro=alpine-3.16.2&upstream=openssl"
        body, _, _ = run(purl)

        assert body["package"]["ecosystem"] == "Alpine:v3.16"


class TestTheRecordedAnswerParses:
    def test_the_nine_records_alpine_v3_16_returns_all_become_vulnerabilities(self):
        _, vulns, client = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16.2",
            recorded("alpine_openssl_v3_16"),
        )

        assert len(vulns) == 9
        assert client.parse_warnings == []

    def test_the_alpine_ids_and_their_cve_aliases_both_survive(self):
        """ALPINE-CVE-* ids are what joins these to the other sources."""
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16.2",
            recorded("alpine_openssl_v3_16"),
        )

        ids = {v.id for v in vulns}
        assert "ALPINE-CVE-2022-4304" in ids
        assert all(i.startswith("ALPINE-CVE-") for i in ids)


class TestEverythingElseStillGoesOutAsAPurl:
    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:pypi/requests@2.28.0",
            "pkg:npm/lodash@4.17.20",
            "pkg:deb/debian/curl@7.64.0-4",
            "pkg:rpm/redhat/openssl@1.1.1k-4.el8",
        ],
    )
    def test_non_apk_coordinates_are_untouched(self, purl):
        body, _, _ = run(purl)

        assert body == {"package": {"purl": purl}}

    @pytest.mark.parametrize("namespace", ["wolfi", "chainguard"])
    def test_the_other_apk_distros_keep_the_purl_path(self, namespace):
        """Both resolve through OSV's PURL index today; verified live.

        Their advisories sit under a bare "Wolfi" and "Chainguard" with no
        branch, so there is nothing for this rewrite to build.
        """
        purl = f"pkg:apk/{namespace}/openssl@3.0.8-r0?distro={namespace}-20230201"
        body, _, _ = run(purl)

        assert body == {"package": {"purl": purl}}

    def test_an_unparseable_string_is_sent_as_given(self):
        body, _, _ = run("not-a-purl")

        assert body == {"package": {"purl": "not-a-purl"}}


class TestAnAlpinePurlWithNoBranchSaysSo:
    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:apk/alpine/openssl@1.1.1q-r0",
            "pkg:apk/alpine/openssl@1.1.1q-r0?arch=x86_64",
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=edge",
        ],
    )
    def test_the_empty_answer_is_explained_rather_than_left_to_read_as_clean(self, purl):
        """OSV has no branchless Alpine data, so an empty answer is a gap."""
        body, vulns, client = run(purl)

        assert body == {"package": {"purl": purl}}
        assert vulns == []
        assert len(client.parse_warnings) == 1
        assert "distro=" in client.parse_warnings[0]

    def test_a_branch_that_does_resolve_warns_about_nothing(self):
        _, _, client = run("pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16")

        assert client.parse_warnings == []

    def test_the_warning_does_not_survive_into_the_next_query(self):
        """_begin_query clears it; a stale gap warning would be a false one."""
        client = OSVClient()

        async def _empty(method, url, **kwargs):
            return {"vulns": []}

        client._make_request = _empty
        asyncio.run(client.query_purl("pkg:apk/alpine/openssl@1.1.1q-r0"))
        assert client.parse_warnings

        asyncio.run(client.query_purl("pkg:pypi/requests@2.28.0"))
        assert client.parse_warnings == []


class TestPaginationStillWorksOnTheRewrittenQuery:
    def test_the_page_token_rides_along_with_the_ecosystem_body(self):
        sent = []
        client = OSVClient()

        async def _two_pages(method, url, **kwargs):
            sent.append(kwargs["json"])
            if len(sent) == 1:
                return {"vulns": [{"id": "ALPINE-CVE-1"}], "next_page_token": "t1"}
            return {"vulns": [{"id": "ALPINE-CVE-2"}]}

        client._make_request = _two_pages
        vulns = asyncio.run(
            client.query_purl("pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16")
        )

        assert len(vulns) == 2
        assert "page_token" not in sent[0]
        assert sent[1]["page_token"] == "t1"
        assert sent[1]["package"] == {"name": "openssl", "ecosystem": "Alpine:v3.16"}

    def test_the_first_page_body_is_not_mutated_by_the_second(self):
        """dict(query) per page, not one body carried across the loop."""
        sent = []
        client = OSVClient()

        async def _two_pages(method, url, **kwargs):
            sent.append(kwargs["json"])
            return {"vulns": [], "next_page_token": "t"} if len(sent) == 1 else {"vulns": []}

        client._make_request = _two_pages
        asyncio.run(client.query_purl("pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16"))

        assert "page_token" not in sent[0]
