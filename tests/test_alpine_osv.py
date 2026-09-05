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

    def test_the_version_zero_is_sent_rather_than_read_as_absent(self):
        """A PURL version is a string, so "0" is not the falsy 0.

        Dropping it would ask OSV a package-wide question while the result
        still claimed SOURCE_FILTERED against a version nobody filtered on.
        """
        body, _, _ = run("pkg:apk/alpine/openssl@0?distro=alpine-3.16")

        assert body["version"] == "0"

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


class TestOneRecordCoversManyPackagesAndBranches:
    """ALPINE-CVE-2022-4304 carries thirteen affected entries in the fixture:
    openssl across eleven Alpine branches, and openssl3 across two. The answer
    to "openssl on 3.16" is one of those, not all thirteen flattened together.
    """

    def _openssl_3_16(self):
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
            recorded("alpine_openssl_v3_16"),
        )
        return next(v for v in vulns if v.id == "ALPINE-CVE-2022-4304")

    def test_the_fix_reported_is_the_one_for_the_branch_asked_about(self):
        assert self._openssl_3_16().fixed_versions == ["1.1.1t-r0"]

    def test_a_sibling_packages_fix_does_not_ride_along(self):
        """openssl3 is fixed in 3.0.8-r0. Nobody asked about openssl3."""
        assert "3.0.8-r0" not in self._openssl_3_16().fixed_versions

    def test_a_later_branchs_fix_does_not_ride_along_either(self):
        """openssl on Alpine:v3.17 is fixed in 3.0.8-r0. Also not the question."""
        vuln = self._openssl_3_16()
        assert len(vuln.fixed_versions) == 1

    def test_every_record_in_the_recorded_answer_names_one_fix(self):
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
            recorded("alpine_openssl_v3_16"),
        )

        assert [len(v.fixed_versions) for v in vulns] == [1] * 9


class TestScopingOnlyAppliesWhereTheQueryNamedOne:
    RECORD = {
        "id": "OSV-1",
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": "Alpine:v3.16"},
                "ranges": [{"events": [{"introduced": "1.0.2"}, {"fixed": "1.1.1t-r0"}]}],
            },
            {
                "package": {"name": "openssl3", "ecosystem": "Alpine:v3.16"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.8-r0"}]}],
            },
        ],
    }

    def test_a_purl_query_still_reads_every_entry(self):
        """No scope means no filter: deb, rpm, npm and pypi are untouched."""
        _, vulns, _ = run("pkg:npm/example@1.0.0", {"vulns": [self.RECORD]})

        assert vulns[0].fixed_versions == ["1.1.1t-r0", "3.0.8-r0"]

    def test_an_alpine_query_reads_only_its_own_entry(self):
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
            {"vulns": [self.RECORD]},
        )

        assert vulns[0].fixed_versions == ["1.1.1t-r0"]

    def test_a_record_naming_nothing_we_asked_for_keeps_all_of_it(self):
        """Under-reporting a fix is worse than reporting one too many.

        A record that came back for this query but names the package some way
        this does not recognise is a shape we do not understand, so it falls
        back to the behaviour every other ecosystem still gets.
        """
        record = {
            "id": "OSV-2",
            "affected": [
                {
                    "package": {"name": "openssl", "ecosystem": "Alpine:v3.99"},
                    "ranges": [{"events": [{"fixed": "9.9.9-r0"}]}],
                }
            ],
        }
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16", {"vulns": [record]}
        )

        assert vulns[0].fixed_versions == ["9.9.9-r0"]

    def test_a_record_with_no_affected_list_at_all_parses(self):
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
            {"vulns": [{"id": "OSV-3"}]},
        )

        assert vulns[0].fixed_versions == []


class TestTheCveTheAdvisoryIsJoinedOnSurvives:
    """Alpine records carry their CVE in `upstream`, not `aliases`.

    Without it an Alpine finding joins nothing: deduplication groups on the
    first CVE alias, and KEV and EPSS are keyed by CVE. Measured live, every
    Alpine record is exactly one upstream CVE and names itself after it -
    246 of 246 across six packages.
    """

    def _first(self):
        _, vulns, _ = run(
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
            recorded("alpine_openssl_v3_16"),
        )
        return vulns

    def test_the_upstream_cve_becomes_an_alias(self):
        vuln = next(v for v in self._first() if v.id == "ALPINE-CVE-2022-4304")

        assert vuln.aliases == ["CVE-2022-4304"]

    def test_every_recorded_alpine_record_carries_its_cve(self):
        # Sliced, not removeprefix: the suite runs on 3.8, where that is absent.
        for vuln in self._first():
            assert vuln.aliases == [vuln.id[len("ALPINE-") :]]

    def test_enrichment_can_now_key_on_it(self):
        from vulnq.enrichment.snapshot import cve_keys

        vuln = next(v for v in self._first() if v.id == "ALPINE-CVE-2022-4304")

        assert cve_keys(vuln) == ["CVE-2022-4304"]


class TestOnlyARenameIsFoldedIn:
    def _aliases(self, record):
        _, vulns, _ = run("pkg:npm/example@1.0.0", {"vulns": [record]})
        return vulns[0].aliases

    def test_a_debian_record_named_after_its_cve_is_folded_too(self):
        """Same shape, same defect; it was never Alpine-specific."""
        assert self._aliases(
            {"id": "DEBIAN-CVE-2019-5481", "upstream": ["CVE-2019-5481"]}
        ) == ["CVE-2019-5481"]

    def test_an_aggregate_record_folds_nothing(self):
        """One Debian record cites thirty CVEs. It is not thirty renames."""
        assert (
            self._aliases(
                {
                    "id": "DSA-1234-1",
                    "upstream": ["CVE-2019-5481", "CVE-2019-5482", "CVE-2020-8169"],
                }
            )
            == []
        )

    def test_upstream_never_matches_twice_so_it_cannot_merge_two_advisories(self):
        record = {
            "id": "DEBIAN-CVE-2019-5481",
            "upstream": ["CVE-2019-5481", "CVE-2019-5482"],
        }

        assert self._aliases(record) == ["CVE-2019-5481"]

    def test_a_real_alias_list_is_kept_and_not_replaced(self):
        assert self._aliases(
            {
                "id": "ALPINE-CVE-2022-4304",
                "aliases": ["GHSA-xxxx-yyyy-zzzz"],
                "upstream": ["CVE-2022-4304"],
            }
        ) == ["GHSA-xxxx-yyyy-zzzz", "CVE-2022-4304"]

    def test_an_id_already_in_aliases_is_not_added_twice(self):
        assert self._aliases(
            {
                "id": "ALPINE-CVE-2022-4304",
                "aliases": ["CVE-2022-4304"],
                "upstream": ["CVE-2022-4304"],
            }
        ) == ["CVE-2022-4304"]

    def test_a_record_with_no_upstream_is_unchanged(self):
        assert self._aliases({"id": "GHSA-1", "aliases": ["CVE-2020-1"]}) == ["CVE-2020-1"]

    def test_the_source_record_is_not_mutated(self):
        """aliases used to be handed out by reference straight from the payload."""
        record = {"id": "ALPINE-CVE-2022-4304", "upstream": ["CVE-2022-4304"]}
        self._aliases(record)

        assert "aliases" not in record
