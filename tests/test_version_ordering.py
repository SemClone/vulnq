"""The first entry of a fixed-versions list is the earliest fix.

Deduplicating with `sorted(set(...))` made the output reproducible, which it
had not been, but it orders strings: lexicographically `10.0.0` precedes
`2.2.28`. The CLI prints the first three under "Fixed In", so someone reading
the first entry as the earliest fix was reading it wrong, and could take an
unnecessary major upgrade or miss that a patch on their own line already
fixes the issue.
"""

import pytest

from vulnq.versions import sort_versions


def test_the_earliest_fix_comes_first():
    """The case from the issue: lexicographic order puts 10.0.0 second."""
    assert sort_versions("npm", ["1.22.1", "10.0.0", "2.2.28"]) == [
        "1.22.1",
        "2.2.28",
        "10.0.0",
    ]


def test_ordering_follows_the_ecosystem_not_the_alphabet():
    """Maven ranks a qualifier below the release it qualifies."""
    assert sort_versions("maven", ["2.14.1", "2.0-beta9", "1.2.17"]) == [
        "1.2.17",
        "2.0-beta9",
        "2.14.1",
    ]


def test_a_prerelease_sorts_below_its_release():
    assert sort_versions("npm", ["1.0.0", "1.0.0-rc.1"]) == ["1.0.0-rc.1", "1.0.0"]


def test_ranges_are_kept_and_grouped_after_the_versions():
    """These lists mix single versions with range expressions, and only the
    first kind can be ordered. Neither may be dropped."""
    ordered = sort_versions("npm", ["4.17.21", ">=2.2, <2.2.28", "1.0.0", "<4.17.21"])
    assert ordered[:2] == ["1.0.0", "4.17.21"]
    assert set(ordered[2:]) == {">=2.2, <2.2.28", "<4.17.21"}
    assert len(ordered) == 4


def test_duplicates_are_removed():
    assert sort_versions("npm", ["1.0.0", "1.0.0", "2.0.0"]) == ["1.0.0", "2.0.0"]


@pytest.mark.parametrize(
    "values",
    [
        ["not-a-version", "1.0.0"],
        ["", "1.0.0"],
        ["1.0.0", None, 42],
        [],
    ],
)
def test_nothing_unorderable_raises_or_disappears(values):
    """A value that cannot be ordered is still a value the source reported."""
    ordered = sort_versions("npm", values)
    keepable = {v for v in values if isinstance(v, str) and v}
    assert set(ordered) == keepable


def test_an_unknown_ecosystem_still_orders_sensibly():
    """None falls back to semver rules rather than to the alphabet."""
    assert sort_versions(None, ["10.0.0", "2.0.0"]) == ["2.0.0", "10.0.0"]
    assert sort_versions("nonesuch", ["10.0.0", "2.0.0"]) == ["2.0.0", "10.0.0"]


def test_the_result_is_reproducible():
    """The property #43 established, which this must not undo."""
    values = ["2.2.28", "10.0.0", ">=1, <2", "1.22.1", "not-a-version"]
    first = sort_versions("npm", values)
    assert all(sort_versions("npm", list(reversed(values))) == first for _ in range(3))


def test_a_client_orders_numerically_not_alphabetically():
    """Chosen so lexicographic and numeric order actually differ.

    With versions whose two orders agree, reverting the sort to
    sorted(set(...)) leaves the test passing and proves nothing.
    """
    from vulnq.clients.osv import OSVClient

    vuln = OSVClient()._parse_vulnerability(
        {
            "id": "T",
            "summary": "x",
            "affected": [{"versions": ["10.0.0", "2.2.28", "1.22.1"]}],
        },
        None,
        "npm",
    )
    assert vuln.affected_versions == ["1.22.1", "2.2.28", "10.0.0"]


def test_the_ecosystem_of_the_purl_reaches_the_ordering():
    """Maven and semver disagree about 2.0-beta9 against 2.0-beta10: Maven
    compares the qualifier numerically, semver does not. So the order alone
    reveals whether the ecosystem was passed down or dropped."""
    from vulnq.clients.osv import OSVClient

    versions = ["2.0-beta10", "2.0-beta9"]

    as_maven = OSVClient()._parse_vulnerability(
        {"id": "T", "summary": "x", "affected": [{"versions": versions}]}, None, "maven"
    )
    assert as_maven.affected_versions == ["2.0-beta9", "2.0-beta10"]

    without = OSVClient()._parse_vulnerability(
        {"id": "T", "summary": "x", "affected": [{"versions": versions}]}, None, None
    )
    assert without.affected_versions == ["2.0-beta10", "2.0-beta9"]


def test_the_client_derives_the_ecosystem_from_the_purl():
    """The step the two tests above depend on."""
    from vulnq.clients.base import BaseClient

    assert BaseClient._ecosystem_of("pkg:maven/org.apache/x@1") == "maven"
    assert BaseClient._ecosystem_of("pkg:npm/lodash@4.17.21") == "npm"
    assert BaseClient._ecosystem_of("not a purl") is None
    assert BaseClient._ecosystem_of(None) is None


def test_an_undecidable_pair_does_not_disturb_the_versions_around_it():
    """compare_versions refuses some pairs: a Maven calendar version like
    2024.Q1.2 against 2024.Q1.12, or a build qualifier against its release.

    Such a pair is treated as equal, so the lexicographic pre-sort breaks the
    tie and the result stays deterministic. Moving them to the end instead was
    tried and is worse: a version is unrankable because of one awkward
    neighbour, so 1.0.0 beside 1.0.0+build would go behind 2.0.0 and the
    earliest fix would no longer be first.
    """
    assert sort_versions("maven", ["1.0.0+build", "1.0.0", "2.0.0"]) == [
        "1.0.0",
        "1.0.0+build",
        "2.0.0",
    ]
    assert sort_versions("maven", ["11.0.6", "11.0.6+security-01", "20.0.0"]) == [
        "11.0.6",
        "11.0.6+security-01",
        "20.0.0",
    ]


def test_the_first_entry_is_the_earliest_fix_beside_an_undecidable_pair():
    """The property the CLI's "Fixed In" column depends on."""
    ordered = sort_versions("maven", ["10.0.0", "2.2.28", "1.0.0+build", "1.0.0"])
    assert ordered[0] == "1.0.0"
    assert ordered[-1] == "10.0.0"


def test_an_all_decidable_list_is_ordered_throughout():
    assert sort_versions("pypi", ["10.0.0", "2.2.9", "1.11.29"]) == [
        "1.11.29",
        "2.2.9",
        "10.0.0",
    ]


@pytest.mark.parametrize("wildcard", ["1.0.x", "1.0.X", "1.0.*", "nightly-0.28.x"])
def test_a_wildcard_names_a_family_not_a_version(wildcard):
    """OSV publishes these: OSV-2024-340 lists `nightly-0.28.x`.

    A wildcard cannot be ordered against a concrete release any more than
    ">=0.28, <0.29" can, so it is grouped with the ranges rather than
    interleaved as though it were a version somebody could install.

    The concrete versions below both sort after the wildcard alphabetically,
    so treating it as a version would put it first, where the CLI reads the
    first entry as the earliest fix.
    """
    ordered = sort_versions("npm", [wildcard, "2.0.0", "3.0.0"])
    assert ordered[:2] == ["2.0.0", "3.0.0"], f"{wildcard} was ranked as a version"
    assert ordered[2] == wildcard


def test_an_x_inside_a_version_is_not_a_wildcard():
    """Only a trailing wildcard component counts, or real versions are lost."""
    assert sort_versions("npm", ["1.0.0-alpha.x1", "1.0.0"]) == [
        "1.0.0-alpha.x1",
        "1.0.0",
    ]


def test_debian_revisions_keep_a_deterministic_order_without_claiming_one():
    """The ecosystem comparison declines Debian revision suffixes, so those
    two are not ranked against each other. The earliest release still comes
    first, which is the property the output depends on."""
    ordered = sort_versions("deb", ["2.36-9+deb12u10", "2.36-9+deb12u2", "2.36-9"])
    assert ordered[0] == "2.36-9"
    assert set(ordered[1:]) == {"2.36-9+deb12u10", "2.36-9+deb12u2"}
    assert sort_versions("deb", list(reversed(ordered))) == ordered


def test_the_order_never_contradicts_the_comparator_itself():
    """The property that matters, over lists taken from real advisories.

    A comparator returning None for pairs it declines to rank is not a total
    order, and cmp_to_key needs one. Mapping None to "equal" broke
    transitivity, and timsort then binary-searched among the apparent equals
    and never compared the decisive pair, so releases came out ahead of their
    own prereleases: 2.0.0 before 2.0.0-BETA, which the comparator itself
    orders the other way round.
    """
    import itertools

    from vulnq.versions import compare_versions

    cases = [
        ("npm", ["2.0.0", "2.0.0+1", "2.0.0-rc.1"]),
        ("maven", ["2.0.0", "2.0.0-ALPHA.1", "2.0.0-ALPHA.2", "2.0.0-BETA"]),
        ("maven", ["1.18", "1.18-alpha"]),
        ("maven", ["1.5-RC3", "1.5-rc2", "1.5"]),
        ("pypi", ["2.2.28", "3.2.13", "4.0.4", "1.11.29", "10.0.0"]),
        ("gem", ["1.0.0.rc.1", "1.0.0", "0.9.2", "1.0.0.pre2"]),
    ]

    for ecosystem, values in cases:
        ordered = sort_versions(ecosystem, values)
        position = {value: index for index, value in enumerate(ordered)}
        for left, right in itertools.combinations(ordered, 2):
            if compare_versions(ecosystem, left, right) == 1:
                assert position[left] > position[right], (
                    f"{ecosystem}: {left} is greater than {right} but was listed first "
                    f"in {ordered}"
                )


def test_the_first_entry_is_never_beaten_by_a_later_one():
    """What the CLI's "Fixed In" column asserts by showing three of them."""
    from vulnq.versions import compare_versions

    for ecosystem, values in [
        ("npm", ["2.0.0", "2.0.0+1", "2.0.0-rc.1"]),
        ("maven", ["2.0.0", "2.0.0-BETA"]),
        ("pypi", ["10.0.0", "2.2.28", "1.22.1"]),
    ]:
        ordered = sort_versions(ecosystem, values)
        assert not any(
            compare_versions(ecosystem, ordered[0], other) == 1 for other in ordered[1:]
        ), f"{ecosystem}: {ordered[0]} is later than something after it in {ordered}"


def test_a_client_orders_its_fixed_versions_too():
    """Only affected_versions was covered, and the CLI prints fixed_versions."""
    from vulnq.clients.osv import OSVClient

    vuln = OSVClient()._parse_vulnerability(
        {
            "id": "T",
            "summary": "x",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "10.0.0"},
                                {"fixed": "2.2.28"},
                            ],
                        }
                    ]
                }
            ],
        },
        None,
        "npm",
    )
    assert vuln.fixed_versions == ["2.2.28", "10.0.0"]


def test_the_vulnerablecode_client_orders_its_fixed_versions():
    """It reads a `version` from each fixed package, not a purl.

    An assertion that allowed an empty list passed whatever the code did.
    """
    from vulnq.clients.vulnerablecode import VulnerableCodeClient

    vuln = VulnerableCodeClient()._parse_vulnerability(
        {
            "vulnerability_id": "VCID-1",
            "summary": "x",
            "references": [],
            "fixed_packages": [{"version": "10.0.0"}, {"version": "2.2.28"}],
        },
        None,
        "npm",
    )
    assert vuln.fixed_versions == ["2.2.28", "10.0.0"]


def test_github_reports_at_most_one_fixed_version_per_advisory():
    """Which is why sorting there cannot reorder anything today.

    Recorded rather than asserted through a sort: GitHub appends a single
    firstPatchedVersion identifier, so a test claiming the client orders a
    list would pass whatever the client did. The ordering that matters for
    GitHub findings happens at the merge, which is covered below.
    """
    from vulnq.clients.github import GitHubClient

    node = {
        "advisory": {
            "ghsaId": "GHSA-test",
            "summary": "x",
            "severity": "HIGH",
            "identifiers": [],
            "references": [],
            "cvss": {"score": None, "vectorString": None},
        },
        "firstPatchedVersion": {"identifier": "10.0.0"},
        "vulnerableVersionRange": "< 10.0.0",
    }
    assert GitHubClient()._parse_vulnerability(node, None, "npm").fixed_versions == ["10.0.0"]


def test_merging_two_sources_leaves_the_versions_ordered():
    """Each source orders its own list, but the merge appends one onto the
    other, so the result was ordered only by which source answered first."""
    from vulnq.core import VulnerabilityQuery
    from vulnq.models import Configuration, Vulnerability, VulnerabilitySource

    def record(source, fixed):
        return Vulnerability(id="CVE-1", source=source, summary="x", fixed_versions=list(fixed))

    engine = VulnerabilityQuery(config=Configuration())
    merged = engine._merge_vulnerabilities(
        [
            record(VulnerabilitySource.NVD, ["10.0.0"]),
            record(VulnerabilitySource.OSV, ["2.2.28", "3.2.13"]),
        ],
        "npm",
    )
    assert merged.fixed_versions == ["2.2.28", "3.2.13", "10.0.0"]


@pytest.mark.parametrize(
    "expression",
    ["<1.0.0", ">=2.2, <2.2.28", "= 1.0.0", "1.0.0 - 2.0.0", "*"],
)
def test_a_range_expression_is_recognised_as_one(expression):
    """Asserted on the predicate directly.

    Going through sort_versions hid the guard: a range the ecosystem also
    declines to rank lands in the tail either way, so removing the marker
    check left the test passing.
    """
    from vulnq.versions import _is_plain_version

    assert not _is_plain_version(expression)


@pytest.mark.parametrize("version", ["1.0.0", "2.0.0-rc.1", "1.0.0+build", "v1.2.3"])
def test_a_single_version_is_not_mistaken_for_a_range(version):
    from vulnq.versions import _is_plain_version

    assert _is_plain_version(version)


def test_a_range_expression_is_never_ranked_as_a_version():
    """The marker check: a range beginning with < sorts before every digit."""
    ordered = sort_versions("npm", ["<1.0.0", "2.0.0", "3.0.0"])
    assert ordered[:2] == ["2.0.0", "3.0.0"], "a range was ranked as a version"
    assert ordered[2] == "<1.0.0"
