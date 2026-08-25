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
