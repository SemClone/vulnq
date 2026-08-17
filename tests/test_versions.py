"""Tests for ecosystem-aware version ordering and range evaluation.

The governing rule: an advisory that cannot be evaluated is included and
marked, never dropped. These tests pin both directions - a version genuinely
outside a range is excluded, and an unevaluable range is not.
"""

import pytest

from vulnq.versions import compare_versions, evaluate_range


class TestSemverOrdering:
    """npm, Cargo, Go, and friends."""

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.0.0", 1),
            ("1.0.0", "1.0.0", 0),
            ("2.0.0", "10.0.0", -1),
            ("1.2", "1.2.0", 0),
            ("4.17.1", "4.19.2", -1),
            # A pre-release precedes the release with the same numbers.
            ("4.0.0-rc1", "4.0.0", -1),
            ("5.0.0-alpha.1", "5.0.0-beta.3", -1),
            ("5.0.0-alpha.1", "5.0.0-alpha.2", -1),
            # Numeric identifiers rank below alphanumeric ones.
            ("1.0.0-1", "1.0.0-alpha", -1),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert compare_versions("npm", left, right) == expected

    def test_build_metadata_is_undecided(self):
        """Semver ignores build metadata; several ecosystems do not.

        "11.0.6+security-01" is the patched build of 11.0.6, so treating the
        suffix as noise reported the fix as a confirmed match for "<= 11.0.6".
        """
        assert compare_versions("npm", "1.0.0+build1", "1.0.0+build2") is None
        assert evaluate_range("golang", "11.0.6+security-01", ">= 11.0.0, <= 11.0.6") is None

    def test_go_v_prefix_is_stripped(self):
        """Go PURLs carry a "v" that GitHub's ranges do not."""
        assert compare_versions("golang", "v1.6.0", "1.6.0") == 0
        assert compare_versions("golang", "v1.5.0", "1.6.0") == -1

    def test_unparseable_version_is_undecided(self):
        assert compare_versions("npm", "latest", "1.0.0") is None
        assert compare_versions("npm", "1.0.0", "") is None


class TestMavenOrdering:
    """Maven ranks qualifiers rather than sorting them alphabetically."""

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("2.14.1", "2.15.0", -1),
            ("2.4", "2.4.0", 0),
            ("2.0-alpha1", "2.0-beta9", -1),
            ("2.0-beta9", "2.0", -1),
            ("3.0.0-beta1", "3.0.0-beta3", -1),
            # "sp" is a service pack: it follows the plain release.
            ("1.0", "1.0-sp1", -1),
            # Where semver would call these equal-ranked strings, Maven does not.
            ("1.0-rc1", "1.0-snapshot", -1),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert compare_versions("maven", left, right) == expected


class TestPep440Ordering:
    """PyPI versions are not semver."""

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("3.2.1", "3.2.10", -1),
            ("1.0rc1", "1.0", -1),
            ("1.0.post1", "1.0", 1),
            ("1.0.dev1", "1.0a1", -1),
            ("2!1.0", "1.0", 1),
            ("1.0", "1.0.0", 0),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert compare_versions("pypi", left, right) == expected

    def test_invalid_pep440_is_undecided(self):
        assert compare_versions("pypi", "not-a-version", "1.0") is None


class TestRangeEvaluation:
    """GitHub's vulnerableVersionRange grammar."""

    @pytest.mark.parametrize(
        "version,vulnerable_range,expected",
        [
            ("0.5.0", "< 1.0.0", True),
            ("1.0.0", "< 1.0.0", False),
            ("9.9.9", "< 1.0.0", False),
            ("1.0.0", "<= 1.0.0", True),
            ("2.0.0", ">= 1.0.0, < 1.5.0", False),
            ("1.2.0", ">= 1.0.0, < 1.5.0", True),
            ("1.0.0", ">= 1.0.0, < 1.5.0", True),
            ("1.5.0", ">= 1.0.0, < 1.5.0", False),
            ("2.1.0", "= 2.1.0", True),
            ("2.1.1", "= 2.1.0", False),
            ("3.0.0", "> 2.0.0", True),
            ("2.0.0", "> 2.0.0", False),
        ],
    )
    def test_npm_ranges(self, version, vulnerable_range, expected):
        assert evaluate_range("npm", version, vulnerable_range) is expected

    def test_the_three_cases_from_the_issue(self):
        """Issue #28 recorded these three returning True before the fix."""
        assert evaluate_range("npm", "9.9.9", "< 1.0.0") is False
        assert evaluate_range("npm", "2.0.0", ">= 1.0.0, < 1.5.0") is False
        assert evaluate_range("npm", "0.5.0", "< 1.0.0") is True

    def test_empty_range_covers_every_version(self):
        """No range means the advisory does not narrow by version."""
        assert evaluate_range("npm", "1.0.0", "") is True
        assert evaluate_range("npm", "1.0.0", "   ") is True

    def test_unparseable_range_is_undecided(self):
        """Undecided must never be reported as "not affected"."""
        assert evaluate_range("npm", "1.0.0", "~> 1.0") is None
        assert evaluate_range("npm", "1.0.0", "< not-a-version") is None

    def test_unparseable_version_is_undecided(self):
        assert evaluate_range("npm", "latest", "< 1.0.0") is None
        assert evaluate_range("npm", "", "< 1.0.0") is None

    def test_maven_prerelease_range(self):
        """A real log4j-core range, evaluated with Maven ordering."""
        assert evaluate_range("maven", "2.14.1", ">= 2.0-beta9, < 2.25.3") is True
        assert evaluate_range("maven", "1.2.17", ">= 2.0-beta9, < 2.25.3") is False
        assert evaluate_range("maven", "3.0.0-beta2", ">= 3.0.0-beta1, <= 3.0.0-beta3") is True

    def test_go_pseudo_version_range(self):
        """A real gin range, with a pseudo-version as the lower bound."""
        span = ">= 1.3.1-0.20190301021747-ccb9e902956d, < 1.9.1"
        assert evaluate_range("golang", "v1.7.0", span) is True
        assert evaluate_range("golang", "v1.9.1", span) is False

    def test_pypi_range(self):
        assert evaluate_range("pypi", "3.2.1", ">= 3.2, < 3.2.13") is True
        assert evaluate_range("pypi", "4.0", ">= 3.2, < 3.2.13") is False


class TestGemOrdering:
    """RubyGems is not semver: it compares digit and letter segments."""

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            # The whole point: as strings "pre2" sorts after "pre12".
            ("3.0.0.pre2", "3.0.0.pre12", -1),
            ("3.0.0.pre1", "3.0.0", -1),
            ("1.2.4", "1.2.10", -1),
            ("7.1.3.1", "7.1.3", 1),
            ("1.0", "1.0.0", 0),
            ("2.0.0.rc1", "2.0.0.rc2", -1),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert compare_versions("gem", left, right) == expected

    def test_prerelease_inside_a_prerelease_range(self):
        """Reproduced live: avo 3.0.0.pre2 was dropped from two advisories."""
        span = ">= 3.0.0.pre1, <= 3.0.0.pre12"
        assert evaluate_range("gem", "3.0.0.pre2", span) is True
        assert evaluate_range("gem", "3.0.0.pre13", span) is False

    def test_ordinary_gem_ranges_still_decide(self):
        assert evaluate_range("gem", "7.1.2", ">= 7.1.0, < 7.1.3.1") is True
        assert evaluate_range("gem", "1.2.4", "< 1.2.4") is False


class TestUnrankableQualifiersAreUndecided:
    """A qualifier this module cannot rank must never be guessed at.

    Ranking unknown Maven qualifiers by raw text put "q1.2" after "q1.12" and
    silently excluded advisories that did apply - the exact false clean scan
    the tool exists to prevent.
    """

    @pytest.mark.parametrize(
        "version,vulnerable_range",
        [
            ("2024.Q1.2", ">= 2024.Q1.1, <= 2024.Q1.12"),
            ("1.0.0-preview.99", "< 1.0.0-preview.100"),
            ("4.21.0-liferay.9", "< 4.21.0-liferay.10"),
            ("2025.Q2.10", ">= 2025.Q2.0, <= 2025.Q2.9"),
            ("1.0-mysteryqualifier", "< 1.0-other"),
        ],
    )
    def test_undecidable_rather_than_excluded(self, version, vulnerable_range):
        assert evaluate_range("maven", version, vulnerable_range) is None

    def test_known_maven_qualifiers_still_decide(self):
        """The fix must not turn ordinary Maven queries into guesswork."""
        assert evaluate_range("maven", "2.14.1", ">= 2.0-beta9, < 2.25.3") is True
        assert evaluate_range("maven", "1.2.17", ">= 2.0-beta9, < 2.25.3") is False
        assert evaluate_range("maven", "2.14.1", ">= 2.13.0, < 2.15.0") is True
        assert evaluate_range("maven", "3.0.0-beta2", ">= 3.0.0-beta1, <= 3.0.0-beta3") is True

    def test_an_identical_odd_qualifier_still_compares_equal(self):
        assert compare_versions("maven", "2024.Q1.2", "2024.Q1.2") == 0


class TestGemDashVersions:
    """Gem::Version rewrites "-" to ".pre.", making a dash version a pre-release.

    Ordering "2.2.3-1" above 2.2.3 instead of below it silently excluded three
    advisories from a live rack query.
    """

    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("2.2.3-1", "2.2.3", -1),
            ("2.2.3-1", "2.2.3.0", -1),
            ("2.2.3-1", "2.2.2", 1),
            ("1.0-1", "1.0", -1),
            ("1.0.0-beta", "1.0.0", -1),
            # Gem treats these two spellings as the same version.
            ("1.0.0.beta.1", "1.0.0.beta1", 0),
        ],
    )
    def test_matches_ruby_gem_version(self, left, right, expected):
        assert compare_versions("gem", left, right) == expected

    def test_the_rack_ranges_that_were_excluded(self):
        assert evaluate_range("gem", "2.2.3-1", ">= 2.2, <= 2.2.3.0") is True
        assert evaluate_range("gem", "2.2.3-1", ">= 2.2.0, < 2.2.3") is True


class TestBuildMetadataOnlyBlocksTies:
    """Build metadata cannot overturn a difference in the release numbers.

    Refusing every comparison involving "+" made Go's ubiquitous
    "+incompatible" unconfirmed even when the major versions settled it.
    """

    def test_differing_releases_still_decide(self):
        assert evaluate_range("golang", "3.2.0+incompatible", "< 4.0.0-preview1") is True
        assert evaluate_range("golang", "1.0.0+build", "< 2.0.0") is True
        assert evaluate_range("golang", "5.0.0+build", "< 2.0.0") is False

    def test_a_tie_is_still_undecided(self):
        assert evaluate_range("golang", "11.0.6+security-01", ">= 11.0.0, <= 11.0.6") is None
        assert compare_versions("npm", "1.0.0+build1", "1.0.0+build2") is None


class TestMavenShortAliases:
    """Maven reads "a"/"b"/"m" as alpha/beta/milestone only before a digit."""

    def test_bare_letters_are_undecided(self):
        assert compare_versions("maven", "12", "12m") is None
        assert compare_versions("maven", "1.0-a", "1.0-alpha1") is None

    def test_letters_with_a_digit_still_rank(self):
        assert compare_versions("maven", "1.0-b2", "1.0-b3") == -1
        assert compare_versions("maven", "1.0-a1", "1.0-b1") == -1
        assert evaluate_range("maven", "2.14.1", ">= 2.0-beta9, < 2.25.3") is True


class TestGoIncompatibleSuffix:
    """ "+incompatible" is a Go module-path marker, not semantic metadata.

    Go's own semver package ignores it, and a large share of real Go SBOM
    entries carry it, so treating it as opaque left them all unconfirmed.
    """

    def test_it_is_ignored_for_ordering(self):
        assert compare_versions("golang", "3.2.0+incompatible", "3.2.0") == 0
        assert compare_versions("golang", "3.2.0+incompatible", "3.1.0") == 1

    def test_the_live_jwt_go_advisory_resolves(self):
        span = ">= 0.0.0-20150717181359-44718f8a89b0, <= 3.2.0"
        assert evaluate_range("golang", "3.2.0+incompatible", span) is True
        assert evaluate_range("golang", "4.0.0+incompatible", span) is False

    def test_other_build_metadata_is_still_undecided(self):
        assert compare_versions("golang", "11.0.6+security-01", "11.0.6") is None
