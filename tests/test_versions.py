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
            # Build metadata never affects precedence.
            ("1.0.0+build1", "1.0.0+build2", 0),
        ],
    )
    def test_ordering(self, left, right, expected):
        assert compare_versions("npm", left, right) == expected

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
