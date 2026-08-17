"""Ecosystem-aware version comparison and vulnerable-range evaluation.

The GitHub Advisory Database returns every advisory it holds for a package and
leaves the version filtering to the caller, in a small grammar:

    "< 1.0.0"
    "<= 3.21.4"
    "= 2.1.0"
    ">= 2.0-beta9, < 2.25.3"
    ">= 5.0.0-alpha.1, < 5.0.0-beta.3"

Evaluating it needs the ecosystem's own ordering, because "1.0-alpha1" and
"1.0.0rc1" sort differently under Maven, semver, and PEP 440.

Every function here returns None rather than guessing when it cannot decide.
Callers must treat None as "include the advisory and say it is unconfirmed":
dropping an advisory that might apply is the dangerous direction for this tool,
and a range we cannot parse is not evidence of safety.
"""

import re
from typing import Any, List, Optional, Tuple

# Ecosystems whose versions follow PEP 440 rather than semver.
_PEP440_ECOSYSTEMS = {"pypi", "pip"}

# RubyGems orders by digit/letter segments, not by semver pre-release rules.
# Routing it through the semver comparator compared "pre2" and "pre12" as whole
# strings, which reversed them and dropped advisories that did apply.
_GEM_ECOSYSTEMS = {"gem", "rubygems"}

# Maven orders qualifiers by rank rather than alphabetically, so "1.0-rc1"
# precedes "1.0" and "1.0-sp1" follows it. Taken from Maven's own
# ComparableVersion ordering; an unrecognised qualifier ranks after all of
# these and is broken by comparing the qualifier text.
_MAVEN_QUALIFIER_RANK = {
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "rc": 4,
    "cr": 4,
    "snapshot": 5,
    "": 6,
    "ga": 6,
    "final": 6,
    "release": 6,
    "sp": 7,
}
_MAVEN_UNKNOWN_QUALIFIER_RANK = 8

# Maven only reads these as alpha/beta/milestone when a digit follows them.
_MAVEN_SHORT_ALIASES = {"a", "b", "m"}

_INCOMPATIBLE_RE = re.compile(r"\+incompatible$", re.IGNORECASE)

_CONSTRAINT_RE = re.compile(r"^\s*(<=|>=|==|=|<|>)?\s*(\S.*?)\s*$")

# A leading dotted-numeric run, then whatever qualifier follows it.
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


class UnparseableVersion(ValueError):
    """Raised internally when a version string cannot be ordered."""


def _strip_v_prefix(version: str) -> str:
    """Drop a leading "v", which Go PURLs carry and GitHub's ranges do not.

    Args:
        version: Raw version string

    Returns:
        The version without a leading "v"
    """
    if len(version) > 1 and version[0] in "vV" and version[1].isdigit():
        return version[1:]
    return version


def _split_release(version: str) -> Tuple[Tuple[int, ...], str]:
    """Split a version into its numeric release and its trailing qualifier.

    Args:
        version: Version string with any "v" prefix already removed

    Returns:
        Tuple of (release numbers, qualifier text)

    Raises:
        UnparseableVersion: If the version does not start with a number
    """
    match = _RELEASE_RE.match(version)
    if not match:
        raise UnparseableVersion(version)
    release = tuple(int(part) for part in match.group(1).split("."))
    qualifier = match.group(2).lstrip(".-_+")
    return release, qualifier


def _pad(left: Tuple[int, ...], right: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """Zero-pad two release tuples to the same length.

    Maven and RubyGems both treat "2.4" and "2.4.0" as the same release, and
    GitHub's ranges mix the two spellings freely within one advisory.

    Args:
        left: First release tuple
        right: Second release tuple

    Returns:
        The two tuples, padded to equal length
    """
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def _compare_prerelease_identifiers(left: List[str], right: List[str]) -> int:
    """Compare two semver pre-release identifier lists.

    Semver rules: numeric identifiers compare numerically and rank below
    alphanumeric ones, and a shorter list ranks below an otherwise equal
    longer one.

    Args:
        left: First identifier list
        right: Second identifier list

    Returns:
        -1, 0, or 1
    """
    for a, b in zip(left, right):
        a_numeric, b_numeric = a.isdigit(), b.isdigit()
        if a_numeric and b_numeric:
            if int(a) != int(b):
                return -1 if int(a) < int(b) else 1
            continue
        if a_numeric != b_numeric:
            # A numeric identifier always has lower precedence.
            return -1 if a_numeric else 1
        if a != b:
            return -1 if a < b else 1

    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def _compare_semver(left: str, right: str) -> int:
    """Compare two versions under semver-style ordering.

    Used for npm, RubyGems, NuGet, Cargo, Composer, Go, Hex, Pub, and Swift,
    which agree on the parts that matter here: numeric release segments, then
    an optional pre-release that sorts before the plain release.

    Args:
        left: First version
        right: Second version

    Returns:
        -1, 0, or 1

    Raises:
        UnparseableVersion: If either version cannot be ordered
    """
    # "+incompatible" is not build metadata in the semver sense: Go's module
    # system appends it to any pre-modules major above v1, and Go's own semver
    # package ignores it. Treating it as opaque left every such version
    # unconfirmed, and a large share of real Go SBOM entries carry it.
    left = _INCOMPATIBLE_RE.sub("", left)
    right = _INCOMPATIBLE_RE.sub("", right)

    has_metadata = "+" in left or "+" in right
    left_release, left_qualifier = _split_release(_strip_v_prefix(left).split("+")[0])
    right_release, right_qualifier = _split_release(_strip_v_prefix(right).split("+")[0])

    left_release, right_release = _pad(left_release, right_release)
    if left_release != right_release:
        # Build metadata cannot overturn a difference in the release numbers,
        # so Go's ubiquitous "+incompatible" still gets a real answer here.
        return -1 if left_release < right_release else 1

    # Once the numbers tie, the suffix is the only thing left to order by, and
    # semver says to ignore it while Grafana and pub do not:
    # "11.0.6+security-01" is the *patched* build of 11.0.6, and discarding
    # the suffix reported it as a confirmed match for "<= 11.0.6". Undecided
    # is honest; the caller reports it as unconfirmed rather than dropping it.
    if has_metadata:
        raise UnparseableVersion(f"build metadata is not orderable: {left} vs {right}")

    if not left_qualifier and not right_qualifier:
        return 0
    if not left_qualifier:
        # A release outranks any pre-release of the same numbers.
        return 1
    if not right_qualifier:
        return -1

    return _compare_prerelease_identifiers(left_qualifier.split("."), right_qualifier.split("."))


def _maven_qualifier_key(qualifier: str) -> Tuple[int, int]:
    """Rank a Maven qualifier so "rc1" sorts before the plain release.

    Args:
        qualifier: Qualifier text, possibly empty

    Returns:
        Sort key of (rank, trailing number)

    Raises:
        UnparseableVersion: If the qualifier is not one this table ranks
    """
    normalized = qualifier.lower().replace("-", "").replace("_", "")
    match = re.match(r"^([a-z]*)(\d*)$", normalized)
    if not match:
        # Calendar-style and vendor qualifiers such as "Q1.2" or "liferay.9"
        # do not fit this shape at all. Ranking them anyway meant comparing
        # them as raw text, which put "q1.2" after "q1.12" and pushed real
        # versions out of every range they belonged to.
        raise UnparseableVersion(qualifier)

    word, number = match.group(1), match.group(2)

    # Maven reads "a", "b" and "m" as alpha/beta/milestone only when a digit
    # follows. Bare, they are ordinary unknown qualifiers, which this table
    # cannot rank - so treat them as undecidable rather than as aliases.
    if word in _MAVEN_SHORT_ALIASES and not number:
        raise UnparseableVersion(qualifier)

    rank = _MAVEN_QUALIFIER_RANK.get(word)
    if rank is None:
        # An unrecognised word is undecidable rather than "ranks last". The
        # caller turns that into an unconfirmed finding, which is reported;
        # a guess here silently excluded advisories that did apply.
        raise UnparseableVersion(qualifier)
    return (rank, int(number) if number else 0)


def _compare_maven(left: str, right: str) -> int:
    """Compare two versions under Maven's ordering.

    Args:
        left: First version
        right: Second version

    Returns:
        -1, 0, or 1

    Raises:
        UnparseableVersion: If either version cannot be ordered
    """
    left_release, left_qualifier = _split_release(_strip_v_prefix(left))
    right_release, right_qualifier = _split_release(_strip_v_prefix(right))

    left_release, right_release = _pad(left_release, right_release)
    if left_release != right_release:
        return -1 if left_release < right_release else 1

    if left_qualifier == right_qualifier:
        # Identical text needs no ranking, so an unrankable qualifier still
        # compares equal to itself.
        return 0

    left_key = _maven_qualifier_key(left_qualifier)
    right_key = _maven_qualifier_key(right_qualifier)
    if left_key == right_key:
        return 0
    return -1 if left_key < right_key else 1


def _gem_segments(version: str) -> List[Any]:
    """Split a RubyGems version into comparable segments.

    Gem::Version tokenizes on runs of digits and runs of letters, so
    "3.0.0.pre2" becomes [3, 0, 0, "pre", 2]. That is what makes "pre2" sort
    before "pre12"; comparing the two as whole strings does the opposite.

    Args:
        version: Version string

    Returns:
        List of int and str segments

    Raises:
        UnparseableVersion: If the version contains no segments
    """
    # Gem::Version rewrites a dash to ".pre." before segmenting, so "2.2.3-1"
    # is a pre-release *below* 2.2.3 rather than something above it. Skipping
    # this step ordered dash versions the opposite way and silently excluded
    # advisories that applied.
    segments: List[Any] = []
    for token in re.findall(r"\d+|[A-Za-z]+", version.replace("-", ".pre.")):
        # Gem compares letter segments as-is; lowercasing them made "RC1" and
        # "rc1" equal where Ruby orders them.
        segments.append(int(token) if token.isdigit() else token)
    if not segments:
        raise UnparseableVersion(version)
    return _canonical_gem_segments(segments)


def _canonical_gem_segments(segments: List[Any]) -> List[Any]:
    """Drop trailing zeros the way Gem::Version#canonical_segments does.

    Gem splits the segments at the first letter and drops trailing zeros from
    each half independently, which is what makes "0.9.b" and "0.9.0.b" the
    same version. Zero-padding alone ordered them apart, and confidently
    wrongly.

    Args:
        segments: Raw int and str segments

    Returns:
        The canonical segment list
    """
    first_text = next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))
    canonical: List[Any] = []
    for half in (segments[:first_text], segments[first_text:]):
        end = len(half)
        while end > 0 and half[end - 1] == 0:
            end -= 1
        canonical.extend(half[:end])
    return canonical


def _compare_gem(left: str, right: str) -> int:
    """Compare two versions under RubyGems ordering.

    Gem is not semver: it compares segment by segment, a letter segment ranks
    below a numeric one, and missing trailing segments count as zero.

    Args:
        left: First version
        right: Second version

    Returns:
        -1, 0, or 1

    Raises:
        UnparseableVersion: If either version cannot be ordered
    """
    left_segments = _gem_segments(_strip_v_prefix(left))
    right_segments = _gem_segments(_strip_v_prefix(right))

    for index in range(max(len(left_segments), len(right_segments))):
        a: Any = left_segments[index] if index < len(left_segments) else 0
        b: Any = right_segments[index] if index < len(right_segments) else 0
        if a == b:
            continue
        a_is_text, b_is_text = isinstance(a, str), isinstance(b, str)
        if a_is_text != b_is_text:
            # A letter segment marks a pre-release, which precedes any number.
            return -1 if a_is_text else 1
        return -1 if a < b else 1

    return 0


def _compare_pep440(left: str, right: str) -> int:
    """Compare two versions under PEP 440.

    Args:
        left: First version
        right: Second version

    Returns:
        -1, 0, or 1

    Raises:
        UnparseableVersion: If either version cannot be ordered
    """
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:  # pragma: no cover - packaging is a dependency
        raise UnparseableVersion(str(exc))

    try:
        left_version = Version(left)
        right_version = Version(right)
    except InvalidVersion as exc:
        raise UnparseableVersion(str(exc))

    if left_version == right_version:
        return 0
    return -1 if left_version < right_version else 1


def compare_versions(ecosystem: Optional[str], left: str, right: str) -> Optional[int]:
    """Order two versions within an ecosystem.

    Args:
        ecosystem: PURL type, e.g. "npm" or "maven". None uses semver rules.
        left: First version
        right: Second version

    Returns:
        -1, 0, or 1, or None if the pair cannot be ordered confidently
    """
    if not left or not right:
        return None

    normalized = (ecosystem or "").lower()
    try:
        if normalized in _PEP440_ECOSYSTEMS:
            return _compare_pep440(left, right)
        if normalized == "maven":
            return _compare_maven(left, right)
        if normalized in _GEM_ECOSYSTEMS:
            return _compare_gem(left, right)
        return _compare_semver(left, right)
    except UnparseableVersion:
        return None
    except Exception:
        # An ordering bug must not take a query down, and must not be read as
        # "not affected" either. Undecided is the safe answer.
        return None


def _satisfies(comparison: int, operator: str) -> Optional[bool]:
    """Apply a comparison operator to a -1/0/1 comparison result.

    Args:
        comparison: Result of comparing the queried version to the bound
        operator: One of <, <=, >, >=, =, ==

    Returns:
        Whether the constraint holds, or None for an unknown operator
    """
    if operator in ("<",):
        return comparison < 0
    if operator in ("<=",):
        return comparison <= 0
    if operator in (">",):
        return comparison > 0
    if operator in (">=",):
        return comparison >= 0
    if operator in ("=", "=="):
        return comparison == 0
    return None


def evaluate_range(ecosystem: Optional[str], version: str, vulnerable_range: str) -> Optional[bool]:
    """Decide whether a version falls inside a GitHub vulnerable-version range.

    Args:
        ecosystem: PURL type the version belongs to
        version: Version being queried
        vulnerable_range: GitHub `vulnerableVersionRange` string

    Returns:
        True if the version is inside the range, False if it is outside, and
        None if the range or version could not be evaluated. None must be
        treated as "include the advisory, unconfirmed" - never as "not
        affected".
    """
    if not version:
        return None
    if not vulnerable_range or not vulnerable_range.strip():
        # No range at all means the advisory does not narrow by version, so
        # every version of the package is in scope.
        return True

    for part in vulnerable_range.split(","):
        if not part.strip():
            continue

        match = _CONSTRAINT_RE.match(part)
        if not match:
            return None

        operator = match.group(1) or "="
        bound = match.group(2)

        comparison = compare_versions(ecosystem, version, bound)
        if comparison is None:
            return None

        holds = _satisfies(comparison, operator)
        if holds is None:
            return None
        if not holds:
            # Constraints within one range are conjunctive: failing any single
            # bound puts the version outside the vulnerable range.
            return False

    return True
