"""The CHANGELOG documents the version the package declares (issue #71).

`pyproject.toml` and `vulnq/__init__.py` already have a test holding them to
each other. Nothing held either of them to the CHANGELOG, so a release could
bump both numbers and ship with the notes still filed under `[Unreleased]` —
the published version then has no entry anywhere describing what changed in
it, which is the one artifact a consumer reads before upgrading.
"""

import re
from pathlib import Path

import vulnq

RELEASE_HEADING = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)


def _changelog_versions():
    """Every released version in CHANGELOG order, newest first.

    `[Unreleased]` is a holding area rather than a version, so it is dropped:
    the question this answers is which version the notes most recently closed.
    """
    root = Path(__file__).resolve().parent.parent
    changelog = (root / "CHANGELOG.md").read_text()
    return [v for v in RELEASE_HEADING.findall(changelog) if v.lower() != "unreleased"]


def test_the_changelog_has_released_sections_at_all():
    """A negative control for the test below.

    If the heading pattern ever stops matching — a reformat, a move to a
    different changelog convention — `_changelog_versions()` returns an empty
    list and the agreement test below becomes vacuously unreadable rather
    than failing. This fails instead, and names the real cause.
    """
    assert _changelog_versions(), "no '## [version]' headings found in CHANGELOG.md"


def test_the_declared_version_has_changelog_notes():
    """The newest released section must be the version being shipped.

    Written as "newest section == __version__" rather than "__version__
    appears somewhere in the file" on purpose: the second passes forever once
    any release mentions the number, including when the current release's
    notes are still sitting under [Unreleased].
    """
    newest = _changelog_versions()[0]
    assert newest == vulnq.__version__, (
        f"__version__ is {vulnq.__version__} but the newest CHANGELOG section "
        f"is [{newest}] — move the [Unreleased] notes under "
        f"[{vulnq.__version__}] before releasing"
    )
