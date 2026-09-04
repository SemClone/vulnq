"""Guards for the VulnerableCode evaluation and the facts it rests on.

Issue #53 asked what removing VulnerableCode would cost rather than what fixing
it would. The answer is a document, and a document rots. These pin the parts of
it that the tree can check, so a later change that invalidates the evaluation
fails here instead of leaving a confident recommendation standing on facts that
have moved.

The one fact that cannot be pinned offline is the one the recommendation turns
on: that OSV answers `deb` and `rpm` PURLs from the default fan-out. That is a
live-API claim, and the document says how to re-run it. What is pinned here is
the half within reach - that vulnq's OSV client does not refuse those PURLs
before they ever reach the API, which is how VulnerableCode fails them.
"""

import asyncio
import pathlib

import pytest

from vulnq.clients.osv import OSVClient
from vulnq.models import VulnerabilitySource
from vulnq.sources import MERGE_PRIORITY

ROOT = pathlib.Path(__file__).parent.parent
EVALUATION = ROOT / "docs" / "evaluations" / "vulnerablecode.md"

DISTRO_PURLS = (
    "pkg:deb/debian/curl@7.64.0-4",
    "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6",
    "pkg:apk/alpine/openssl@1.1.1q-r0",
)


class TestTheEvaluationIsWhereItSaysItIs:
    """The deprecation warning the document proposes names this path."""

    def test_the_document_exists(self):
        assert EVALUATION.is_file(), f"{EVALUATION} is referenced but missing"

    @pytest.mark.parametrize(
        "heading",
        [
            "## Recommendation",
            "## 1. What removing it costs",
            "## 2. Unique coverage, measured",
            "## 5. Deprecation path",
            "## 6. Replacing it",
            "## 7. Removal versus the fix, side by side",
        ],
    )
    def test_every_acceptance_criterion_has_a_section(self, heading):
        """Issue #53 lists six. A section can be wrong; a missing one is not
        an evaluation at all."""
        assert heading in EVALUATION.read_text()

    def test_the_readme_points_at_it(self):
        """Otherwise it is a file nobody finds until they go looking."""
        assert "docs/evaluations/vulnerablecode.md" in (ROOT / "README.md").read_text()


class TestTheFactsTheRecommendationRestsOn:
    """Each of these is quoted in the document as a reason to remove.

    Two more are quoted and are not repeated here, because the tree already
    pins them and a second copy would be one more thing to keep in step:
    that the source is selectable but not in the default fan-out lives in
    test_source_registry.py, and that it refuses distribution PURLs lives in
    test_vulnerablecode_v3.py, which also asserts the reason it gives.
    """

    def test_it_defers_to_every_other_source(self):
        """Lower wins, so the largest number is the one that never decides."""
        others = [
            priority
            for source, priority in MERGE_PRIORITY.items()
            if source is not VulnerabilitySource.VULNERABLECODE
        ]
        assert MERGE_PRIORITY[VulnerabilitySource.VULNERABLECODE] > max(others)


class TestRemovalWouldNotCreateTheGap:
    """OSV is in the default fan-out, so what it accepts is what survives."""

    @pytest.mark.parametrize("purl", DISTRO_PURLS)
    def test_osv_does_not_refuse_a_distribution_purl(self, purl, monkeypatch):
        """VulnerableCode declines these before the request is made. OSV does
        not, so the same query reaches an API that answers deb and rpm."""

        async def empty(self, method, url, **kwargs):
            return {"vulns": []}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", empty)

        assert asyncio.run(OSVClient().query_purl(purl)) == []
