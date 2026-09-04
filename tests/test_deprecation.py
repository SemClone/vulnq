"""A source on the way out has to say so, once, on the right stream.

The whole reason VulnerableCode gets a deprecation release rather than a
straight delete is USE_VULNERABLECODE=true: it is read with os.environ.get, so
when the source goes it starts being ignored in silence and a job that thought
it was querying one thing quietly queries another. A warning nobody sees is the
same outcome, so what is pinned here is that it reaches every path that can
select the source, and that it does not reach stdout.
"""

import io
import subprocess
import sys

import pytest
from click.testing import CliRunner

from vulnq.cli import main
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, VulnerabilitySource
from vulnq.sources import BY_SOURCE, REGISTRY, deprecation_warning

DEPRECATED = [spec.source for spec in REGISTRY if spec.removed_in]
CURRENT = [spec.source for spec in REGISTRY if not spec.removed_in]


def _stderr_of(config):
    """Build an engine and return only what it wrote to stderr."""
    captured = io.StringIO()
    original = sys.stderr
    sys.stderr = captured
    try:
        VulnerabilityQuery(config=config)
    finally:
        sys.stderr = original
    return captured.getvalue()


class TestTheNoticeItself:
    def test_vulnerablecode_is_the_source_being_retired(self):
        """If this changes, the evaluation and the changelog are stale too."""
        assert DEPRECATED == [VulnerabilitySource.VULNERABLECODE]
        assert BY_SOURCE[VulnerabilitySource.VULNERABLECODE].removed_in == "2.0"

    def test_it_names_the_source_and_the_release_that_removes_it(self):
        warning = deprecation_warning(VulnerabilitySource.VULNERABLECODE)
        assert warning is not None
        assert "vulnerablecode" in warning
        assert "2.0" in warning

    def test_it_says_what_to_use_instead(self):
        """A warning that only says stop is one the reader cannot act on."""
        warning = deprecation_warning(VulnerabilitySource.VULNERABLECODE)
        assert "osv" in warning

    @pytest.mark.parametrize("source", CURRENT)
    def test_a_source_that_is_staying_has_no_notice(self, source):
        assert deprecation_warning(source) is None


class TestEveryPathThatSelectsItWarns:
    def test_a_library_caller_is_told(self):
        """Configuration(sources=[...]) reaches none of the CLI surfaces, so
        warning at those would leave this caller the only one told nothing."""
        assert "deprecated" in _stderr_of(
            Configuration(sources=[VulnerabilitySource.VULNERABLECODE])
        )

    def test_the_use_vulnerablecode_environment_variable_is_told(self, monkeypatch):
        """The surface the deprecation release exists for: it is read with
        os.environ.get, so after removal it fails silently."""
        monkeypatch.setenv("USE_VULNERABLECODE", "true")
        assert "deprecated" in _stderr_of(VulnerabilityQuery.load_config())

    def test_the_default_fanout_is_quiet(self):
        """Nobody asked for it, so nobody needs telling."""
        assert _stderr_of(Configuration()) == ""

    def test_a_source_switched_off_does_not_warn(self):
        """It was named and then disabled, so it is not being queried and
        there is nothing to stop doing."""
        config = Configuration(
            sources=[VulnerabilitySource.VULNERABLECODE, VulnerabilitySource.OSV],
            disabled_sources=[VulnerabilitySource.VULNERABLECODE],
        )
        assert _stderr_of(config) == ""

    def test_it_is_said_once_per_engine(self):
        config = Configuration(
            sources=[VulnerabilitySource.VULNERABLECODE, VulnerabilitySource.OSV]
        )
        assert _stderr_of(config).count("deprecated") == 1


def test_the_warning_stays_off_stdout():
    """A caller reading --format json on stdout would otherwise get a warning
    spliced into the document, which is worse than the problem it reports."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from vulnq.core import VulnerabilityQuery;"
            "from vulnq.models import Configuration, VulnerabilitySource;"
            "VulnerabilityQuery(config=Configuration("
            "sources=[VulnerabilitySource.VULNERABLECODE]))",
        ],
        capture_output=True,
        text=True,
    )
    assert result.stdout == ""
    assert "deprecated" in result.stderr


class TestAnUnknownSourceFailsTheSameWayFromEitherRoute:
    """Issue #61. VULNQ_DISABLED_SOURCES is parsed in load_config, outside the
    handler --disable-source is wrapped in, so the same typo used to print a
    traceback and exit 1 through one route and the valid sources and exit 2
    through the other."""

    def test_the_flag_exits_two_and_names_the_valid_sources(self):
        result = CliRunner().invoke(main, ["pkg:npm/x@1.0.0", "--disable-source", "gitub"])
        assert result.exit_code == 2
        assert "gitub" in result.output
        assert "osv" in result.output

    def test_the_environment_variable_does_the_same(self, monkeypatch):
        monkeypatch.setenv("VULNQ_DISABLED_SOURCES", "gitub")
        result = CliRunner().invoke(main, ["pkg:npm/x@1.0.0"])
        assert result.exit_code == 2
        assert "gitub" in result.output
        assert "osv" in result.output

    def test_neither_route_leaks_a_traceback(self, monkeypatch):
        monkeypatch.setenv("VULNQ_DISABLED_SOURCES", "gitub")
        result = CliRunner().invoke(main, ["pkg:npm/x@1.0.0"])
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Traceback" not in result.output


class TestRemovingItWouldNotCreateAGap:
    """The two facts the removal decision rests on that the tree can check.
    Kept from the evaluation's own tests, which went with the document."""

    def test_it_never_decides_an_overlap(self):
        """Lower priority wins, so the largest number is the source that
        defers to every other. It aggregates them; it does not add to them."""
        from vulnq.sources import MERGE_PRIORITY

        others = [
            priority
            for source, priority in MERGE_PRIORITY.items()
            if source is not VulnerabilitySource.VULNERABLECODE
        ]
        assert MERGE_PRIORITY[VulnerabilitySource.VULNERABLECODE] > max(others)

    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:deb/debian/curl@7.64.0-4",
            "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6",
            "pkg:apk/alpine/openssl@1.1.1q-r0",
        ],
    )
    def test_osv_accepts_the_distro_purls_vulnerablecode_refuses(self, purl, monkeypatch):
        """VulnerableCode declines these before the request is made, which is
        what opened issue #53. OSV does not, so the same query reaches an API
        that answers deb and rpm - and OSV is in the default fan-out, so
        removing VulnerableCode takes nothing away here."""
        import asyncio

        from vulnq.clients.osv import OSVClient

        async def empty(self, method, url, **kwargs):
            return {"vulns": []}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", empty)

        assert asyncio.run(OSVClient().query_purl(purl)) == []
