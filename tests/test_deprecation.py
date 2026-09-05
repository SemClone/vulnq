"""Retiring a source, and the two notices that go with it.

A source on the way out has to say so, once, on the right stream. Nothing is
deprecated right now - VulnerableCode was the first and only user of that
machinery, and 2.0 deleted it - so what is pinned here is that the machinery
still works for whoever needs it next, and that the name it left behind is
handled rather than tripped over.

The name matters because of how it was read. USE_VULNERABLECODE=true and
VULNQ_DISABLED_SOURCES=vulnerablecode both come from os.environ.get, so once
the source is gone they are skipped in silence and a job that believes it is
querying one thing quietly queries another. Silence is exactly what the
deprecation release was written to avoid, and deleting the source must not
reintroduce it.
"""

import io
import subprocess
import sys

import pytest
from click.testing import CliRunner

from vulnq.cli import main
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, VulnerabilitySource
from vulnq.sources import (
    BY_SOURCE,
    REGISTRY,
    RETIRED_SOURCES,
    SourceSpec,
    UnknownSourceError,
    deprecation_warning,
    parse_disabled,
    retired_note,
)


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


def _stderr_while(call):
    """Return only what a call wrote to stderr."""
    captured = io.StringIO()
    original = sys.stderr
    sys.stderr = captured
    try:
        call()
    finally:
        sys.stderr = original
    return captured.getvalue()


def _deprecate(monkeypatch, source, removed_in="9.9", note="use something else"):
    """Put a source on the way out, for the length of one test."""
    spec = BY_SOURCE[source]
    monkeypatch.setitem(
        BY_SOURCE,
        source,
        SourceSpec(
            source=spec.source,
            build=spec.build,
            in_default_fanout=spec.in_default_fanout,
            merge_priority=spec.merge_priority,
            removed_in=removed_in,
            deprecation_note=note,
        ),
    )


class TestTheDeprecationMachineryOutlivedItsFirstUser:
    """`removed_in` and `deprecation_note` are how the next source goes."""

    def test_a_spec_with_a_removal_release_produces_a_notice(self, monkeypatch):
        _deprecate(monkeypatch, VulnerabilitySource.OSV)
        warning = deprecation_warning(VulnerabilitySource.OSV)

        assert warning is not None
        assert "osv" in warning
        assert "9.9" in warning

    def test_the_notice_says_what_to_do_instead(self, monkeypatch):
        """A warning that only says stop is one the reader cannot act on."""
        _deprecate(monkeypatch, VulnerabilitySource.NVD, note="use github")

        assert "use github" in deprecation_warning(VulnerabilitySource.NVD)

    def test_a_note_without_a_removal_release_says_nothing(self, monkeypatch):
        """`deprecation_note` is pointless without `removed_in`, and silent."""
        _deprecate(monkeypatch, VulnerabilitySource.OSV, removed_in=None, note="ignored")

        assert deprecation_warning(VulnerabilitySource.OSV) is None

    def test_the_engine_reaches_a_library_caller_too(self, monkeypatch):
        """Configuration(sources=[...]) reaches none of the CLI surfaces, so
        warning at those would leave this caller the only one told nothing."""
        _deprecate(monkeypatch, VulnerabilitySource.OSV)

        assert "deprecated" in _stderr_of(Configuration(sources=[VulnerabilitySource.OSV]))

    def test_it_is_said_once_per_engine(self, monkeypatch):
        _deprecate(monkeypatch, VulnerabilitySource.OSV)
        config = Configuration(sources=[VulnerabilitySource.OSV, VulnerabilitySource.NVD])

        assert _stderr_of(config).count("deprecated") == 1

    def test_a_source_switched_off_does_not_warn(self, monkeypatch):
        """It was named and then disabled, so it is not being queried and
        there is nothing to stop doing."""
        _deprecate(monkeypatch, VulnerabilitySource.OSV)
        config = Configuration(
            sources=[VulnerabilitySource.OSV, VulnerabilitySource.NVD],
            disabled_sources=[VulnerabilitySource.OSV],
        )

        assert _stderr_of(config) == ""


class TestNothingIsOnTheWayOutRightNow:
    @pytest.mark.parametrize("spec", REGISTRY, ids=lambda s: s.source.value)
    def test_no_shipped_source_carries_a_removal_release(self, spec):
        assert spec.removed_in is None
        assert deprecation_warning(spec.source) is None

    def test_the_default_fanout_is_quiet(self):
        assert _stderr_of(Configuration()) == ""


class TestTheNameARetiredSourceLeftBehind:
    def test_vulnerablecode_is_the_name_that_was_retired(self):
        """If this changes, the changelog and the migration note are stale."""
        assert RETIRED_SOURCES == {"vulnerablecode": "2.0"}

    def test_the_notice_names_the_release_and_what_covers_it_now(self):
        note = retired_note("vulnerablecode")

        assert "2.0" in note
        assert "osv" in note

    def test_a_name_that_was_never_a_source_gets_no_notice(self):
        assert retired_note("gitub") is None

    def test_disabling_it_is_a_no_op_rather_than_a_failure(self):
        """A job with it baked in is asking for something already true."""
        assert parse_disabled("vulnerablecode") == ()

    def test_disabling_it_alongside_a_real_source_still_disables_that_one(self):
        assert parse_disabled("vulnerablecode,nvd") == (VulnerabilitySource.NVD,)

    def test_it_is_not_selectable_again_by_the_back_door(self):
        """Forgiven in the disable list is not the same as still a source."""
        assert "vulnerablecode" not in {s.value for s in VulnerabilitySource}

    def test_a_typo_is_still_a_typo(self):
        with pytest.raises(UnknownSourceError):
            parse_disabled("gitub")

    def test_the_environment_variable_that_selected_it_says_it_is_ignored(
        self, monkeypatch
    ):
        """The surface the deprecation release existed for."""
        monkeypatch.setenv("USE_VULNERABLECODE", "true")

        # Said where it is read. There is no other path that names it.
        assert "removed in 2.0" in _stderr_while(VulnerabilityQuery.load_config)

    def test_the_environment_variable_no_longer_narrows_the_fanout(self, monkeypatch):
        """It used to mean "query only VulnerableCode". It must not now mean
        "query only" anything."""
        monkeypatch.setenv("USE_VULNERABLECODE", "true")
        config = VulnerabilityQuery.load_config()

        assert VulnerabilitySource.OSV in (config.sources or [])

    def test_the_notice_is_said_once_per_run_not_once_per_parse(self):
        """VULNQ_DISABLED_SOURCES was read by load_config and by click, so the
        value was parsed twice and the notice printed twice."""
        import os
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "vulnq.cli", "pkg:npm/x@1.0.0", "--sources", "osv"],
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "VULNQ_DISABLED_SOURCES": "vulnerablecode"},
        )

        assert proc.stderr.count("removed in 2.0") == 1

    def test_the_disable_list_still_disables_a_real_source_from_the_environment(self):
        """Reading it in one place must not stop it being read at all."""
        import json
        import os
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "vulnq.cli", "pkg:npm/x@1.0.0", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "VULNQ_DISABLED_SOURCES": "github"},
        )

        assert "github" in json.loads(proc.stdout)["sources_skipped"]

    def test_selecting_it_by_name_fails_and_lists_what_is_left(self):
        result = CliRunner().invoke(main, ["pkg:npm/x@1.0.0", "--sources", "vulnerablecode"])

        assert result.exit_code == 2
        assert "osv" in result.output


def test_the_notices_stay_off_stdout():
    """A caller reading --format json on stdout would otherwise get a warning
    spliced into the document, which is worse than the problem it reports."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os;"
            "os.environ['USE_VULNERABLECODE'] = 'true';"
            "from vulnq.core import VulnerabilityQuery;"
            "VulnerabilityQuery(config=VulnerabilityQuery.load_config())",
        ],
        capture_output=True,
        text=True,
    )

    assert result.stdout == ""
    assert "removed in 2.0" in result.stderr


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


class TestRemovingItDidNotCreateAGap:
    """The fact the removal decision rested on that the tree can still check:
    the distro PURLs it declined before the request was made - which is what
    opened issue #53 - are accepted by OSV, and OSV is in the default fan-out.
    """

    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:deb/debian/curl@7.64.0-4",
            "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6",
            "pkg:apk/alpine/openssl@1.1.1q-r0?distro=alpine-3.16",
        ],
    )
    def test_osv_accepts_the_distro_purls(self, purl, monkeypatch):
        import asyncio

        from vulnq.clients.osv import OSVClient

        async def empty(self, method, url, **kwargs):
            return {"vulns": []}

        monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", empty)

        assert asyncio.run(OSVClient().query_purl(purl)) == []
