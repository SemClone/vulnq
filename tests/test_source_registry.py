"""A source is declared once, and can be switched off without a code change.

A source used to be named in seven files. One of them accounted for fifteen of
those sites on its own, because it replaced the fan-out instead of joining it,
and that special case is how three bugs lived unnoticed in its client.

Upstreams are not stable ground: that source's v1 API was withdrawn before the
source itself was removed, and ClearlyDefined has changed owners. Turning a
feed off should be configuration.
"""

import datetime

import pytest

from vulnq.core import NoSourcesConfiguredError, VulnerabilityQuery
from vulnq.models import Configuration, IdentifierType, VulnerabilitySource
from vulnq.sources import (
    BY_SOURCE,
    DEFAULT_SOURCES,
    MERGE_PRIORITY,
    REGISTRY,
    SELECTABLE_SOURCES,
    parse_disabled,
)


def test_every_enum_member_is_declared_exactly_once():
    """The registry is the list, so nothing may exist outside it."""
    assert [spec.source for spec in REGISTRY] == list(VulnerabilitySource)
    assert len({spec.source for spec in REGISTRY}) == len(REGISTRY)


def test_every_declared_source_builds_a_client():
    """A member landing without a client is the failure this guards."""
    for spec in REGISTRY:
        engine = VulnerabilityQuery(config=Configuration(sources=[spec.source]))
        assert spec.source in engine._clients
        assert engine._clients[spec.source].source is spec.source


def test_merge_priorities_are_distinct():
    """Two sources sharing a priority makes the winner depend on list order."""
    priorities = list(MERGE_PRIORITY.values())
    assert len(set(priorities)) == len(priorities)


def test_the_default_fanout_is_the_official_sources():
    """Every source that ships is queried unasked; there is no opt-in one."""
    assert set(DEFAULT_SOURCES) == {
        VulnerabilitySource.OSV,
        VulnerabilitySource.GITHUB,
        VulnerabilitySource.NVD,
    }
    assert set(SELECTABLE_SOURCES) == set(DEFAULT_SOURCES)


def test_the_default_configuration_queries_the_default_fanout():
    engine = VulnerabilityQuery(config=Configuration())
    assert set(engine._clients) == set(DEFAULT_SOURCES)


class TestNoSourceReplacesTheFanOut:
    """One source used to replace every other. That special case is gone."""

    def test_any_combination_can_be_expressed(self):
        engine = VulnerabilityQuery(
            config=Configuration(sources=[VulnerabilitySource.OSV, VulnerabilitySource.NVD])
        )
        assert set(engine._clients) == {
            VulnerabilitySource.OSV,
            VulnerabilitySource.NVD,
        }

    def test_selecting_one_queries_only_it(self):
        engine = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.NVD]))
        assert set(engine._clients) == {VulnerabilitySource.NVD}

    def test_there_is_no_separate_query_path_left(self):
        """It had its own, which duplicated the fan-out logic and drifted."""
        assert not hasattr(VulnerabilityQuery, "_query_vulnerablecode")

    def test_the_replaces_everything_switch_is_gone(self):
        assert not hasattr(Configuration(), "use_vulnerablecode")


class TestDisablingASource:
    """Switched off is a reason a source was not checked, not silence."""

    def test_a_disabled_source_builds_no_client(self):
        engine = VulnerabilityQuery(
            config=Configuration(disabled_sources=[VulnerabilitySource.GITHUB])
        )
        assert VulnerabilitySource.GITHUB not in engine._clients
        assert set(engine._clients) == {VulnerabilitySource.OSV, VulnerabilitySource.NVD}

    def test_a_disabled_source_is_reported_in_the_envelope(self, monkeypatch):
        """Left out, a query with everything but one source off would read as
        a complete answer from that one."""
        engine = VulnerabilityQuery(
            config=Configuration(
                sources=[VulnerabilitySource.OSV, VulnerabilitySource.GITHUB],
                disabled_sources=[VulnerabilitySource.GITHUB],
            )
        )
        client = engine._clients[VulnerabilitySource.OSV]

        async def no_session():
            return None

        async def nothing(purl):
            return []

        monkeypatch.setattr(client, "start_session", no_session)
        monkeypatch.setattr(client, "close_session", no_session)
        monkeypatch.setattr(client, "query_purl", nothing)

        result = engine.query("pkg:npm/left-pad@1.3.0")
        assert "github" in result.sources_skipped
        assert "disabled" in result.sources_skipped["github"].lower()
        assert VulnerabilitySource.GITHUB not in result.sources_checked

    def test_disabling_beats_selecting(self):
        """An operator switching a feed off outranks a caller asking for it."""
        with pytest.raises(NoSourcesConfiguredError):
            VulnerabilityQuery(
                config=Configuration(
                    sources=[VulnerabilitySource.OSV],
                    disabled_sources=[VulnerabilitySource.OSV],
                )
            )

    def test_disabling_everything_is_an_error_not_a_clean_scan(self):
        with pytest.raises(NoSourcesConfiguredError) as excinfo:
            VulnerabilityQuery(config=Configuration(disabled_sources=list(DEFAULT_SOURCES)))
        message = str(excinfo.value)
        assert "Disabled by configuration" in message
        for source in DEFAULT_SOURCES:
            assert source.value in message


class TestParsingTheDisableList:
    """It is set by whoever runs vulnq, often in an image or a job."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("osv,github", ["osv", "github"]),
            (" osv , GITHUB ", ["osv", "github"]),
            ("OSV", ["osv"]),
            ("", []),
            (None, []),
            (",,", []),
        ],
    )
    def test_it_reads_what_an_operator_would_write(self, raw, expected):
        assert [s.value for s in parse_disabled(raw)] == expected

    def test_an_unknown_name_is_refused(self):
        """Ignoring it is worse than failing: whoever wrote "gitub" believes
        GitHub is switched off, and it would be quietly queried instead."""
        from vulnq.sources import UnknownSourceError

        with pytest.raises(UnknownSourceError, match="gitub"):
            parse_disabled("gitub")
        with pytest.raises(UnknownSourceError, match="Valid sources"):
            parse_disabled("osv,retired-source")

    def test_the_environment_variable_reaches_the_configuration(self, monkeypatch):
        monkeypatch.setenv("VULNQ_DISABLED_SOURCES", "github,nvd")
        config = VulnerabilityQuery.load_config()
        assert set(config.disabled_sources) == {
            VulnerabilitySource.GITHUB,
            VulnerabilitySource.NVD,
        }


def test_adding_a_source_needs_one_registry_entry():
    """The point of the exercise, asserted structurally.

    core.py used to name each source in an if-block, a fan-out tuple and a
    merge table. If any of those come back, this fails.
    """
    import pathlib

    core = (pathlib.Path(__file__).parent.parent / "vulnq" / "core.py").read_text()
    for name in ("OSVClient(", "GitHubClient(", "NVDClient("):
        assert name not in core, f"core.py builds {name} directly again"
    assert "FANOUT_SOURCES" not in core
    assert "source_priority" not in core


class TestTheCommandLineSurface:
    """Run as a real process: a shadowed import crashed the alias while 417
    in-process tests stayed green, because none of them entered main()."""

    @staticmethod
    def _run(args):
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "vulnq.cli", *args],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_the_removed_alias_flag_fails_rather_than_being_ignored(self):
        """A flag that selected a deleted source cannot quietly do nothing.

        The env var is forgiven because os.environ.get would skip it in
        silence. A flag has no such problem: click refuses an option it does
        not have, so the script that passes it stops rather than querying
        something its author did not choose.
        """
        proc = self._run(["pkg:npm/left-pad@1.3.0", "--use-vulnerablecode", "-f", "json"])

        assert proc.returncode == 2
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "--use-vulnerablecode" in proc.stderr
        assert proc.stdout == ""

    def test_the_environment_variable_that_selected_a_removed_source_is_survivable(self):
        """A job with USE_VULNERABLECODE=true baked in must still run, still
        produce a document on stdout, and query the default fan-out."""
        import json
        import os
        import subprocess
        import sys

        env = {**os.environ, "USE_VULNERABLECODE": "true"}
        proc = subprocess.run(
            [sys.executable, "-m", "vulnq.cli", "pkg:npm/left-pad@1.3.0", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "removed in 2.0" in proc.stderr
        payload = json.loads(proc.stdout)
        reported = set(payload["sources_checked"]) | set(payload["sources_skipped"])
        reported |= {e.split(":")[0] for e in payload["errors"]}
        assert "vulnerablecode" not in reported
        assert "osv" in reported

    def test_disabling_a_source_from_the_command_line_runs(self):
        proc = self._run(
            [
                "pkg:npm/left-pad@1.3.0",
                "--sources",
                "osv",
                "--disable-source",
                "github",
                "-f",
                "json",
            ]
        )
        assert "Traceback" not in proc.stderr, proc.stderr
        import json

        assert "github" not in json.loads(proc.stdout)["sources_checked"]

    def test_disabling_every_selected_source_fails_loudly(self):
        proc = self._run(["pkg:npm/left-pad@1.3.0", "--sources", "osv", "--disable-source", "osv"])
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.returncode != 0
        assert "Disabled by configuration" in proc.stdout

    def test_the_environment_variable_runs_too(self):
        import json
        import os
        import subprocess
        import sys

        env = {**os.environ, "VULNQ_DISABLED_SOURCES": "github,nvd"}
        proc = subprocess.run(
            [sys.executable, "-m", "vulnq.cli", "pkg:npm/left-pad@1.3.0", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        assert "Traceback" not in proc.stderr, proc.stderr
        payload = json.loads(proc.stdout)
        assert set(payload["sources_skipped"]) >= {"github", "nvd"}


def test_unknown_configuration_keys_are_refused():
    """pydantic drops them by default, so a removed field or a typo would be
    accepted in silence and the caller would get defaults they did not ask for.
    """
    import pytest as _pytest

    from vulnq.models import Configuration

    with _pytest.raises(Exception):
        Configuration(use_vulnerablecode=True)
    with _pytest.raises(Exception):
        Configuration(tiemout=30)


def test_the_configuration_default_follows_the_registry():
    """Otherwise a new default-fanout source needs a third edit."""
    from vulnq.models import Configuration

    assert Configuration().sources == list(DEFAULT_SOURCES)


def test_merging_two_records_never_lowers_a_severity():
    """Two records for one advisory with no score to derive from simply
    disagree. Taking the first meant a HIGH could vanish into a LOW and then be
    removed by a severity filter."""
    from vulnq.core import VulnerabilityQuery
    from vulnq.models import Configuration, Severity, Vulnerability, VulnerabilitySource

    def record(vid, severity):
        return Vulnerability(
            id=vid,
            source=VulnerabilitySource.OSV,
            summary="x",
            severity=severity,
            aliases=["CVE-2021-1"],
        )

    engine = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))
    merged = engine._deduplicate_vulnerabilities(
        [record("OSV-1", Severity.LOW), record("OSV-2", Severity.HIGH)]
    )
    assert len(merged) == 1
    assert merged[0].severity is Severity.HIGH


def test_no_source_spec_declares_something_nothing_reads():
    """credential_hint was declared, documented and read by nobody."""
    import dataclasses

    from vulnq.sources import SourceSpec

    declared = {f.name for f in dataclasses.fields(SourceSpec)}
    assert declared == {
        "source",
        "build",
        "in_default_fanout",
        "merge_priority",
        # Read by deprecation_warning, which every path that selects a source
        # goes through. Both are needed: a warning that names no replacement
        # release is not actionable, and one that names no alternative tells
        # the reader to stop without saying what to do instead.
        "removed_in",
        "deprecation_note",
    }


def test_a_typo_in_disable_source_is_a_usage_error_not_a_silent_query():
    """Run as a real process: the whole point is that GitHub is not queried."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "vulnq.cli", "pkg:npm/left-pad@1.3.0", "--disable-source", "gitub"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 2
    assert "gitub" in proc.stdout
    assert "api.github.com" not in proc.stdout + proc.stderr
