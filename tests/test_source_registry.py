"""A source is declared once, and can be switched off without a code change.

A source used to be named in seven files. VulnerableCode accounted for fifteen
of those sites on its own, because it replaced the fan-out instead of joining
it, and that special case is how three bugs lived unnoticed in its client.

Upstreams are not stable ground: VulnerableCode's v1 API was withdrawn, and
ClearlyDefined has changed owners. Turning a feed off should be configuration.
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
    """VulnerableCode aggregates the others, so it is not queried unasked."""
    assert set(DEFAULT_SOURCES) == {
        VulnerabilitySource.OSV,
        VulnerabilitySource.GITHUB,
        VulnerabilitySource.NVD,
    }
    assert VulnerabilitySource.VULNERABLECODE in SELECTABLE_SOURCES
    assert VulnerabilitySource.VULNERABLECODE not in DEFAULT_SOURCES


def test_the_default_configuration_queries_the_default_fanout():
    engine = VulnerabilityQuery(config=Configuration())
    assert set(engine._clients) == set(DEFAULT_SOURCES)


class TestVulnerableCodeIsOrdinaryNow:
    """It replaced every other source. That special case is gone."""

    def test_it_can_be_combined_with_the_others(self):
        """A combination the tool could not express before."""
        engine = VulnerabilityQuery(
            config=Configuration(
                sources=[VulnerabilitySource.OSV, VulnerabilitySource.VULNERABLECODE]
            )
        )
        assert set(engine._clients) == {
            VulnerabilitySource.OSV,
            VulnerabilitySource.VULNERABLECODE,
        }

    def test_selecting_it_alone_queries_only_it(self):
        engine = VulnerabilityQuery(
            config=Configuration(sources=[VulnerabilitySource.VULNERABLECODE])
        )
        assert set(engine._clients) == {VulnerabilitySource.VULNERABLECODE}

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
            ("vulnerablecode", ["vulnerablecode"]),
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

    def test_an_unknown_name_is_ignored_rather_than_fatal(self):
        """A name outliving the source it referred to must not break every
        query for whoever inherited that job definition."""
        assert [s.value for s in parse_disabled("osv,retired-source")] == ["osv"]

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
    for name in ("OSVClient(", "GitHubClient(", "NVDClient(", "VulnerableCodeClient("):
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

    def test_the_use_vulnerablecode_alias_still_runs(self):
        """Anyone with a token and a script depends on this flag."""
        proc = self._run(["pkg:npm/left-pad@1.3.0", "--use-vulnerablecode", "-f", "json"])
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.stdout.strip().startswith("{")

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
