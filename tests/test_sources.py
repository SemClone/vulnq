"""Tests for source configuration and the failure paths around it."""

import pytest
from click.testing import CliRunner

from vulnq import NoSourcesConfiguredError, VulnerabilitySource
from vulnq.cli import main
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, IdentifierType, QueryResult
from vulnq.sources import SELECTABLE_SOURCES


class TestSourceEnum:
    """Every nameable source must have a client behind it."""

    def test_only_implemented_sources_are_nameable(self):
        """A source with no client must not exist to be requested."""
        assert {source.value for source in VulnerabilitySource} == {
            "osv",
            "github",
            "nvd",
            "vulnerablecode",
        }

    @pytest.mark.parametrize("removed", ["snyk", "sonatype"])
    def test_removed_stubs_fail_loudly(self, removed):
        """Naming a removed stub fails at construction, not silently at runtime."""
        with pytest.raises(ValueError):
            VulnerabilitySource(removed)

    def test_every_source_initializes_a_client(self):
        """Guards against a future member landing without a client."""
        for source in VulnerabilitySource:
            engine = VulnerabilityQuery(config=Configuration(sources=[source]))
            assert source in engine._clients


class TestNoSourcesConfigured:
    """An empty client set must never look like a clean bill of health."""

    def test_empty_source_list_raises(self):
        """Zero sources is a configuration error, not a package with no CVEs."""
        with pytest.raises(NoSourcesConfiguredError) as excinfo:
            VulnerabilityQuery(config=Configuration(sources=[]))

        assert "No queryable vulnerability sources" in str(excinfo.value)

    def test_error_names_what_was_requested_and_what_is_selectable(self):
        """The message has to be actionable without reading the source."""
        with pytest.raises(NoSourcesConfiguredError) as excinfo:
            VulnerabilityQuery(config=Configuration(sources=[]))

        message = str(excinfo.value)
        assert "requested: none" in message
        for source in SELECTABLE_SOURCES:
            assert source.value in message

    def test_vulnerablecode_is_selectable_like_any_other_source(self):
        """It used to replace the fan-out, so naming it here built nothing.

        Selecting it now builds its client, and it can be combined with the
        others rather than displacing them.
        """
        engine = VulnerabilityQuery(
            config=Configuration(sources=[VulnerabilitySource.VULNERABLECODE])
        )
        assert VulnerabilitySource.VULNERABLECODE in engine._clients

        both = VulnerabilityQuery(
            config=Configuration(
                sources=[VulnerabilitySource.OSV, VulnerabilitySource.VULNERABLECODE]
            )
        )
        assert set(both._clients) == {
            VulnerabilitySource.OSV,
            VulnerabilitySource.VULNERABLECODE,
        }

    def test_every_source_disabled_is_a_configuration_error(self):
        """Disabling everything must not read as a package with no findings."""
        with pytest.raises(NoSourcesConfiguredError) as excinfo:
            VulnerabilityQuery(
                config=Configuration(
                    sources=[VulnerabilitySource.OSV],
                    disabled_sources=[VulnerabilitySource.OSV],
                )
            )
        assert "Disabled by configuration: osv" in str(excinfo.value)

    def test_error_is_catchable_as_runtime_error(self):
        """Consumers catching RuntimeError keep working."""
        assert issubclass(NoSourcesConfiguredError, RuntimeError)

    def test_valid_configuration_still_builds(self):
        """The guard must not fire on an ordinary configuration."""
        engine = VulnerabilityQuery(config=Configuration())
        assert engine._clients


class TestUnsupportedIdentifier:
    """An identifier no client can answer must not return a silent empty."""

    def test_multi_source_path_reports_unsupported_identifier(self, monkeypatch):
        """A hash query reaches no client, so it must not look like a clean result."""
        engine = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))

        async def no_session(self):
            return None

        monkeypatch.setattr("vulnq.clients.osv.OSVClient.start_session", no_session, raising=False)
        monkeypatch.setattr("vulnq.clients.osv.OSVClient.close_session", no_session, raising=False)

        result = engine.query("sha256:" + "a" * 64)

        assert result.vulnerabilities == []
        assert result.sources_checked == []
        assert any("no lookup was performed" in error for error in result.errors)

    def test_vulnerablecode_path_reports_unsupported_identifier(self, monkeypatch):
        """The VulnerableCode path claimed the source was checked when it was not."""
        engine = VulnerabilityQuery(
            config=Configuration(sources=[VulnerabilitySource.VULNERABLECODE])
        )

        async def no_session(self):
            return None

        monkeypatch.setattr(
            "vulnq.clients.vulnerablecode.VulnerableCodeClient.start_session",
            no_session,
            raising=False,
        )
        monkeypatch.setattr(
            "vulnq.clients.vulnerablecode.VulnerableCodeClient.close_session",
            no_session,
            raising=False,
        )

        result = engine.query("sha256:" + "a" * 64)

        assert result.query_type == IdentifierType.SHA256
        assert result.sources_checked == []
        assert any("no lookup was performed" in error for error in result.errors)

    def test_supported_identifier_records_the_source(self, monkeypatch):
        """The honest path still reports what actually ran."""
        engine = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))

        async def fake_sources(identifier, id_type, package_info, result):
            result.sources_checked.append(VulnerabilitySource.OSV)
            return []

        monkeypatch.setattr(engine, "_query_all_sources", fake_sources)
        result = engine.query("pkg:npm/express@4.17.1")

        assert isinstance(result, QueryResult)
        assert result.sources_checked == [VulnerabilitySource.OSV]
        assert result.errors == []


class TestCLISourceHandling:
    """The CLI must not turn a source choice into a silent no-op."""

    def test_unknown_source_names_the_offender(self):
        """With several --sources flags the user should not have to guess."""
        result = CliRunner().invoke(
            main, ["pkg:npm/express@4.17.1", "--sources", "osv", "--sources", "bogus"]
        )

        assert result.exit_code == 2
        assert "bogus" in result.output

    def test_vulnerablecode_source_selects_vulnerablecode(self, monkeypatch):
        """Naming it must select it, not resolve to zero sources."""
        captured = {}

        def fake_init(self, config=None, verbose=False):
            captured["config"] = config
            raise SystemExit(0)

        monkeypatch.setattr("vulnq.cli.VulnerabilityQuery.__init__", fake_init)
        CliRunner().invoke(main, ["pkg:npm/express@4.17.1", "--sources", "vulnerablecode"])

        assert captured["config"].sources == [VulnerabilitySource.VULNERABLECODE]

    def test_vulnerablecode_can_now_be_combined_with_the_others(self, monkeypatch):
        """It used to replace them: naming both left only the fan-out ones.

        As an ordinary source it joins them, which is a combination the tool
        could not express before.
        """
        captured = {}

        def fake_init(self, config=None, verbose=False):
            captured["config"] = config
            raise SystemExit(0)

        monkeypatch.setattr("vulnq.cli.VulnerabilityQuery.__init__", fake_init)
        CliRunner().invoke(
            main,
            ["pkg:npm/express@4.17.1", "--sources", "osv", "--sources", "vulnerablecode"],
        )

        assert captured["config"].sources == [
            VulnerabilitySource.OSV,
            VulnerabilitySource.VULNERABLECODE,
        ]
