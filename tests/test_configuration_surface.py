"""Every knob vulnq advertises has to do something.

A flag or field that is accepted and then ignored is the same defect as a
source that reports itself checked without being queried: the tool claims a
behaviour it does not have, and nothing in the output says otherwise.
"""

import os
import pathlib

import pytest
from click.testing import CliRunner

from vulnq.cli import main
from vulnq.clients.osv import OSVClient
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration


def test_no_cache_surface_remains():
    """Caching was configurable and never implemented, so the surface is gone."""
    assert not hasattr(Configuration(), "cache_enabled")
    assert not hasattr(Configuration(), "cache_dir")
    assert not hasattr(Configuration(), "cache_ttl")

    result = CliRunner().invoke(main, ["--help"])
    assert "--no-cache" not in result.output

    root = pathlib.Path(__file__).parent.parent
    assert "diskcache" not in (root / "pyproject.toml").read_text()
    assert "VULNQ_CACHE" not in (root / "README.md").read_text()


def test_max_concurrent_reaches_the_semaphore():
    """The knob the README documents has to bind the semaphore that limits us."""
    client = OSVClient(max_concurrent=3)
    assert client._concurrency_guard()._value == 3


def test_max_concurrent_defaults_to_five():
    """Unchanged from the value that was hardcoded before it was configurable."""
    assert OSVClient()._concurrency_guard()._value == 5


def test_zero_concurrency_is_refused_rather_than_hanging():
    """Semaphore(0) blocks forever, so this has to fail at construction."""
    with pytest.raises(ValueError, match="at least 1"):
        OSVClient(max_concurrent=0)


def test_config_max_concurrent_reaches_every_client():
    """Threading it through core is what makes the config field real."""
    query = VulnerabilityQuery(config=Configuration(max_concurrent=2))
    assert query._clients
    for client in query._clients.values():
        assert client.max_concurrent == 2


def test_env_var_documented_in_the_readme_is_read(monkeypatch):
    monkeypatch.setenv("VULNQ_MAX_CONCURRENT", "7")
    assert VulnerabilityQuery.load_config().max_concurrent == 7


def test_unparseable_env_var_fails_loudly(monkeypatch):
    """Falling back to the default would silently ignore what the caller set."""
    monkeypatch.setenv("VULNQ_MAX_CONCURRENT", "lots")
    with pytest.raises(ValueError, match="VULNQ_MAX_CONCURRENT"):
        VulnerabilityQuery.load_config()


def test_env_var_unset_leaves_the_default(monkeypatch):
    monkeypatch.delenv("VULNQ_MAX_CONCURRENT", raising=False)
    assert VulnerabilityQuery.load_config().max_concurrent == 5
