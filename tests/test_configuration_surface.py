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


def test_version_lists_are_ordered_not_hash_ordered():
    """list(set(...)) made the envelope different on every run.

    Python randomizes string hashing per process, so two scans of one package
    could not be diffed without phantom changes, and nothing downstream could
    checksum the output. Asserted at the source, because the ordering is only
    visible across processes.
    """
    import pathlib

    clients = pathlib.Path(__file__).parent.parent / "vulnq" / "clients"
    offenders = []
    for path in sorted(clients.glob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            # Comments may name the pattern while explaining why it is gone.
            if "list(set(" in line.split("#", 1)[0]:
                offenders.append(f"{path.name}:{number}")
    assert offenders == []


def test_the_removed_helpers_stay_removed():
    """Each had no caller. Re-adding one without a caller re-adds the problem."""
    import vulnq.utils as utils
    from vulnq.clients.base import BaseClient
    from vulnq.core import VulnerabilityQuery

    for name in ("normalize_version", "severity_to_score", "score_to_severity"):
        assert not hasattr(utils, name), name
    assert not hasattr(BaseClient, "generate_vuln_id")
    assert not hasattr(VulnerabilityQuery, "query_hash")


def test_the_shared_helpers_are_shared():
    """_queried_version and _parse_timestamp were copied per client.

    The timestamp one lived in six places across three clients, each in a bare
    try/except, so a fix to one left the others as they were.
    """
    import pathlib

    from vulnq.clients.base import BaseClient

    assert hasattr(BaseClient, "_queried_version")
    assert hasattr(BaseClient, "_parse_timestamp")

    clients = pathlib.Path(__file__).parent.parent / "vulnq" / "clients"
    for path in sorted(clients.glob("*.py")):
        if path.name == "base.py":
            continue
        assert "fromisoformat" not in path.read_text(), path.name


def test_query_result_no_longer_advertises_an_empty_metadata_field():
    """It was never populated, and the README showed it filled in."""
    import datetime

    from vulnq.models import IdentifierType, QueryResult

    result = QueryResult(
        query="q", query_type=IdentifierType.PURL, query_time=datetime.datetime.now()
    )
    assert "metadata" not in result.model_dump(mode="json")


def test_a_swid_tag_is_named_rather_than_read_as_a_purl():
    """Detecting SWID looks like dead code and is not.

    No source is keyed by SWID, so the branch only ever reaches an error. But
    deleting it does not delete the identifier from the world: a real SWID tag
    then falls through to the PURL default and is reported as query_type
    "purl" with an empty errors list, which says nothing went wrong. Naming
    what cannot be answered is the point.
    """
    import datetime

    from vulnq.models import Configuration, IdentifierType, VulnerabilitySource
    from vulnq.utils import detect_identifier_type

    assert detect_identifier_type("swid:example.com-myapp-1.0") is IdentifierType.SWID

    from vulnq.core import VulnerabilityQuery

    query = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.NVD]))
    result = query.query("swid:example.com-myapp-1.0")
    assert result.query_type is IdentifierType.SWID
    assert result.errors, "an identifier nobody can answer must say so"
    assert result.is_conclusive is False
    assert isinstance(result.query_time, datetime.datetime)
