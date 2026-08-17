"""Tests for constructing and reusing clients around event loops.

Before Python 3.10, asyncio.Semaphore binds to the current event loop when it
is constructed. Building one in a client's __init__ meant a caller who had
already used asyncio.run() - any async application - could not construct a
client at all, and a client reused across loops held a semaphore bound to a
closed one. CI only runs 3.13, where the binding is gone, so nothing caught it.
"""

import asyncio

from vulnq.clients import GitHubClient, NVDClient, OSVClient, VulnerableCodeClient
from vulnq.core import VulnerabilityQuery
from vulnq.models import Configuration, VulnerabilitySource


def test_clients_construct_with_no_current_event_loop():
    """asyncio.run() clears the current loop on the way out."""

    async def nothing():
        return None

    asyncio.run(nothing())

    for client_class in (OSVClient, GitHubClient, NVDClient, VulnerableCodeClient):
        client_class()


def test_engine_constructs_after_asyncio_run():
    """The shape a consumer hits: async app first, vulnq second."""

    async def nothing():
        return None

    asyncio.run(nothing())
    VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))


def test_a_reused_client_survives_a_new_loop(monkeypatch):
    """The engine builds a fresh loop per query but keeps its clients."""

    async def no_session(self):
        return None

    async def clean(self, method, url, **kwargs):
        return {"vulns": [{"id": "OSV-1", "summary": "real"}]}

    monkeypatch.setattr("vulnq.clients.base.BaseClient.start_session", no_session)
    monkeypatch.setattr("vulnq.clients.base.BaseClient.close_session", no_session)
    monkeypatch.setattr("vulnq.clients.base.BaseClient._make_request", clean)

    engine = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))
    first = engine.query("pkg:npm/express@4.17.1")
    second = engine.query("pkg:npm/express@4.17.1")

    assert first.is_conclusive and second.is_conclusive
    assert len(second.vulnerabilities) == 1
