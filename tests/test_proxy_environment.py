"""A host whose only way out is a CONNECT proxy has to work.

aiohttp reads HTTPS_PROXY/HTTP_PROXY from the environment only when the
session is built with trust_env=True. Without it every source failed on a
worker with no direct route, and the proxy log showed no connection attempt
at all - the request never left the process.
"""

import ast
import asyncio
import pathlib
from typing import List, Tuple

import aiohttp
import pytest

from vulnq.clients.osv import OSVClient

PROXY_ENV_VARS = (
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "ALL_PROXY",
    "all_proxy",
)


class RecordingProxy:
    """A one-shot HTTP proxy that records the request line it is handed."""

    def __init__(self):
        self.request_lines: List[str] = []
        self._server = None

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self._server.close()
        await self._server.wait_closed()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def _handle(self, reader, writer):
        request_line = await reader.readline()
        self.request_lines.append(request_line.decode().strip())
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        body = b'{"vulns": []}'
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
        writer.close()


@pytest.mark.asyncio
async def test_a_request_goes_through_the_proxy_the_environment_names(monkeypatch):
    """HTTP_PROXY has to carry the request, not be ignored.

    The target host does not resolve, so a session that ignores the
    environment cannot reach it at all: the proxy receiving the absolute-form
    request line is the only way this passes.
    """
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    async with RecordingProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", proxy.url)
        monkeypatch.setenv("http_proxy", proxy.url)

        client = OSVClient(max_retries=1, timeout=10)
        try:
            payload = await client._make_request("GET", "http://vulnq-proxy-probe.invalid/v1/query")
        finally:
            await client.close_session()

    assert payload == {"vulns": []}
    assert proxy.request_lines == ["GET http://vulnq-proxy-probe.invalid/v1/query HTTP/1.1"]


@pytest.mark.asyncio
async def test_no_proxy_still_excludes_a_host(monkeypatch):
    """NO_PROXY has to be honoured, or trust_env would break direct hosts."""
    for var in PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    async with RecordingProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", proxy.url)
        monkeypatch.setenv("http_proxy", proxy.url)
        monkeypatch.setenv("NO_PROXY", "vulnq-proxy-probe.invalid")
        monkeypatch.setenv("no_proxy", "vulnq-proxy-probe.invalid")

        client = OSVClient(max_retries=1, timeout=10)
        try:
            with pytest.raises(aiohttp.ClientConnectorError):
                await client._make_request("GET", "http://vulnq-proxy-probe.invalid/v1/query")
        finally:
            await client.close_session()

    assert proxy.request_lines == []


def _client_session_calls() -> List[Tuple[pathlib.Path, ast.Call]]:
    """Every aiohttp.ClientSession construction in the package.

    Derived from the source tree rather than from a list kept by hand, so a
    session added later is covered whatever file it lands in.
    """
    package = pathlib.Path(__file__).parent.parent / "vulnq"
    calls = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id if isinstance(func, ast.Name) else None
            )
            if name == "ClientSession":
                calls.append((path, node))
    return calls


def test_every_session_in_the_package_trusts_the_environment():
    """The flag is a property of every session, not of the one we patched."""
    calls = _client_session_calls()
    assert calls, "no aiohttp.ClientSession construction found - the sweep is blind"

    offenders = []
    for path, call in calls:
        trusted = any(
            kw.arg == "trust_env" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call.keywords
        )
        unparsable = any(kw.arg is None for kw in call.keywords)
        if not trusted or unparsable:
            offenders.append(f"{path.name}:{call.lineno}")

    assert not offenders, f"ClientSession without trust_env=True: {offenders}"
