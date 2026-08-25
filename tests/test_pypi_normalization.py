"""PEP 503 is an identity rule here, not a transport one.

PyPI treats several spellings as one distribution, so what vulnq *reports* is
the canonical name. What it *asks a source* is the spelling it was given,
because GitHub keys GHSA by the as-published name and folds case but not dots.
Normalizing before the query trades duplicate identity for dropped findings.
"""

import pytest

from vulnq.models import IdentifierType
from vulnq.utils import normalize_pypi_name, parse_purl


@pytest.mark.parametrize(
    "name",
    ["zope.interface", "zope_interface", "Zope-Interface", "ZOPE..INTERFACE", "zope--interface"],
)
def test_pypi_spellings_collapse_to_one_purl(name):
    """Every legal spelling of one distribution yields one canonical purl."""
    info = parse_purl(f"pkg:pypi/{name}@5.4.0")
    assert info.name == "zope-interface"
    assert info.purl == "pkg:pypi/zope-interface@5.4.0"


def test_normalize_matches_the_pep_503_rule():
    """The helper is the rule from PEP 503, not an approximation of it."""
    import re

    for raw in ["zope.interface", "Foo_Bar", "a.-_b", "Requests", "already-normal"]:
        assert normalize_pypi_name(raw) == re.sub(r"[-_.]+", "-", raw).lower()


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:npm/ua-parser-js@0.7.29",
        "pkg:npm/%40babel/traverse@7.23.2",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "pkg:golang/gopkg.in/yaml.v2@2.2.8",
        "pkg:gem/actionpack@6.0.0",
    ],
)
def test_other_ecosystems_keep_their_dots(purl):
    """PEP 503 is a PyPI rule. Maven and Go names are dot-separated and stay."""
    assert parse_purl(purl).purl == purl


def test_version_and_ecosystem_survive_normalization():
    info = parse_purl("pkg:pypi/zope.interface@5.4.0")
    assert info.ecosystem == "pypi"
    assert info.version == "5.4.0"


def test_unparseable_purl_still_returns_none():
    assert parse_purl("not a purl at all") is None


def test_canonical_purl_is_idempotent_and_total():
    """Callers normalize without first checking, so it must never raise."""
    from vulnq.utils import canonical_purl

    once = canonical_purl("pkg:pypi/zope.interface@5.4.0")
    assert once == "pkg:pypi/zope-interface@5.4.0"
    assert canonical_purl(once) == once
    # Junk comes back untouched rather than raising or becoming None.
    for junk in ["", "not a purl", "pkg:pypi", "pkg:pypi/", "express"]:
        assert canonical_purl(junk) == junk


def test_canonical_purl_keeps_qualifiers_and_subpath():
    from vulnq.utils import canonical_purl

    assert (
        canonical_purl("pkg:pypi/foo.bar?repository_url=https://example.com/simple")
        == "pkg:pypi/foo-bar?repository_url=https://example.com/simple"
    )
    assert canonical_purl("pkg:pypi/foo.bar#sub/path") == "pkg:pypi/foo-bar#sub/path"


@pytest.mark.parametrize(
    "spelling",
    [
        "pkg:pypi/zope.interface@5.4.0",
        "pkg:pypi/zope_interface@5.4.0",
        "pkg:pypi/Zope-Interface@5.4.0",
        "pkg:pypi/zope-interface@5.4.0",
    ],
)
def test_canonical_purl_folds_every_spelling(spelling):
    """Assert on canonical_purl itself.

    Going through a client's own parser would hide a failure here, because
    packageurl folds case and underscores again on the way in.
    """
    from vulnq.utils import canonical_purl

    assert canonical_purl(spelling) == "pkg:pypi/zope-interface@5.4.0"


def test_github_is_asked_the_name_as_published(monkeypatch):
    """GHSA is keyed by the as-published PyPI name and does not fold dots.

    Verified live: package "products.pluggableauthservice" holds three
    advisories and "products-pluggableauthservice" holds none. Folding the dot
    before the query turns three real findings into a clean scan with github
    still in sources_checked, which is worse than the duplicate identity this
    module set out to fix.

    Asserted at the GraphQL variable, not through the client's own parser.
    _parse_purl runs after any normalization at the top of query_purl, so
    calling it directly would let that exact defect back in unnoticed.
    """
    from tests.test_package_names import sent_package

    ecosystem, package = sent_package(monkeypatch, "pkg:pypi/products.pluggableauthservice@2.5")
    assert (ecosystem, package) == ("PIP", "products.pluggableauthservice")


def test_no_client_normalizes_before_querying(monkeypatch):
    """No client may apply the PEP 503 rule before querying.

    Covers all four clients where a behavioural test cannot: NVD's purl-to-CPE
    table has no pypi row carrying a foldable separator, so the mutation is
    unobservable there, and VulnerableCode's public API refuses
    unauthenticated queries, which is how vulnq calls it.
    A client reaching for canonical_purl is making the transport carry an
    identity rule, which is the defect whether or not a test can observe it.

    Narrow on purpose: this greps for one name. It says nothing about
    normalization arriving by another route, which is what
    test_underscores_are_folded_only_on_the_github_path covers.
    """
    import pathlib

    clients = pathlib.Path(__file__).parent.parent / "vulnq" / "clients"
    offenders = [
        path.name for path in sorted(clients.glob("*.py")) if "canonical_purl" in path.read_text()
    ]
    assert offenders == []


def test_osv_is_asked_the_purl_as_given():
    """Same rule at the transport: send what the caller asked about."""
    import asyncio

    from vulnq.clients.osv import OSVClient

    sent = []
    client = OSVClient()

    async def _capture(method, url, **kwargs):
        sent.append(kwargs["json"]["package"]["purl"])
        return {"vulns": []}

    client._make_request = _capture
    asyncio.run(client.query_purl("pkg:pypi/plone.namedfile@6.0.0"))

    assert sent == ["pkg:pypi/plone.namedfile@6.0.0"]


def test_core_reports_the_canonical_name_but_queries_the_given_one():
    """The two halves of the rule, together.

    package_info is identity, so it is canonical. The query that goes out is
    the caller's spelling, so a source that matches exactly still matches.
    """
    from vulnq.core import VulnerabilityQuery
    from vulnq.models import Configuration, VulnerabilitySource

    asked = []
    query = VulnerabilityQuery(config=Configuration(sources=[VulnerabilitySource.OSV]))

    for client in query._clients.values():

        async def _noop():
            return None

        async def _capture(purl, _asked=asked):
            _asked.append(purl)
            return []

        client.start_session = _noop
        client.close_session = _noop
        client.query_purl = _capture

    result = query.query("pkg:pypi/plone.namedfile@6.0.0")

    assert asked == ["pkg:pypi/plone.namedfile@6.0.0"]
    assert result.package_info.purl == "pkg:pypi/plone-namedfile@6.0.0"
    assert result.query == "pkg:pypi/plone.namedfile@6.0.0"


def test_underscores_are_folded_only_on_the_github_path():
    """Underscores are handled inconsistently, and this branch does not change it.

    The GitHub client builds its package name from PackageURL.name, which
    packageurl has already folded, so GitHub is asked about scikit-learn. OSV
    and VulnerableCode pass the purl string straight through, so they do see
    the underscore. That asymmetry is identical on main.

    Left alone deliberately: for GitHub the fold is what GHSA wants anyway.
    scikit-learn is the PyPI project name, scikit_learn only a wheel filename
    spelling, and GHSA holds three advisories under the hyphenated name and
    none under the underscored one.
    """
    import asyncio

    from vulnq.clients.github import GitHubClient
    from vulnq.clients.osv import OSVClient

    assert GitHubClient()._parse_purl("pkg:pypi/scikit_learn@1.0")[1] == "scikit-learn"

    sent = []
    client = OSVClient()

    async def _capture(method, url, **kwargs):
        sent.append(kwargs["json"]["package"]["purl"])
        return {"vulns": []}

    client._make_request = _capture
    asyncio.run(client.query_purl("pkg:pypi/scikit_learn@1.0"))
    assert sent == ["pkg:pypi/scikit_learn@1.0"]

    # The dot is the case this branch changed, and it survives to GitHub.
    assert GitHubClient()._parse_purl("pkg:pypi/plone.namedfile@6.0.0")[1] == "plone.namedfile"
