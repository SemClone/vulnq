"""Where a vulnerability source is declared, and the only place it is declared.

A source used to be named in seven files: the enum, the default list, the
fan-out tuple, an if-block per client, the merge priority table, the CLI flag,
and the client itself. Adding or removing one meant finding all of them, and
VulnerableCode's replaces-everything special case accounted for fifteen sites
on its own. That is how three bugs lived unnoticed in its client.

Upstreams are not stable ground. VulnerableCode's v1 API was withdrawn and its
public instance now gates on a header; ClearlyDefined has changed owners. When
a feed changes hands, gates, or starts charging, the answer should be turning
it off, not surgery.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from .clients.base import BaseClient
from .clients.github import GitHubClient
from .clients.nvd import NVDClient
from .clients.osv import OSVClient
from .clients.vulnerablecode import VulnerableCodeClient
from .models import Configuration, VulnerabilitySource


@dataclass(frozen=True)
class SourceSpec:
    """Everything vulnq needs to know about one source.

    Attributes:
        source: The identifier this source reports itself as
        build: Makes the client, given the configuration and verbosity
        in_default_fanout: Whether it is queried when nobody said otherwise
        merge_priority: Lower wins when several sources describe one advisory
        credential_hint: What to tell someone whose query it refuses, or None
            if it needs no credential
    """

    source: VulnerabilitySource
    build: Callable[[Configuration, bool], BaseClient]
    in_default_fanout: bool
    merge_priority: int
    credential_hint: Optional[str] = None


def _common(config: Configuration, verbose: bool) -> Dict[str, object]:
    """Return the arguments every client takes.

    Args:
        config: The active configuration
        verbose: Whether the engine was asked to narrate

    Returns:
        Keyword arguments common to all clients
    """
    return {
        "timeout": config.timeout,
        "max_concurrent": config.max_concurrent,
        "verbose": verbose,
    }


# Order here is the order sources are declared, nothing more. Precedence when
# two sources describe one advisory is merge_priority; NVD is authoritative for
# CVEs, GitHub is better for packages it hosts, and VulnerableCode aggregates
# others so it defers to all of them.
REGISTRY: Tuple[SourceSpec, ...] = (
    SourceSpec(
        source=VulnerabilitySource.OSV,
        build=lambda c, v: OSVClient(**_common(c, v)),
        in_default_fanout=True,
        merge_priority=3,
    ),
    SourceSpec(
        source=VulnerabilitySource.GITHUB,
        build=lambda c, v: GitHubClient(api_key=c.github_token, **_common(c, v)),
        in_default_fanout=True,
        merge_priority=2,
        credential_hint="set GITHUB_TOKEN for a higher rate limit",
    ),
    SourceSpec(
        source=VulnerabilitySource.NVD,
        build=lambda c, v: NVDClient(api_key=c.nvd_api_key, **_common(c, v)),
        in_default_fanout=True,
        merge_priority=1,
        credential_hint="set NVD_API_KEY for a higher rate limit",
    ),
    SourceSpec(
        source=VulnerabilitySource.VULNERABLECODE,
        build=lambda c, v: VulnerableCodeClient(**_common(c, v)),
        # Opt-in. It aggregates the three above rather than adding to them, and
        # its public instance is not usable anonymously, so querying it unasked
        # would spend a request to report a failure.
        in_default_fanout=False,
        merge_priority=4,
    ),
)

BY_SOURCE: Dict[VulnerabilitySource, SourceSpec] = {spec.source: spec for spec in REGISTRY}

DEFAULT_SOURCES: Tuple[VulnerabilitySource, ...] = tuple(
    spec.source for spec in REGISTRY if spec.in_default_fanout
)

SELECTABLE_SOURCES: Tuple[VulnerabilitySource, ...] = tuple(spec.source for spec in REGISTRY)

MERGE_PRIORITY: Dict[VulnerabilitySource, int] = {
    spec.source: spec.merge_priority for spec in REGISTRY
}


def parse_disabled(raw: Optional[str]) -> Tuple[VulnerabilitySource, ...]:
    """Read a comma separated list of sources an operator has switched off.

    Unknown names are ignored rather than rejected: the variable is set by
    whoever runs vulnq, often in an image or a job definition, and a name that
    outlives the source it referred to should not break every query.

    Args:
        raw: The value of VULNQ_DISABLED_SOURCES, or None

    Returns:
        The sources named, in registry order
    """
    if not raw:
        return ()

    named = {piece.strip().lower() for piece in raw.split(",") if piece.strip()}
    return tuple(spec.source for spec in REGISTRY if spec.source.value in named)
