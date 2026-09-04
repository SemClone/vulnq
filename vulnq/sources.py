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

import sys
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional, Tuple

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
        removed_in: The release that deletes this source, if one is scheduled.
            Set it and every path that selects the source warns; leave it None
            and none of them do
        deprecation_note: What a caller should do instead, appended to the
            warning. Pointless without removed_in
    """

    source: VulnerabilitySource
    build: Callable[[Configuration, bool], BaseClient]
    in_default_fanout: bool
    merge_priority: int
    removed_in: Optional[str] = None
    deprecation_note: str = ""


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
    ),
    SourceSpec(
        source=VulnerabilitySource.NVD,
        build=lambda c, v: NVDClient(api_key=c.nvd_api_key, **_common(c, v)),
        in_default_fanout=True,
        merge_priority=1,
    ),
    SourceSpec(
        source=VulnerabilitySource.VULNERABLECODE,
        build=lambda c, v: VulnerableCodeClient(
            api_key=c.vulnerablecode_api_key,
            base_url=c.vulnerablecode_url,
            **_common(c, v),
        ),
        # Opt-in. It aggregates the three above rather than adding to them,
        # and its public instance is throttled at ten requests a minute, so
        # querying it unasked would spend that budget on a second-hand answer.
        in_default_fanout=False,
        merge_priority=4,
        # Measured against the other three across fifteen packages in eight
        # ecosystems: it returned 122 findings where they returned 152, missed
        # 66 they carry, and of the 36 it returned that they did not, 11 were
        # false positives it produces by reading a fixed version without an
        # introduced one - axios@0.21.0 reported against nine advisories
        # introduced in 1.0.0 or later. The deb and rpm packages it declines
        # are answered by OSV today, in the default fan-out. It defers to all
        # three on every overlap anyway, so nothing it says ever decides.
        removed_in="2.0",
        deprecation_note=(
            "its ecosystems are covered by osv, github and nvd, which vulnq "
            "queries by default"
        ),
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


def deprecation_warning(source: VulnerabilitySource) -> Optional[str]:
    """Return the notice a caller selecting this source should see, if any.

    Args:
        source: The source that was selected

    Returns:
        A one-line warning, or None if the source is not on the way out
    """
    spec = BY_SOURCE.get(source)
    if spec is None or not spec.removed_in:
        return None

    warning = f"the {spec.source.value} source is deprecated and will be removed in {spec.removed_in}"
    if spec.deprecation_note:
        warning = f"{warning} - {spec.deprecation_note}"
    return warning


def warn_about_deprecated(sources: Iterable[VulnerabilitySource]) -> None:
    """Write a deprecation notice to stderr for each source on the way out.

    Deliberately stderr and not the rich console the CLI prints results with:
    a caller reading `vulnq <purl> --format json` on stdout would otherwise get
    a warning spliced into the document, which is a worse failure than the one
    the warning is trying to prevent.

    Args:
        sources: The sources actually about to be queried
    """
    for source in sources:
        warning = deprecation_warning(source)
        if warning:
            print(f"warning: {warning}", file=sys.stderr)


class UnknownSourceError(ValueError):
    """Raised when a disable list names something that is not a source.

    Ignoring it would be worse than failing: whoever wrote the name believes
    that source is switched off, and it is not. A typo like "gitub" would leave
    GitHub quietly queried by someone who thinks they turned it off.
    """


def parse_disabled(raw: Optional[str]) -> Tuple[VulnerabilitySource, ...]:
    """Read a comma separated list of sources an operator has switched off.

    Args:
        raw: The value of VULNQ_DISABLED_SOURCES or --disable-source, or None

    Returns:
        The sources named, in registry order

    Raises:
        UnknownSourceError: If a name matches no source
    """
    if not raw:
        return ()

    named = {piece.strip().lower() for piece in raw.split(",") if piece.strip()}
    known = {spec.source.value for spec in REGISTRY}

    unknown = sorted(named - known)
    if unknown:
        raise UnknownSourceError(
            f"Unknown source(s) to disable: {', '.join(unknown)}. "
            f"Valid sources: {', '.join(sorted(known))}."
        )

    return tuple(spec.source for spec in REGISTRY if spec.source.value in named)
