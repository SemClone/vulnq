"""Command-line interface for vulnq."""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .core import NoSourcesConfiguredError, VulnerabilityQuery
from .models import QueryResult, Severity, VersionMatch

console = Console()


def print_table(result: QueryResult, show_fixes: bool = False):
    """Print results in table format."""
    table = Table(title=f"Vulnerabilities for {result.query}")

    # Only widen the table when a snapshot was actually joined, so output is
    # unchanged for callers running without enrichment configured.
    show_kev = "cisa-kev" in result.enrichment
    show_epss = "first-epss" in result.enrichment

    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("CVSS", justify="right")
    if show_kev:
        table.add_column("KEV", justify="center")
    if show_epss:
        table.add_column("EPSS", justify="right")
    table.add_column("Summary", style="dim", overflow="fold")
    if show_fixes:
        table.add_column("Fixed In", style="green")

    for vuln in result.vulnerabilities:
        severity_style = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.NONE: "dim",
        }.get(vuln.severity, "white")

        row = [
            vuln.id,
            Text(vuln.severity.value, style=severity_style),
            # 0.0 is a computed score meaning no impact. Falsy checks printed
            # it as "-", making it indistinguishable from never scored.
            # One decimal always, so the column lines up and a float artifact
            # cannot reach the output as 7.000000001.
            f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "-",
        ]

        if show_kev:
            # "?" is not "no" - an unknown join must not read as safe.
            if vuln.known_exploited is None:
                row.append(Text("?", style="dim"))
            elif vuln.known_exploited:
                row.append(Text("YES", style="bold red"))
            else:
                row.append(Text("no", style="dim"))

        if show_epss:
            row.append(f"{vuln.epss_score:.3f}" if vuln.epss_score is not None else "?")

        summary_text = vuln.summary[:100] + "..." if len(vuln.summary) > 100 else vuln.summary
        if vuln.version_match == VersionMatch.UNCONFIRMED:
            # Included because the range could not be evaluated, not because it
            # was evaluated and matched. Saying so is the whole point of
            # reporting it rather than dropping it.
            summary_text = f"[unconfirmed] {summary_text}"
        row.append(summary_text)

        if show_fixes:
            fixes = ", ".join(vuln.fixed_versions[:3])
            if len(vuln.fixed_versions) > 3:
                fixes += f" (+{len(vuln.fixed_versions) - 3} more)"
            row.append(fixes or "-")

        table.add_row(*row)

    console.print(table)

    # Print summary
    summary = f"Found {result.vulnerability_count} vulnerabilities: "
    summary += f"{result.critical_count} critical, {result.high_count} high"
    console.print(f"\n[bold]{summary}[/bold]")

    if not result.is_conclusive:
        # Zero findings from zero sources is not a clean scan.
        console.print(
            "[bold red]No source answered this query.[/bold red] "
            "Zero results here means nobody looked, not that nothing was found."
        )

    for source, reason in result.sources_skipped.items():
        console.print(f"[yellow]{source} skipped:[/yellow] {reason}")

    for provenance in result.enrichment.values():
        if not provenance.available:
            console.print(
                f"[yellow]{provenance.source}: unavailable[/yellow] "
                f"({provenance.error}) - exploitability left unknown"
            )
            continue

        age = ""
        if provenance.age_seconds is not None:
            age = f", {provenance.age_seconds / 86400:.1f}d old"
        state = " [yellow](stale, not joined)[/yellow]" if provenance.stale else ""
        console.print(
            f"[dim]{provenance.source}: {provenance.version or 'unknown'}{age}[/dim]{state}"
        )

    if result.warnings:
        console.print("\n[yellow]Incomplete answers:[/yellow]")
        for warning in result.warnings:
            console.print(f"  • {warning}")

    if result.errors:
        console.print("\n[red]Errors:[/red]")
        for error in result.errors:
            console.print(f"  • {error}")


def print_json(result: QueryResult):
    """Print results in JSON format."""
    output = result.model_dump(mode="json")
    console.print_json(data=output)


def print_markdown(result: QueryResult):
    """Print results in Markdown format."""
    md = f"# Vulnerability Report for {result.query}\n\n"
    md += f"**Query Time:** {result.query_time.isoformat()}\n"
    md += f"**Sources Checked:** {', '.join(s.value for s in result.sources_checked)}\n\n"

    md += "## Summary\n\n"
    md += f"- **Total Vulnerabilities:** {result.vulnerability_count}\n"
    md += f"- **Critical:** {result.critical_count}\n"
    md += f"- **High:** {result.high_count}\n\n"

    for provenance in result.enrichment.values():
        if provenance.available and not provenance.stale:
            md += f"- **{provenance.source}:** {provenance.version or 'unknown'}\n"
        else:
            md += f"- **{provenance.source}:** unavailable, exploitability unknown\n"
    if result.enrichment:
        md += "\n"

    # A saved report must carry the same caveats as the terminal output, or an
    # inconclusive query reads as a clean scan for as long as the file exists.
    if not result.is_conclusive:
        md += (
            "> **No source answered this query.** Zero results here means nobody "
            "looked, not that nothing was found.\n\n"
        )

    if result.sources_skipped:
        md += "### Sources Skipped\n\n"
        for source, reason in result.sources_skipped.items():
            md += f"- **{source}:** {reason}\n"
        md += "\n"

    if result.warnings:
        md += "### Incomplete Answers\n\n"
        for warning in result.warnings:
            md += f"- {warning}\n"
        md += "\n"

    if result.errors:
        md += "### Errors\n\n"
        for error in result.errors:
            md += f"- {error}\n"
        md += "\n"

    if result.vulnerabilities:
        md += "## Vulnerabilities\n\n"

        for vuln in result.vulnerabilities:
            md += f"### {vuln.id} - {vuln.severity.value}\n\n"
            score = "N/A" if vuln.cvss_score is None else f"{vuln.cvss_score:.1f}"
            md += f"**CVSS Score:** {score}\n\n"

            if vuln.version_match == VersionMatch.UNCONFIRMED:
                md += (
                    "> Reported because its affected-version range could not be evaluated, "
                    "not because the queried version was confirmed to be in it.\n\n"
                )

            if vuln.known_exploited is not None:
                exploited = "Yes" if vuln.known_exploited else "No"
                md += f"**Known Exploited (CISA KEV):** {exploited}\n\n"
                if vuln.known_exploited and vuln.kev_required_action:
                    md += f"**Required Action:** {vuln.kev_required_action}\n\n"

            if vuln.epss_score is not None:
                md += f"**EPSS:** {vuln.epss_score:.5f}"
                if vuln.epss_percentile is not None:
                    md += f" (percentile {vuln.epss_percentile:.5f})"
                md += "\n\n"

            md += f"**Summary:** {vuln.summary}\n\n"

            if vuln.fixed_versions:
                md += f"**Fixed in:** {', '.join(vuln.fixed_versions)}\n\n"

            if vuln.references:
                md += "**References:**\n"
                for ref in vuln.references[:5]:
                    md += f"- {ref}\n"
                md += "\n"

    console.print(md)


@click.command()
@click.argument("identifier", required=False)
@click.option("--cpe", help="Query using CPE string")
@click.option("--sha256", help="Query using SHA256 hash")
@click.option("--sha1", help="Query using SHA1 hash")
@click.option("--md5", help="Query using MD5 hash")
@click.option("--input", "-i", type=click.Path(exists=True), help="Input file with identifiers")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    help="Output format",
)
@click.option(
    "--min-severity",
    type=click.Choice(["none", "low", "medium", "high", "critical"]),
    help="Minimum severity to report",
)
@click.option("--show-fixes", is_flag=True, help="Show fixed versions in output")
@click.option(
    "--sources",
    multiple=True,
    help="Sources to check: osv, github, nvd. Naming vulnerablecode selects it instead.",
)
@click.option("--use-vulnerablecode", is_flag=True, help="Use VulnerableCode as the primary source")
@click.option(
    "--kev-snapshot",
    envvar="VULNQ_KEV_SNAPSHOT",
    help="CISA KEV snapshot path, directory, or URL",
)
@click.option(
    "--epss-snapshot",
    envvar="VULNQ_EPSS_SNAPSHOT",
    help="FIRST EPSS snapshot path, directory, or URL",
)
@click.option(
    "--snapshot-max-age-days",
    type=int,
    envvar="VULNQ_SNAPSHOT_MAX_AGE_DAYS",
    help="Refuse snapshots older than this instead of joining against them",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.version_option(version=__version__)
def main(
    identifier: Optional[str],
    cpe: Optional[str],
    sha256: Optional[str],
    sha1: Optional[str],
    md5: Optional[str],
    input: Optional[str],
    format: str,
    min_severity: Optional[str],
    show_fixes: bool,
    sources: tuple,
    use_vulnerablecode: bool,
    kev_snapshot: Optional[str],
    epss_snapshot: Optional[str],
    snapshot_max_age_days: Optional[int],
    verbose: bool,
):
    """vulnq - Vulnerability Query Tool

    Query multiple vulnerability databases using various software identifiers.

    Examples:

        vulnq pkg:npm/express@4.17.1

        vulnq --cpe "cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*"

        vulnq --sha256 abc123def456...

        vulnq --input packages.txt --format json
    """

    # Determine what to query
    queries = []

    if identifier:
        queries.append(identifier)
    elif cpe:
        queries.append(f"cpe:{cpe}" if not cpe.startswith("cpe:") else cpe)
    elif sha256:
        queries.append(f"sha256:{sha256}")
    elif sha1:
        queries.append(f"sha1:{sha1}")
    elif md5:
        queries.append(f"md5:{md5}")
    elif input:
        if input == "-":
            queries.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            with open(input) as f:
                queries.extend(line.strip() for line in f if line.strip())
    else:
        console.print("[red]Error: No identifier provided[/red]")
        console.print("Run 'vulnq --help' for usage information")
        sys.exit(1)

    # Start from the environment so API keys and snapshot locations reach a
    # subprocess caller, then let explicit flags override.
    config = VulnerabilityQuery.load_config()
    if use_vulnerablecode:
        config.use_vulnerablecode = True
    if kev_snapshot:
        config.kev_snapshot = kev_snapshot
    if epss_snapshot:
        config.epss_snapshot = epss_snapshot
    if snapshot_max_age_days is not None:
        config.snapshot_max_age_days = snapshot_max_age_days
    if sources:
        from .models import VulnerabilitySource

        parsed = []
        for name in sources:
            try:
                parsed.append(VulnerabilitySource(name))
            except ValueError:
                valid = ", ".join(source.value for source in VulnerabilitySource)
                console.print(f"[red]Unknown source '{name}'.[/red] Available sources: {valid}")
                sys.exit(2)

        # VulnerableCode replaces the fan-out rather than joining it, so naming
        # it here means the same thing as passing --use-vulnerablecode. Doing
        # nothing instead would leave the caller with no sources at all.
        if VulnerabilitySource.VULNERABLECODE in parsed:
            config.use_vulnerablecode = True
            parsed = [s for s in parsed if s is not VulnerabilitySource.VULNERABLECODE]

        if parsed:
            config.sources = parsed

    # Initialize query engine
    try:
        vq = VulnerabilityQuery(config=config, verbose=verbose)
    except NoSourcesConfiguredError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(2)

    # Process queries
    inconclusive = False
    for query_str in queries:
        if verbose:
            console.print(f"[dim]Querying: {query_str}[/dim]")

        try:
            result = vq.query(query_str)
            inconclusive = inconclusive or not result.is_conclusive

            # Filter by severity if requested
            if min_severity:
                min_sev = Severity[min_severity.upper()]
                result.vulnerabilities, withheld = result.filter_by_severity(min_sev)
                if withheld:
                    # A shortened list handed back with nothing said about it
                    # reads as the whole answer.
                    result.warnings.append(
                        f"{withheld} finding(s) below {min_sev.value} were withheld by "
                        "--min-severity. Unrated findings are always kept"
                    )

            # Output results
            if format == "json":
                print_json(result)
            elif format == "markdown":
                print_markdown(result)
            else:
                print_table(result, show_fixes=show_fixes)

        except Exception as e:
            console.print(f"[red]Error processing {query_str}: {e}[/red]")
            if verbose:
                import traceback

                console.print(traceback.format_exc())
            sys.exit(1)

    # A script keying on the exit code must not read "no source answered" as a
    # clean scan. Findings themselves are reported through the output, not the
    # exit code, so this stays reserved for "the question went unanswered".
    if inconclusive:
        sys.exit(1)


if __name__ == "__main__":
    main()
