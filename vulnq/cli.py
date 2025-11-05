"""Command-line interface for vulnq."""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .core import VulnerabilityQuery
from .models import Configuration, QueryResult, Severity

console = Console()


def print_table(result: QueryResult, show_fixes: bool = False):
    """Print results in table format."""
    table = Table(title=f"Vulnerabilities for {result.query}")

    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("CVSS", justify="right")
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
            str(vuln.cvss_score) if vuln.cvss_score else "-",
            vuln.summary[:100] + "..." if len(vuln.summary) > 100 else vuln.summary,
        ]

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

    if result.errors:
        console.print("\n[yellow]Warnings:[/yellow]")
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

    if result.vulnerabilities:
        md += "## Vulnerabilities\n\n"

        for vuln in result.vulnerabilities:
            md += f"### {vuln.id} - {vuln.severity.value}\n\n"
            md += f"**CVSS Score:** {vuln.cvss_score or 'N/A'}\n\n"
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
@click.option("--sources", multiple=True, help="Vulnerability sources to check (osv, github, nvd)")
@click.option("--use-vulnerablecode", is_flag=True, help="Use VulnerableCode as the primary source")
@click.option("--no-cache", is_flag=True, help="Disable caching")
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
    no_cache: bool,
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

    # Configure
    config = Configuration(cache_enabled=not no_cache, use_vulnerablecode=use_vulnerablecode)
    if sources:
        from .models import VulnerabilitySource

        config.sources = [VulnerabilitySource(s) for s in sources]

    # Initialize query engine
    vq = VulnerabilityQuery(config=config, verbose=verbose)

    # Process queries
    for query_str in queries:
        if verbose:
            console.print(f"[dim]Querying: {query_str}[/dim]")

        try:
            result = vq.query(query_str)

            # Filter by severity if requested
            if min_severity:
                min_sev = Severity[min_severity.upper()]
                result.vulnerabilities = result.filter_by_severity(min_sev)

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


if __name__ == "__main__":
    main()
