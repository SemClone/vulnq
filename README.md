# vulnq - Vulnerability Query Tool

[![Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

vulnq is a lightweight, multi-source vulnerability query tool that consolidates security data from multiple vulnerability databases. It accepts various software identifiers (PURLs, CPEs, hashes) and returns comprehensive vulnerability information including CVEs, severity scores, and available fixes.

## Key Features

- **Multiple ID Formats** - Accepts PURLs, CPE strings, and file hashes
- **Multi-Source Aggregation** - Queries OSV.dev, GitHub Advisory, NIST NVD, and more
- **Smart Format Detection** - Auto-detects input format or accepts explicit flags
- **Upgrade Path Suggestions** - Identifies fixed versions when available
- **Lightweight** - API-only design, no local vulnerability databases
- **Flexible Output** - JSON, table, and markdown formats

## Installation

```bash
pip install vulnq
```

For development:

```bash
git clone https://github.com/SemClone/vulnq.git
cd vulnq
pip install -e .
```

## Quick Start

### Command Line

```bash
# Query using Package URL (auto-detected)
vulnq pkg:npm/express@4.17.1

# Query using CPE string (example: Apache Log4j)
vulnq --cpe "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"

# Note: Hash-based queries are not currently supported by vulnerability databases

# Query multiple identifiers from file
vulnq --input packages.txt

# Filter by severity
vulnq pkg:pypi/django@3.2.1 --min-severity high

# Output as JSON
vulnq pkg:gem/rails@6.0.0 --format json

# Include fixed versions only
vulnq pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 --show-fixes
```

### Python API

```python
from vulnq import VulnerabilityQuery

# Initialize the query engine
vq = VulnerabilityQuery()

# Query by PURL
results = vq.query("pkg:npm/express@4.17.1")

# Query by CPE
results = vq.query_cpe("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")

# Note: Hash queries are not currently supported by vulnerability databases
# Future versions may support this through file-to-package mapping services

# Process results
for vuln in results.vulnerabilities:
    print(f"{vuln.id}: {vuln.severity} - {vuln.summary}")
    if vuln.fixed_versions:
        print(f"  Fixed in: {', '.join(vuln.fixed_versions)}")
```

## Supported Vulnerability Sources

Queried per lookup, in parallel, then de-duplicated:

- **OSV.dev** - Google's Open Source Vulnerability database
- **GitHub Advisory Database** - GitHub Security Advisories
- **NIST NVD** - National Vulnerability Database

Joined from published snapshots rather than queried (see
[Exploitability Enrichment](#exploitability-enrichment)):

- **CISA KEV** - known-exploited status
- **FIRST EPSS** - exploitation probability

Every source named in `VulnerabilitySource` has a working client. Requesting a
source that does not exist fails immediately rather than returning an empty
result that reads as a clean scan.

### An empty result means "we looked and found nothing"

Not every source can answer every identifier. OSV and GitHub are keyed by PURL
and have no CPE lookup; NVD is keyed by CPE and can only take the PURLs it can
convert. A source that cannot be asked, or that fails when
asked, is never counted as having answered:

- `sources_checked` — ran and returned an answer
- `sources_skipped` — could not be asked, mapped to why
- `errors` — was asked and failed, including rate limits
- `is_conclusive` — true when at least one source ran

```console
$ vulnq --cpe "2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"
Found 100 vulnerabilities: 17 critical, 51 high
osv skipped: OSV cannot be queried by CPE; use a PURL
github skipped: GitHub Advisory Database cannot be queried by CPE; use a PURL
```

If no source answers, the CLI says so and exits 1 — zero findings from zero
sources is not a clean scan. Findings themselves are reported through the
output, not the exit code.

A source can also answer incompletely. When records come back that vulnq cannot
parse, the ones it could parse are still reported, and `warnings` says how many
were lost:

```console
$ vulnq pkg:npm/example@1.0.0
Found 4 vulnerabilities: 1 critical, 0 high

Incomplete answers:
  • osv: 2 of 6 records returned by osv could not be parsed and are missing
    from this result
```

That is the safe direction — under-reporting, not a false clean bill — but only
if you can see it happened.

The same rule covers a question a source cannot answer as asked:

```console
$ vulnq pkg:apk/alpine/openssl@1.1.1q-r0
Found 0 vulnerabilities: 0 critical, 0 high

Incomplete answers:
  • osv: no Alpine release named in a distro= qualifier on
    pkg:apk/alpine/openssl@1.1.1q-r0; OSV keys its Alpine advisories by
    release, so none were checked
```

### Version matching

Sources disagree about who filters by version. OSV and NVD do it server-side.
The GitHub Advisory Database returns every advisory it holds for a package and
leaves the filtering to the caller, in a range grammar like
`>= 2.0-beta9, < 2.25.3`. vulnq evaluates those using the ecosystem's own
version ordering — semver, Maven qualifier ranks, or PEP 440.

Every finding records which of those happened, in `version_match`:

| Value | Meaning |
| --- | --- |
| `affected` | vulnq evaluated the range; the queried version is inside it |
| `source_filtered` | The upstream source filtered by version itself |
| `unconfirmed` | The range could not be evaluated; reported as a precaution |
| `not_evaluated` | The query pinned no version, so nothing was filtered |

An advisory whose range cannot be evaluated is **reported, not dropped**, and
marked `[unconfirmed]` in the table. Dropping an advisory that might apply is
the dangerous direction; over-reporting is acceptable only when it is visible.

Maven qualifier ranks (`alpha` < `beta` < `rc` < `snapshot` < release < `sp`),
RubyGems digit/letter segments, and Go pseudo-versions are handled. Anything
this cannot order confidently — an unrecognised Maven qualifier, a version
carrying build metadata, a range grammar outside GitHub's — falls through to
`unconfirmed` rather than being guessed at.

## Supported Identifier Formats

### Package URLs (PURLs)
- `pkg:npm/package@version`
- `pkg:pypi/package@version`
- `pkg:maven/group/artifact@version`
- `pkg:gem/package@version`
- `pkg:cargo/package@version`
- `pkg:nuget/package@version`
- `pkg:golang/module@version`
- `pkg:deb/debian/package@version`
- `pkg:rpm/redhat/package@version`
- `pkg:apk/alpine/package@version?distro=alpine-3.16&upstream=origin`

Alpine is the one that needs qualifiers. OSV keys its Alpine advisories two
ways, and a PURL missing either comes back empty:

- **by release branch**, from `distro=`. `alpine-3.16.2`, `3.16.2` and `v3.16`
  all read as the same branch, so whatever your SBOM tool writes will do.
- **by origin package**, from `upstream=`. Alpine ships most libraries as
  subpackages — `libcrypto1.1` and `libssl1.1` both come from `openssl` — and
  the advisories are filed under the origin. syft writes `upstream=` when the
  two differ.

An Alpine answer with nothing in it is checked before it is reported as clean,
so a branch that does not exist yet, or a subpackage nobody named the origin
of, says so in `warnings` instead of reading as a clean bill.
`pkg:apk/wolfi` and `pkg:apk/chainguard` need none of this.

### CPE (Common Platform Enumeration)
- `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`
- `cpe:/a:vendor:product:version` (legacy format)

### File Hashes

Detected and parsed, but **not queryable** — none of the upstream databases
accept a file hash as a lookup key. `--sha256`, `--sha1`, and `--md5` are
accepted and return no results with an explicit error saying no lookup was
performed, rather than an empty result that would read as a clean scan.

- SHA256
- SHA1
- MD5

## Configuration

vulnq is configured through environment variables and command line flags. There is no config file.

```bash
# API Keys (optional, for higher rate limits)
export GITHUB_TOKEN="your_github_token"
export NVD_API_KEY="your_nvd_api_key"

# Rate limiting
export VULNQ_MAX_CONCURRENT="5"

# Switch a source off whatever else selects it. Reported in
# sources_skipped rather than dropped, so an answer never reads as complete
# when a feed was not asked.
export VULNQ_DISABLED_SOURCES="nvd"

# Exploitability snapshots (see below)
export VULNQ_KEV_SNAPSHOT="/srv/snapshots"
export VULNQ_EPSS_SNAPSHOT="/srv/snapshots"
export VULNQ_SNAPSHOT_MAX_AGE_DAYS="7"   # optional; unset means age is advisory
```

## Exploitability Enrichment

vulnq answers "is this package vulnerable, how badly, and is there a fix." KEV
and EPSS add the other half: is anyone exploiting it, and how likely is that to
change.

- **CISA KEV** marks CVEs that are known to be exploited in the wild, with the
  date they were catalogued, whether ransomware campaigns use them, and the
  required remediation action.
- **FIRST EPSS** gives the probability of exploitation in the next 30 days,
  which is what makes a backlog of hundreds of medium-severity CVEs rankable.

Both are static reference files joined on the CVE id, not per-query APIs. Mine
them once and point a fleet of workers at the result:

```bash
# Mine snapshots (an operational job - schedule this yourself)
vulnq-mine kev --out /srv/snapshots
vulnq-mine epss --out /srv/snapshots

# Query against them
export VULNQ_KEV_SNAPSHOT=/srv/snapshots
export VULNQ_EPSS_SNAPSHOT=/srv/snapshots
vulnq pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

```
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━━━┳ ...
┃ ID                  ┃ Severity ┃ CVSS ┃ KEV ┃  EPSS ┃ ...
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━━━╇ ...
│ GHSA-jfh8-c2jp-5v3q │ CRITICAL │  9.0 │ YES │ 1.000 │ ...

cisa-kev: 2026.08.14, 0.2d old
first-epss: 2026-08-16, 0.2d old
```

`vulnq` reads snapshots; it does not schedule mining, hold credentials, or
publish anywhere. Those are deployment policy, so installing `vulnq` never
inherits a publishing dependency. A snapshot location may be a file, a
directory, or a URL.

### Unknown is not a negative

A missing, unreachable, or stale snapshot leaves `known_exploited` and
`epss_score` as `null` — never `false` or `0.0`. Zero is a real EPSS score and
`false` is a real KEV verdict, so a consumer that reads either out of a failed
join would confidently under-rate a live threat. Check `enrichment` in the JSON
envelope to see which snapshot a result was scored against and how old it was:

```json
"enrichment": {
  "cisa-kev": {"available": true, "version": "2026.08.14", "age_seconds": 23.8, "stale": false},
  "first-epss": {"available": true, "version": "2026-08-16", "record_count": 360399}
}
```

Advisories with no CVE alias (GHSA-only) can never be joined and stay `null`.

### Attribution

CISA KEV is a US Government work in the public domain. FIRST requests
attribution when EPSS data is used in a product — confirm placement before
customer delivery, and confirm FIRST's terms separately if you republish a
snapshot rather than consuming it privately.

## Integration with SEMCL.ONE

vulnq is designed to work seamlessly with other SEMCL.ONE tools:

vulnq reads one identifier per line, from a file, from `--input -`, or from a
bare pipe. Blank lines are skipped and `#` starts a comment, so a list can be
annotated.

```bash
# From a file
vulnq --input packages.txt --format json

# From a pipe, with or without --input -
printf 'pkg:npm/lodash@4.17.20\npkg:pypi/django@3.2.0\n' | vulnq --format markdown > vulns.md
```

Other SEMCL.ONE tools emit richer structures than a list of identifiers, so
extract the PURLs before piping. With `jq`:

```bash
jq -r '.. | .purl? // empty' sbom.json | sort -u | vulnq --min-severity high
```

Note that a direct `src2purl ... | vulnq` pipe does not work today: src2purl
writes its banner to standard output alongside its results, so the stream is
not a clean list of identifiers. Tracked in src2purl.

## Output Formats

### Table (default)
```
┌──────────────┬──────────┬──────────┬─────────────────┬──────────────┐
│ CVE          │ Severity │ CVSS     │ Package         │ Fixed In     │
├──────────────┼──────────┼──────────┼─────────────────┼──────────────┤
│ CVE-2021-1234│ HIGH     │ 7.5      │ express@4.17.1  │ 4.17.2       │
│ CVE-2021-5678│ CRITICAL │ 9.8      │ express@4.17.1  │ 4.18.0       │
└──────────────┴──────────┴──────────┴─────────────────┴──────────────┘
```

### JSON
```json
{
  "query": "pkg:npm/express@4.17.1",
  "vulnerabilities": [
    {
      "id": "CVE-2021-1234",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "summary": "Remote Code Execution...",
      "fixed_versions": ["4.17.2", "4.18.0"],
      "version_match": "affected",
      "references": [...]
    }
  ],
  "sources_checked": ["osv", "github", "nvd"],
  "sources_skipped": {},
  "warnings": [],
  "errors": [],
  "is_conclusive": true
}
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vulnq tests/

# Run specific test
pytest tests/test_cvss.py -v
```

### Building

```bash
# Build package
python -m build

# Install locally for testing
pip install -e .
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

vulnq is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/SemClone/vulnq/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SemClone/vulnq/discussions)
- **Security**: Report vulnerabilities to security@semcl.one

---

*Part of the [SEMCL.ONE](https://github.com/SemClone/semcl.one) Software Composition Analysis toolchain*
