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
- **VulnerableCode** - opt-in via `--use-vulnerablecode`, replaces the above

Joined from published snapshots rather than queried (see
[Exploitability Enrichment](#exploitability-enrichment)):

- **CISA KEV** - known-exploited status
- **FIRST EPSS** - exploitation probability

Every source named in `VulnerabilitySource` has a working client. Requesting a
source that does not exist fails immediately rather than returning an empty
result that reads as a clean scan.

## Supported Identifier Formats

### Package URLs (PURLs)
- `pkg:npm/package@version`
- `pkg:pypi/package@version`
- `pkg:maven/group/artifact@version`
- `pkg:gem/package@version`
- `pkg:cargo/package@version`
- `pkg:nuget/package@version`
- `pkg:golang/module@version`

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

vulnq can be configured via environment variables or config file:

```bash
# API Keys (optional, for higher rate limits)
export GITHUB_TOKEN="your_github_token"
export NVD_API_KEY="your_nvd_api_key"

# Cache settings
export VULNQ_CACHE_DIR="~/.vulnq/cache"
export VULNQ_CACHE_TTL="3600"  # seconds

# Rate limiting
export VULNQ_MAX_CONCURRENT="5"

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

```bash
# Pipe PURLs from src2purl to vulnq
src2purl /path/to/project | vulnq --format json

# Check vulnerabilities for detected packages
upmex /path/to/package.json | vulnq --min-severity critical

# Generate vulnerability report from SBOM
cat sbom.json | vulnq --input - --format markdown > vulns.md
```

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
      "references": [...]
    }
  ],
  "metadata": {
    "sources": ["osv", "github", "nvd"],
    "query_time": "2024-11-04T10:30:00Z"
  }
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
pytest tests/test_osv_client.py -v
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
