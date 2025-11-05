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
git clone https://github.com/scanoss/vulnq.git
cd vulnq
pip install -e .
```

## Quick Start

### Command Line

```bash
# Query using Package URL (auto-detected)
vulnq pkg:npm/express@4.17.1

# Query using CPE string
vulnq --cpe "cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*"

# Query using file hash
vulnq --sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

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
results = vq.query_cpe("cpe:2.3:a:nodejs:node.js:14.17.0:*:*:*:*:*:*:*")

# Query by hash
results = vq.query_hash("sha256", "abc123...")

# Process results
for vuln in results.vulnerabilities:
    print(f"{vuln.id}: {vuln.severity} - {vuln.summary}")
    if vuln.fixed_versions:
        print(f"  Fixed in: {', '.join(vuln.fixed_versions)}")
```

## Supported Vulnerability Sources

- **OSV.dev** - Google's Open Source Vulnerability database
- **GitHub Advisory Database** - GitHub Security Advisories
- **NIST NVD** - National Vulnerability Database
- **FIRST.org** - Forum of Incident Response and Security Teams (planned)
- **Sonatype OSS Index** - Component vulnerability data (planned)

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
```

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

- **Issues**: [GitHub Issues](https://github.com/scanoss/vulnq/issues)
- **Discussions**: [GitHub Discussions](https://github.com/scanoss/vulnq/discussions)
- **Security**: Report vulnerabilities to security@scanoss.com

## Related Projects

vulnq is part of the SEMCL.ONE toolchain:

- [ospac](https://github.com/scanoss/ospac) - Policy as Code for license compliance
- [src2purl](https://github.com/scanoss/src2purl) - Generate PURLs from source code
- [osslili](https://github.com/scanoss/osslili) - License detection in source code
- [upmex](https://github.com/scanoss/upmex) - Package metadata extraction

---

*Part of the [SEMCL.ONE](https://github.com/scanoss/semcl.one) Software Composition Analysis toolchain*