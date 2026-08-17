# Changelog

All notable changes to vulnq will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-17

### Removed - BREAKING
- `VulnerabilitySource.SNYK` and `VulnerabilitySource.SONATYPE`. Both were
  declared but had no client, so configuring either produced no client, no
  error, and an empty result — which reads as "this package has no known
  vulnerabilities". The failure was silent and in the dangerous direction.
  Code naming these members now fails at the point of use instead of returning
  a false clean bill of health. Nothing in the SEMCL.ONE toolchain referenced
  them.

### Added
- `NoSourcesConfiguredError`, raised when a configuration yields no queryable
  source, rather than returning an empty result that cannot be distinguished
  from a clean scan
- An identifier type no client can answer — a file hash today — is reported in
  `errors` instead of returning an empty result silently

### Fixed
- `sources_checked` claimed VulnerableCode had been checked on queries where no
  lookup was performed
- The CLI printed a raw traceback for an unknown `--sources` value; it now
  names the valid sources and exits 2

### Added
- Exploitability enrichment from published snapshots: CISA KEV known-exploited
  status and FIRST EPSS exploitation probability, joined on the CVE id after
  de-duplication
- `vulnq-mine` command with `kev` and `epss` subcommands for producing
  snapshots; scheduling, credentials, publishing target, and retention stay
  outside the tool
- `Vulnerability` fields `known_exploited`, `kev_date_added`,
  `kev_known_ransomware`, `kev_required_action`, `epss_score`,
  `epss_percentile`, and `epss_score_date`
- `QueryResult.enrichment` records the catalog version or score date each join
  ran against, plus snapshot age, so a stale join is distinguishable from a
  fresh one and an answer can be explained later
- `VULNQ_KEV_SNAPSHOT`, `VULNQ_EPSS_SNAPSHOT`, and
  `VULNQ_SNAPSHOT_MAX_AGE_DAYS` environment variables with matching
  `--kev-snapshot`, `--epss-snapshot`, and `--snapshot-max-age-days` flags
- `VulnerabilityQuery.load_config()` for callers that build a configuration but
  still want environment defaults

### Safety
- `vulnq-mine kev` refuses to publish an implausibly small catalog, and a KEV
  snapshot below that floor confers no negatives. An upstream schema change
  would otherwise mine cleanly to zero rows and mark every CVE not-exploited
  across a whole fleet
- Snapshot records are validated at load, and enrichment failures are contained
  per source, so one corrupt published snapshot degrades exploitability to
  unknown instead of failing every vulnerability query
- A snapshot whose age cannot be established does not pass a configured
  freshness gate, and an unparseable `fetched_at` is refused outright
- An invalid `VULNQ_SNAPSHOT_MAX_AGE_DAYS` raises instead of silently
  disabling the gate the operator believes is switched on
- Snapshot URLs are parsed rather than concatenated, so presigned S3 and GCS
  locations work
- The first snapshot load is serialised, so a second thread cannot observe an
  absent snapshot mid-load
- `vulnq-mine epss` fetches an explicitly requested date exactly rather than
  silently substituting a nearby day, and its walk-back now also survives a
  corrupt file rather than only a missing one

### Fixed
- The CLI built a `Configuration` directly and so never read the environment,
  leaving `GITHUB_TOKEN` and `NVD_API_KEY` unused for every command-line and
  subprocess caller
- Enrichment applies to the VulnerableCode-only query path, which returned
  before consolidation and would otherwise have been skipped
- `__version__` no longer disagrees with the packaged version, which matters
  now that results carry provenance

## [1.0.2] - 2025-11-05

### Fixed
- Fix README examples with working queries

## [1.0.1] - 2025-01-05

### Fixed
- Replace broken pip-licenses with osslili-based license checking workflow
- Update deprecated GitHub Actions (upload-artifact v3 → v4, CodeQL v2 → v3)
- Fix PyPI publishing to use GitHub OIDC trusted publishing instead of API tokens
- Add explicit permissions to all workflow jobs for security best practices
- Remove unnecessary files (Makefile, .pre-commit-config.yaml) for consistency
- Remove Related Projects section from README

### Changed
- Standardize Python version to 3.13 across all workflows
- Align workflow structure with other SEMCL.ONE projects

## [1.0.0] - 2025-01-05

### Added
- Full implementation of vulnerability querying from multiple sources
- Real API client implementations for OSV.dev, GitHub Advisory, and NIST NVD
- Support for VulnerableCode as an optional aggregated source
- Parallel asynchronous queries for improved performance
- Advanced deduplication and data normalization across sources
- CVSS score parsing from vector strings
- No API keys required for OSV.dev and VulnerableCode
- Optional API keys for enhanced rate limits (GitHub, NVD)
- Proper session management to prevent resource leaks

### Changed
- Upgraded from mock implementations to production-ready API clients
- Improved error handling and retry logic with exponential backoff
- Enhanced vulnerability merging logic with source prioritization
- Better CVSS score extraction from various formats

### Fixed
- Session cleanup warnings in async operations
- CVSS vector string parsing for OSV.dev responses
- CPE string normalization and parsing
- Deduplication using CVE as primary identifier

## [0.1.0] - 2024-11-04

### Added
- Initial release of vulnq
- Support for multiple identifier formats (PURL, CPE, hashes)
- Integration with OSV.dev API
- Integration with GitHub Advisory Database
- Integration with NIST NVD
- Command-line interface with multiple output formats (table, JSON, markdown)
- Python API for programmatic access
- Caching support for API responses
- Severity filtering capabilities
- Batch processing from input files

### Security
- Secure API key handling via environment variables
- Rate limiting for API calls

[1.0.2]: https://github.com/SemClone/vulnq/releases/tag/v1.0.2
[1.0.1]: https://github.com/SemClone/vulnq/releases/tag/v1.0.1
[1.0.0]: https://github.com/SemClone/vulnq/releases/tag/v1.0.0
[0.1.0]: https://github.com/SemClone/vulnq/releases/tag/v0.1.0