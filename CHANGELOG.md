# Changelog

All notable changes to vulnq will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/scanoss/vulnq/releases/tag/v1.0.0
[0.1.0]: https://github.com/scanoss/vulnq/releases/tag/v0.1.0