# Changelog

All notable changes to vulnq will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-08-17

### Fixed
- GitHub's version-range filter never excluded anything. `_is_version_affected`
  returned `True` on every path, including the one commented "assume affected",
  so every advisory GitHub holds for a package was reported regardless of the
  queried version. `pkg:npm/express@4.17.1` reported ten advisories where three
  apply, and a version on 4.x was told it was affected by an advisory fixed in
  1.0.1. Ranges are now evaluated with the ecosystem's own version ordering
- GitHub was queried under package names that cannot exist. Its advisory
  database keys Maven as `group:artifact`, but the PURL name was passed through
  verbatim as `group/artifact`, so every canonical Maven coordinate returned
  zero advisories and was counted as checked — a structurally wrong question
  wearing the "asked and clean" costume. `log4j-core@2.14.1` now reports seven
  advisories including Log4Shell, where it previously reported none
- Scoped npm packages were queried as `%40scope/pkg`. The percent-encoding was
  never decoded, so a large share of the npm ecosystem returned a confident
  zero. `@babel/traverse` now resolves
- Records that failed to parse below the all-records-failed threshold vanished
  into a verbose print. Nine of ten broken advisories could be dropped and the
  result still looked complete. They are now reported in `warnings`
- NVD had no all-records-failed guard at all, so a response whose every record
  was unparseable came back as a clean scan. It now raises, as OSV and GitHub
  already did

### Added
- `Vulnerability.version_match`, recording whether the queried version was
  actually checked against the advisory's affected range, and by whom:
  `affected` (vulnq evaluated the range and it matches), `source_filtered` (the
  upstream source filtered by version itself), `unconfirmed` (the range could
  not be evaluated, so the advisory is reported as a precaution), and
  `not_evaluated` (the query pinned no version, so nothing was filtered)
- `QueryResult.warnings`, for a source that answered but whose answer was
  incomplete. Distinct from `errors`, which means the source did not answer
- `vulnq.versions`, with ecosystem-aware version ordering for semver, Maven,
  and PEP 440, and an evaluator for GitHub's `vulnerableVersionRange` grammar
- `packaging` as a direct dependency, for PEP 440 ordering

### Changed
- GitHub result counts drop for versioned queries, because the version filter
  now works. Counts rise for Maven and scoped npm, because those were
  previously unanswerable. Anyone holding a baseline will see both move
- An advisory whose range cannot be evaluated is reported rather than dropped,
  and marked `unconfirmed` in JSON and `[unconfirmed]` in the table. Dropping
  an advisory that might apply is the dangerous direction; over-reporting is
  acceptable only when it is visible as such
- The CLI printed `errors` under a "Warnings" heading. Errors are now labelled
  as errors, with incomplete answers listed separately

## [1.3.0] - 2026-08-17

### Fixed
- Client exceptions were swallowed and turned into an empty list, so a network
  failure, an HTTP error, or a rate limit was indistinguishable from a package
  with no known vulnerabilities. They now propagate and are reported
- `sources_checked` listed sources that had failed or could not be queried at
  all. It now means "this source ran and returned an answer"
- The `RateLimitError` branch in the query engine was unreachable, because no
  client ever let one escape. Hitting a rate limit read as a clean scan
- The GitHub client returned an empty list for an unparseable identifier and
  for any ecosystem outside its mapping table, and was then counted as checked.
  Because an unrecognised identifier defaults to PURL, a bare typo such as
  `vulnq express` reported a clean scan and exited 0
- The GitHub ecosystem table was missing `golang`, the official Go PURL type,
  along with Hex, Pub, Swift and GitHub Actions. Every Go query was answered
  with nothing
- The NVD PURL-to-CPE table mapped npm `express` to `expressjs:express`, a
  vendor NVD does not index. NVD accepted it and returned zero results, hiding
  three real CVEs behind a conclusive-looking clean scan. The correct vendor is
  `openjsf`, verified against live NVD data
- GitHub reports GraphQL failures, including rate limiting, as HTTP 200 with an
  `errors` array and no data. That parsed as a package with no advisories
- GitHub's primary rate limit uses HTTP 403, not 429, so it was never
  recognised as a rate limit
- A response whose records are all unparseable now raises rather than reporting
  zero findings; parsing none of N is a shape change, not a clean package
- Markdown output carried none of the new caveats, so a saved report of an
  inconclusive query read as clean for as long as the file existed
- Merging a CVE found by both NVD and another source raised a timezone
  comparison error that failed the entire query and discarded every finding
  from every source. NVD publishes timestamps without an offset and the others
  publish them with one. This surfaced only once the npm `express` mapping was
  corrected, because that was the first time real NVD results reached the merge
- A GitHub advisory node missing its advisory or id is now counted as a parse
  failure rather than skipped; only a record that does not apply to the queried
  version yields nothing without being counted
- A rate-limit message reported `X-RateLimit-Reset`, an epoch timestamp, as a
  delay in seconds, and the corrected message was then discarded by the caller
  in favour of a bare label. The reset time now reaches `errors`
- Merged records stored one source's naive timestamp beside another's
  offset-aware one; published dates are now normalized on assignment

### Added
- `sources_skipped` on `QueryResult`, mapping a source to why it could not be
  asked. A source that structurally cannot answer an identifier — OSV, GitHub
  and VulnerableCode take PURLs but not CPEs; NVD takes CPEs and only the PURLs
  it can convert — previously returned an empty list and was counted as checked
- `QueryResult.is_conclusive`, true when at least one source ran. An empty
  result is only meaningful when it is true. Serialized into the JSON envelope
  so a subprocess consumer does not have to derive it
- `UnsupportedQueryError`, raised by a client that cannot be asked a given
  identifier, as distinct from one that was asked and failed

### Changed
- The CLI exits 1 when no source answered a query, and says so in the output.
  Findings themselves are still reported through the output rather than the
  exit code; this is reserved for a question that went unanswered

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
  names the offending value and the valid sources, and exits 2
- `--sources vulnerablecode` resolved to zero sources and failed with a message
  that called VulnerableCode available. It now selects VulnerableCode, and the
  no-sources error distinguishes selectable fan-out sources from it
- Enabling `use_vulnerablecode` after constructing `VulnerabilityQuery` left a
  path that returned an empty result with no error

## [1.1.0] - 2026-08-17

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