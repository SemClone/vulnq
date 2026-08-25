# Changelog

All notable changes to vulnq will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- OSV CVSS scores were invented. The client did not parse the vector: it
  checked it for a handful of substrings and picked one of four hardcoded
  numbers, ignoring attack vector, privileges required, user interaction and
  scope entirely. `AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N` scores 4.2 and was
  reported as 9.0 CRITICAL, because it contains `/C:H` and `/AC:L`. The number
  sat in the same field as NVD's real scores, so anything sorting or gating on
  it was acting on a value nobody computed. Base scores are now computed from
  the vector per the CVSS 3.1 specification, checked against 235 published NVD
  records. CVSS 4.0 scores through a lookup table and 2.0 uses different
  metrics, so neither is approximated: the vector is reported and the score is
  left empty. `severity` now follows the computed score rather than being
  guessed alongside it, and a database's own label no longer overrules a score
  derived from the vector. A vector that states a base metric twice is refused
  rather than scored from the first value. A CVSS 2.0 vector, which the OSV
  schema allows and which carries no `CVSS:` prefix, is now recognised and
  reported rather than discarded by the prefix check; no live OSV record
  carries one today, so that part is defensive
- A score of `0.0` was treated as a missing score. It is a computed result
  meaning no impact, and falsy checks made it indistinguishable from never
  scored: the table and markdown printed `-` and `N/A` for it, the merge
  overwrote it with another source's score, and the GitHub, NVD and
  VulnerableCode clients skipped deriving a severity from it
- GitHub returns a score of `0.0` with a null vector for an advisory it never
  scored, and about one PyPI advisory in eight arrives that way. It was stored
  as a real score, so a finding GitHub rated HIGH reported `cvss_score: 0.0`,
  blocked another source's real score during the merge, and read to any
  downstream gate as harmless. A genuine zero always carries the vector it was
  computed from, so a bare `0.0` is now an absent score. VulnerableCode had the
  same shape, defaulting a missing `value` to `0`
- A score arriving as a string failed the whole source. Sources disagree about
  the type: NVD and GitHub send a JSON number that is int or float depending on
  whether it has a fraction, OSV sends a string, VulnerableCode sends either.
  A string reached `cvss_to_severity` and raised `TypeError`, which is not
  caught per advisory, so one odd record turned a working GitHub or NVD query
  into a reported failure. Every source now goes through one coercion that
  accepts int, float and numeric string, and rejects booleans, NaN, infinity
  and anything outside the 0 to 10 range a CVSS score occupies
- VulnerableCode's CVSS branch never ran. It matched the scoring system name
  `cvss_v3`, where VulnerableCode writes `cvssv3` and `cvssv3.1`. Worse, the
  fallback took the first positive value from any scoring system, so an EPSS
  row, a probability between 0 and 1, could land in `cvss_score`: a 0.97
  likelihood of exploitation was reported as a CVSS score of 0.97, which reads
  as LOW. Only CVSS systems fill the CVSS field now, newest specification
  first, and a textual rating from any system still sets the severity
- Scores render to one decimal in the table and in markdown, so the column
  lines up and a float artifact cannot reach the output
- A merged record could carry one source's score beside another source's
  severity, reporting `9.8` next to `UNKNOWN`. A score, its vector and its
  severity are now taken together
- `--min-severity` silently discarded every finding the source had not rated.
  UNKNOWN was absent from the ordering table, so it scored below NONE and fell
  out of any filter. OSV records frequently carry no severity, so this was
  routine: filtering `pkg:pypi/django@3.2.0` to high dropped unrated advisories
  with nothing said about it. Unrated findings are now always kept, and the
  number withheld by the filter is reported in `warnings`. The two severity
  ordering tables, one in the filter and one in the result sort, are now one
- VulnerableCode findings were labelled `source: osv`. The envelope
  contradicted itself, with `sources_checked` naming `vulnerablecode` while
  every record inside credited a database that was never queried. It also left
  the VulnerableCode entry in the merge priority table unreachable

### Fixed
- Piping into vulnq did not work, and the README documented three ways to do
  it. `--input` was declared `click.Path(exists=True)` without `allow_dash`, so
  click rejected `-` as a nonexistent path before the branch that handles it
  could run, and vulnq never read standard input without `--input` at all. Both
  work now: `--input -` and a bare pipe. Blank lines and `#` comments in an
  identifier list are ignored. A terminal with no arguments still gets the
  usage error rather than waiting silently for input. A closed descriptor,
  where Python leaves `sys.stdin` as `None`, is treated as no input rather
  than raising; input that is not UTF-8 text, such as a piped archive, is
  named as such rather than dumping a decode traceback, on any platform:
  whether an undecodable byte raises depends on the locale, and under
  surrogateescape it would otherwise have been queried as an identifier; and
  a byte order mark
  on the first line of a list written on Windows no longer rides into the
  first identifier
- The README's three SEMCL.ONE pipe recipes did not work end to end even once
  the pipe mechanics were fixed. `src2purl` writes its banner to standard
  output alongside a rendered table, `upmex` takes a subcommand rather than a
  bare path, and raw SBOM JSON is not a list of identifiers, so each line was
  queried as one. They are replaced with recipes that were run before being
  written down, and the src2purl limitation is stated rather than papered over

### Fixed
- Version lists came out in a different order on every run. `affected_versions`
  and `fixed_versions` were deduplicated with `list(set(...))` in five places,
  and Python randomizes string hashing per process, so two scans of the same
  package could not be diffed without phantom changes and nothing downstream
  could checksum the envelope. They are sorted now
- `_queried_version` was copied between two clients and the timestamp parser
  between six places across three, each in a bare `try/except`, so a fix to one
  left the others as they were. Both now live on `BaseClient`

### Removed
These are breaking changes to the importable surface, so the next release is a
major one. Each had no caller inside vulnq, but a library consumer importing
from `vulnq.utils` or reading `QueryResult.metadata` will need to change. Note
that `QueryResult(..., metadata={...})` is now ignored rather than rejected.

- Code nothing called: `utils.normalize_version`, `utils.severity_to_score`,
  `utils.score_to_severity` which duplicated `BaseClient.cvss_to_severity`,
  `BaseClient.generate_vuln_id`, `OSVClient._parse_response`, and
  `VulnerabilityQuery.query_hash`, which had no callers and always returned an
  error envelope
- `QueryResult.metadata`, which was never populated and always serialized as
  `{}`, though the README's example showed it filled in
- The `is_fixed` parameter of `VulnerableCodeClient._parse_vulnerability`,
  accepted and never read
- The README's claim of config file support, and the `pyyaml` and `jsonschema`
  dependencies that only existed to back it. There was no `--config`, no
  `VULNQ_CONFIG`, no parser and no path anything looked in, so tokens or limits
  put in the advertised file were silently ignored. vulnq is configured through
  environment variables and flags

### Added
- `VULNQ_DISABLED_SOURCES` and `--disable-source`. A source named there is not
  queried whatever else selects it, and is reported in `sources_skipped` with
  the reason rather than dropped, so an answer never reads as complete when a
  feed was switched off. Disabling every selected source is a configuration
  error, not a clean scan. Upstreams change hands, gate, or withdraw an API,
  and turning one off should not need a code change

### Changed
- A source is now declared once, in `vulnq/sources.py`: its client, whether it
  joins the default fan-out, its merge priority. It used to be named across
  seven files
- VulnerableCode is an ordinary source. It replaced the whole fan-out rather
  than joining it, which accounted for fifteen of those sites and a duplicate
  query path in `core.py` that drifted from the one beside it. That drift is
  how its findings came to be labelled as coming from OSV. `--sources
  vulnerablecode` now joins the others, a combination the tool could not
  express before, and `--use-vulnerablecode` keeps working as an alias for
  querying only VulnerableCode
- `Configuration.use_vulnerablecode` is replaced by selecting the source. The
  `USE_VULNERABLECODE` environment variable keeps working
- `QueryResult.filter_by_severity` returns `(kept, withheld)` rather than a
  list, so a caller can report what a filter removed instead of presenting a
  shortened list as the whole answer. JSON output is unaffected

### Removed
- `cache_enabled`, `cache_dir`, `cache_ttl`, the `--no-cache` flag, the
  `VULNQ_CACHE_DIR` and `VULNQ_CACHE_TTL` environment variables and the
  `cache` extra. Nothing read any of them and `diskcache` was never imported,
  so every run re-queried every source. `--no-cache` forced nothing and
  `cache_ttl` bounded no staleness. Caching belongs at the layer that runs
  vulnq in bulk, not inside a single query

### Fixed
- PyPI names were not normalized per PEP 503. Dots were left alone where
  underscores and case were folded, so `zope.interface` and `zope_interface`
  named one distribution but reported two different purls. `package_info.name`
  and `package_info.purl` now carry the canonical name for every legal
  spelling, and `query` still echoes the string the caller passed.

  Note this goes further than the purl spec, which folds underscore and case
  for `pkg:pypi` but leaves the dot alone. A purl vulnq reports may therefore
  not string-match one emitted by a spec-conformant tool. PyPI resolving every
  spelling to one distribution is the property that matters for deduplicating
  findings, which is what this identity is for.

  Normalization is deliberately limited to identity: the sources are still
  asked about the spelling they were given. Folding the dot before the query
  is not safe, because GitHub keys its advisory database by the as-published
  PyPI name and folds case but not separators.
  `products.pluggableauthservice` holds three advisories where
  `products-pluggableauthservice` holds none, so normalizing first would turn
  those three into a clean scan with `github` still listed in
  `sources_checked`.

  Underscores are a separate matter and are unchanged here. packageurl folds
  them while parsing, so the GitHub client, which builds its name from the
  parsed purl, asks about `scikit-learn` for `pkg:pypi/scikit_learn`; OSV and
  VulnerableCode pass the purl through and do see the underscore. That split
  is the same before and after this release, and for GitHub the fold matches
  what GHSA stores anyway.

- `Vulnerability` carried a class-based `Config` with `json_encoders`. Both are
  removed in pydantic v3, so the model would have stopped building on upgrade.
  Timestamps now go through a `field_serializer` that keeps the existing
  `+00:00` spelling, which pydantic's own default would have changed to `Z`.
  `pydantic` is pinned below 3 until compatibility with it can be tested
  against a real release.

- `max_concurrent` was configurable and ignored: the request semaphore was
  hardcoded to five, and `VULNQ_MAX_CONCURRENT` was documented in the README
  but never read. Both now reach the semaphore. The default is still five, so
  nothing changes unless it is set, and a value below one is refused at
  construction rather than deadlocking on `Semaphore(0)`

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
- GitHub answers were cut off at the first 100 advisories with nothing said
  about it. `tensorflow` reported 27 of 1324. Results are now paged through,
  and hitting the page cap is reported as an incomplete answer
- Maven qualifiers the ranking table does not recognise — calendar versions
  like `2024.Q1.2`, vendor suffixes like `4.21.0-liferay.9` — were ranked by
  raw text, which sorted `q1.2` after `q1.12` and excluded versions that were
  inside the range. `release.dxp.bom@2024.Q1.2` reported a clean scan against
  ten applicable advisories. An unrankable qualifier is now undecidable, so
  the advisory is reported as unconfirmed instead of dropped
- RubyGems versions were compared with semver rules, but Gem tokenizes digit
  and letter runs, so `pre2` sorted after `pre12`. `avo@3.0.0.pre2` was
  dropped from two advisories it is affected by. Gem now has its own ordering
- Build metadata was discarded as semver requires, but several ecosystems
  carry meaning in it: `11.0.6+security-01` is the *patched* build of 11.0.6
  and was reported as a confirmed match for `<= 11.0.6`. Build metadata is now
  undecidable when it is the only thing left to order by. It still cannot
  overturn a difference in the release numbers, and Go's `+incompatible` — a
  module-path marker Go's own ordering ignores — is not treated as metadata
- OSV stopped at the first page of results and dropped its `next_page_token`,
  so a package with thousands of records reported the first 3000 as the whole
  answer. Pages are now followed
- NVD reported the first 100 records of a larger result with nothing said
  about it: a kernel CPE returned 100 of 6332 as a complete answer. NVD's rate
  limits make paging a query of that size impractical, so the shortfall is
  reported as an incomplete answer instead
- Constructing any client raised `RuntimeError: There is no current event
  loop` on Python 3.8 and 3.9 if the caller had already used `asyncio.run()`,
  because the concurrency semaphore bound to the current loop at construction.
  An async application integrating vulnq could not build the engine at all.
  The semaphore is now created inside the running loop, and rebuilt when the
  loop changes, so a client reused across queries no longer holds one bound to
  a closed loop

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
- CI runs the test suite on Python 3.8 and 3.11 as well as 3.13. `pyproject`
  has claimed 3.8 support throughout, but only 3.13 was ever exercised, which
  is how the event-loop defect above stayed hidden

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