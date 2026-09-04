# Evaluation: keep, fix, or remove VulnerableCode

**Issue:** [#53](https://github.com/SemClone/vulnq/issues/53) ·
**Status:** evaluation only — no behaviour changes in this branch ·
**Date of the probes:** 2026-09-03, against `https://public.vulnerablecode.io/api`

---

## Recommendation

**Remove the source. Deprecate it for one minor release first, then delete it.**

Three measurements decide it, and none of them is about how hard the distro fix
would be:

1. **Removal is cheap and total.** It costs one client file, one test file, one
   fixture directory, and 328 lines across twelve others. Nothing in `core.py`,
   `models.py` or `cli.py` resists it. The suite goes from 539 tests to 471 and
   stays green.
2. **The unique coverage is near-empty, and what there is cannot be trusted.**
   Over fifteen comparable packages in eight ecosystems, VulnerableCode returned
   122 findings against the other three's 152, and missed 66 they carry. Of the
   36 it returned that they did not, 11 are confirmed false positives and 5 are
   confirmed duplicates. The remaining 19 are one package - the Ruby `rails`
   meta-gem - and two of those are 2006 advisories reported against Rails
   5.2.0.
3. **The gap that opened the issue is already covered by a source vulnq queries
   by default.** OSV answers `pkg:deb/...` and `pkg:rpm/...` PURLs today, with
   severities and fixed versions. Teaching VulnerableCode those ecosystems
   would rebuild, worse, an answer vulnq already has.

Removal leaves two real gaps, and neither is a reason to keep the source.
**Alpine** is an OSV-client gap, roughly a day of work — see
[The Alpine gap](#the-alpine-gap-the-only-thing-removal-actually-costs).
**Ruby meta-gems** (`pkg:gem/rails`) are the one place VulnerableCode returns
something no other source does, and it returns it with 2006 advisories attached
— see [section 2](#the-findings-it-returned-that-the-other-three-did-not). Both
are better answered inside vulnq than by keeping a source that is wrong eleven
times out of thirty-six.

---

## 1. What removing it costs

Measured by doing it: the removal was carried out on a scratch copy of the tree
at `c58ffe4`, the suite was run, and the diff was counted.

### Deleted outright

| Path | Size |
|---|---|
| `vulnq/clients/vulnerablecode.py` | 510 lines |
| `tests/test_vulnerablecode_v3.py` | 616 lines, 51 tests |
| `tests/fixtures/vulnerablecode/` | 6 JSON files, 2,869 lines, 132 KB |

### Edited

**328 lines removed, 10 added, across twelve files**, plus about a dozen lines
of README. Nothing needed restructuring; every site was a deletion or a one-line
substitution.

| File | What goes |
|---|---|
| `vulnq/sources.py` | one `SourceSpec` and one import |
| `vulnq/models.py` | the `VULNERABLECODE` enum member, `vulnerablecode_api_key`, `vulnerablecode_url` |
| `vulnq/cli.py` | `--use-vulnerablecode`, `--vulnerablecode-api-key`, `--vulnerablecode-url`, and the `--sources` help text |
| `vulnq/core.py` | the `VULNERABLECODE_API_KEY` / `VULNERABLECODE_URL` / `USE_VULNERABLECODE` environment reads |
| `vulnq/clients/__init__.py` | one import and one `__all__` entry |
| `tests/` (8 files) | see below |
| `README.md` | the source bullet, two sentences elsewhere, one env-var example |

That the registry absorbs it in one `SourceSpec` is not luck. `vulnq/sources.py`
was written for exactly this: *"When a feed changes hands, gates, or starts
charging, the answer should be turning it off, not surgery."* This evaluation is
the first time that claim has been tested, and it holds.

### Tests

**68 tests go: 539 → 471, all passing, no rewrites needed beyond substitution.**

| File | Tests lost | Note |
|---|---|---|
| `test_vulnerablecode_v3.py` | 51 | the whole file |
| `test_source_registry.py` | 8 | fan-out, the `--use-vulnerablecode` alias, the `USE_VULNERABLECODE` env var |
| `test_sources.py` | 4 | selection and combination |
| `test_client_errors.py` | 3 | CPE refusal, failure reporting, skip-is-not-an-error |
| `test_severity_reporting.py` | 1 | source labelling |
| `test_enrichment.py` | 1 | enrichment of a VulnerableCode-only result |
| `test_cwe_extraction.py`, `test_event_loops.py` | 0 | a stale import and one entry in a parametrize list |

Four of those are worth keeping in another source's name rather than losing:
the deduplication-never-lowers-severity test, the disable-list parsing case, the
"core.py does not build clients directly" structural guard, and the
unknown-configuration-key guard. Each rewrites to OSV or NVD in one line — the
scratch removal did exactly that and they still pass.

### What breaks for a caller

Everyone currently passing `--sources vulnerablecode` breaks, and they break
**loudly**, which is the good direction:

```console
$ vulnq pkg:npm/express@4.17.1 --sources vulnerablecode
Unknown source 'vulnerablecode'. Available sources: osv, github, nvd
$ echo $?
2
```

The five surfaces that stop working:

| Surface | After removal |
|---|---|
| `--sources vulnerablecode` | exit 2, names the valid sources |
| `--use-vulnerablecode` | `no such option` from click, exit 2 |
| `USE_VULNERABLECODE=true` | silently ignored — **the one quiet failure** |
| `VULNQ_DISABLED_SOURCES=vulnerablecode` | `UnknownSourceError`, exit 2 |
| `Configuration(sources=[VulnerabilitySource.VULNERABLECODE])` | `AttributeError` |

Only `USE_VULNERABLECODE` fails quietly, and only because `core.py` reads it
with `os.environ.get`. Anyone with it set in a job would start getting the
default fan-out without being told. That single case is the argument for a
deprecation release rather than a straight delete — see [section 5](#5-deprecation-path).

---

## 2. Unique coverage, measured

The question the issue asks: **what does VulnerableCode return that OSV, GitHub
and NVD together do not?**

Sixteen packages across eight ecosystems, each queried twice through the real
CLI — once with `--sources vulnerablecode`, once with `--sources osv --sources
github --sources nvd`. Findings were matched on every CVE, GHSA, PYSEC, GO and
RUSTSEC identifier each record carries.

`pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8` is excluded:
VulnerableCode returned a throttling error for it even at fifteen seconds
between probes, which is itself a finding — one package in sixteen went
unanswered at a spacing chosen to stay inside its rate limit.

| PURL | VulnerableCode | OSV+GitHub+NVD | VC-only | missed by VC |
|---|---|---|---|---|
| `pkg:pypi/django@2.2.0` | 1 | 45 | 0 | 44 |
| `pkg:pypi/requests@2.19.0` | 5 | 5 | 0 | 0 |
| `pkg:pypi/pyyaml@5.1` | 4 | 3 | 1 | 0 |
| `pkg:pypi/jinja2@2.10` | 7 | 6 | 1 | 0 |
| `pkg:pypi/urllib3@1.24.1` | 15 | 12 | 3 | 0 |
| `pkg:npm/lodash@4.17.15` | 7 | 6 | 1 | 0 |
| `pkg:npm/express@4.16.0` | 4 | 4 | 0 | 0 |
| `pkg:npm/minimist@1.2.0` | 3 | 3 | 0 | 0 |
| `pkg:npm/axios@0.21.0` | 35 | 26 | 9 | 0 |
| `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` | 7 | 7 | 0 | 0 |
| `pkg:golang/github.com/gin-gonic/gin@1.6.0` | 0 | 3 | 0 | 3 |
| `pkg:cargo/openssl@0.10.30` | 0 | 19 | 0 | 19 |
| `pkg:gem/rails@5.2.0` | 19 | 0 | 19 | 0 |
| `pkg:composer/laravel/framework@8.0.0` | 12 | 11 | 1 | 0 |
| `pkg:nuget/Newtonsoft.Json@12.0.1` | 3 | 2 | 1 | 0 |
| **total, 15 packages** | **122** | **152** | **36** | **66** |

Two rows deserve reading twice.

**`django@2.2.0`: one finding against forty-five.** VulnerableCode reads affected
status from `affected_by_vulnerabilities` on the package endpoint, and for Django
2.2.0 that list holds exactly one entry. This is the same emptiness the issue
found for distro packages, showing up in an ecosystem VulnerableCode is supposed
to be good at. The distro gap is not a distro problem; it is how that field is
populated.

**`cargo` and `golang`: nothing at all.** Not refused, not throttled — answered,
with zero findings, where OSV and GitHub return 19 and 3. A caller reading
`sources_checked: ["vulnerablecode"]` gets a clean bill for `openssl@0.10.30`.

### The findings it returned that the other three did not

All 36 were resolved against OSV's record for the same advisory identifier.

| Class | Count | What it is |
|---|---|---|
| **False positive** | 11 | The queried version sits **below** every `introduced` boundary OSV records. VulnerableCode carries only the fixed version, so anything below the fix reads as affected |
| **Duplicate** | 5 | The same advisory the other three already returned, under an alias-less record ID, so deduplication cannot join them |
| **`rails` meta-gem** | 19 | Genuinely absent from OSV and GitHub under `pkg:gem/rails` — but 2 of the 19 are 2006 advisories |
| **Unverified** | 1 | `CVE-2022-40482` against `laravel/framework@8.0.0` |

The false positives are the clearest result, because they are not a data gap —
they are an arithmetic error, reproducible on demand:

```console
$ vulnq pkg:pypi/urllib3@1.24.1 --sources vulnerablecode -f json | grep GHSA-hmv2
      "id": "GHSA-hmv2-79q8-fv6g",      # "fixed in 1.25.8", so 1.24.1 is affected
```

```console
$ curl -s https://api.osv.dev/v1/vulns/GHSA-hmv2-79q8-fv6g | jq '.affected[].ranges'
[{"type":"ECOSYSTEM","events":[{"introduced":"1.25.2"},{"fixed":"1.25.8"}]}]
```

CVE-2020-7212 was introduced in 1.25.2. `1.24.1` predates the vulnerability.
Nine of the eleven are `axios@0.21.0` against advisories introduced in 1.0.0 or
later — a package two major versions too old to be affected, reported as
carrying nine vulnerabilities it cannot have.

**The one real find is the `rails` meta-gem.** OSV and GitHub key RubyGems
advisories to the component gem (`actionpack`, `activerecord`), so
`pkg:gem/rails@5.2.0` returns nothing from either. VulnerableCode returns 19.
That is genuine coverage no other source offers — and it arrives with
CVE-2006-4111 and CVE-2006-4112, Rails 1.1-era advisories, reported against
5.2.0 with no fixed version at all. It is a real gap in the other three,
answered by a source that cannot be trusted to answer it correctly. The right
fix is a meta-package expansion in vulnq, not a source that guesses.

### Metadata quality

Coverage is only half of it. A finding without a severity cannot be filtered by
`--min-severity`, and one without aliases cannot be deduplicated at all.

| | VulnerableCode | OSV+GitHub+NVD |
|---|---|---|
| Findings | 122 | 152 |
| With a severity | 88 (72%) | 147 (97%) |
| With a CVSS score | 82 (67%) | 118 (78%) |
| With references | 99 (81%) | 152 (100%) |
| With a CWE classification | 69 (57%) | 142 (93%) |
| With aliases | 85 (70%) | 138 (91%) |

Thirty-four VulnerableCode findings carry no severity, so
`--min-severity high` silently drops them. Thirty-seven carry no aliases, which
is what turns a duplicate into a phantom extra finding — five of the 36 above
are exactly that.

---

## 3. The distro gap is already covered — by a default source

The issue was opened because `--sources vulnerablecode` refuses `deb`, `rpm` and
`apk` PURLs. Before pricing a fix, the obvious question: does anything vulnq
already queries answer them?

**OSV does, today, in the default fan-out, with no code change.**

```console
$ vulnq pkg:deb/debian/curl@7.64.0-4 --sources osv -f json
  sources_checked: ["osv"]   sources_skipped: {}   139 findings
  DEBIAN-CVE-2019-5481  CRITICAL  fixed in 7.66.0-1
  DEBIAN-CVE-2019-5482  CRITICAL  fixed in 7.66.0-1
  DEBIAN-CVE-2021-22945 CRITICAL  fixed in 7.79.1-1
  ...
```

| PURL | OSV findings |
|---|---|
| `pkg:deb/debian/curl@7.64.0-4` | 139 |
| `pkg:rpm/redhat/openssl@1.1.1k-7.el8_6` | 118 |
| `pkg:deb/ubuntu/curl@7.68.0-1ubuntu2` | 93 |
| `pkg:apk/alpine/openssl@1.1.1q-r0` | **0** |

Severities, fixed versions, and `DEBIAN-`/`UBUNTU-`/`RHSA-` advisory identities,
in one request, from a source that is already on by default and already outranks
VulnerableCode at merge time.

That first row is the exact PURL from the issue's worked example.
VulnerableCode's own answer for the same coordinate — nothing, under any
spelling — is in [section 4](#4-what-the-fix-would-have-to-overcome).

One caveat worth recording: adding the `distro=` qualifier **narrows** OSV's
answer rather than sharpening it — `pkg:deb/debian/curl@7.64.0-4?distro=buster`
returns 9, all `DLA-` records, against 139 for the bare coordinate. Whatever
closes the Alpine gap should not start passing `distro=` through for `deb`.

### The Alpine gap: the only thing removal actually costs

`pkg:apk/alpine/...` is the one distro coordinate OSV does not resolve by PURL,
and the data is there under another key:

```console
# By PURL: nothing
$ curl -s https://api.osv.dev/v1/query \
    -d '{"package":{"purl":"pkg:apk/alpine/openssl@1.1.1q-r0"}}'
{}

# By ecosystem name: nine advisories for the same build
$ curl -s https://api.osv.dev/v1/query \
    -d '{"version":"1.1.1q-r0","package":{"name":"openssl","ecosystem":"Alpine:v3.16"}}'
ALPINE-CVE-2022-4304, ALPINE-CVE-2022-4450, ALPINE-CVE-2023-0215,
ALPINE-CVE-2023-0286, ALPINE-CVE-2023-0464, ... (9)
```

So OSV holds Alpine advisories; its PURL index does not reach them. Closing that
means mapping an `apk` PURL's `distro=` qualifier onto the `Alpine:vX.Y`
ecosystem name and querying by name and version instead. That is one branch in
`vulnq/clients/osv.py`, a version comparator that already exists, and a fixture.
Roughly a day, against a source vulnq already queries by default and already
trusts above VulnerableCode.

---

## 4. What the fix would have to overcome

For completeness, the cost of the alternative the issue describes — teaching
VulnerableCode the distro ecosystems by reconstructing affected status from each
package's version history.

First, what the instance actually holds. Probed 2026-09-03:

| PURL asked | Stored as | `affected_by` | `fixing` | `next_non_vulnerable` | advisories |
|---|---|---|---|---|---|
| `pkg:deb/debian/curl@7.64.0-4` | `...?distro=trixie` | **0** | 2 | `7.66.0-1` | 0 |
| `pkg:deb/debian/curl@7.64.0-4?distro=trixie` | same | **0** | 2 | `7.66.0-1` | 2 |
| `pkg:rpm/redhat/openssl@1.1.1k-7.el8_6` | 5 per-arch variants | **0** each | 1 each | `1.1.1k-8.el8_6` | 0 |
| `pkg:apk/alpine/openssl@1.1.1q-r0` | **29** variants | **0** each | 1 each | `1.1.1t-r0` | 0 |
| `pkg:deb/debian/openssl@1.1.1n-0+deb11u3` | `...?distro=trixie` | **0** | 0 | `1.1.1n-1` | 0 |

`affected_by_vulnerabilities` is empty for every distro build probed, while
`next_non_vulnerable_version` is populated for every one — the instance knows
these builds are still vulnerable and does not say so in the field a client
reads. Alpine stores **29** variants of one build; Red Hat stores five.

The two advisories the `?distro=trixie` spelling returns for `curl@7.64.0-4` are
CVE-2019-5435 and CVE-2019-5436, and they appear in `fixing_vulnerabilities`.
The issue's own worked example is a **fixed** build.

Three things have to be true for that fix to work, and none of them is:

1. **`affected_by_vulnerabilities` would have to be populated.** It is empty for
   every distro build probed.
2. **Affected would have to be distinguishable from fixing.** The advisory
   endpoint matches a PURL without saying which relation it is, so the issue's
   own worked example — `curl@7.64.0-4` matching CVE-2019-5435 and CVE-2019-5436
   — is the *fix*, not the vulnerability.
3. **The `distro=` qualifier would have to be derivable.** It is not derivable
   from an SBOM's PURL; it can only be discovered by asking the package endpoint
   and reading back what it echoes — one extra request per query, against ten
   requests a minute.

Reconstructing affected status means fetching every stored version of the
package, sorting them with per-ecosystem comparators (`deb`, `rpm` and `apk` each
sort differently — `rpm` needs epoch handling, `apk` needs the `-rN` suffix), and
inferring the affected interval from where the fixing builds sit. Estimate:

| Piece | Cost |
|---|---|
| `distro=` discovery via the package endpoint | 1 extra request per query |
| Per-ecosystem version comparators | `vulnq/versions.py` has some of this; `rpm` epochs and `apk` revisions do not exist yet |
| Version-history fetch and interval inference | 1–2 extra requests per query, plus the paging already at `MAX_PAGES = 25` |
| Red Hat's per-architecture storage | five stored variants for one build, all needing reconciliation |
| Fixtures and tests for three ecosystems | comparable to the 616-line file that exists for the ecosystems it already handles |

Call it a week, ending at **three to four requests per query against a
ten-request-a-minute budget** — under two queries a minute anonymously — to
reproduce, less reliably, an answer OSV already gives in one request.

---

## 5. Deprecation path

**Deprecate for one minor release, then remove.** Not a straight delete, and the
reason is narrow and specific: `USE_VULNERABLECODE=true` is read with
`os.environ.get` and would start being ignored in silence. Every other surface
fails loudly on its own.

**1.6.0 — deprecate.** Keep the source working. Emit a warning to stderr on any
path that selects it:

```
warning: the vulnerablecode source is deprecated and will be removed in 2.0.
  Its ecosystems are covered by osv, github and nvd, which vulnq queries by
  default. See docs/evaluations/vulnerablecode.md
```

Fire it from three places: `--sources vulnerablecode`, `--use-vulnerablecode`,
and the `USE_VULNERABLECODE` environment read in `core.py`. The last one matters
most and is the only one that cannot be discovered any other way.

**2.0.0 — remove.** Carry out section 1. Keep `"vulnerablecode"` accepted by
`parse_disabled` as a no-op for one further release, so a job with
`VULNQ_DISABLED_SOURCES=vulnerablecode` baked in does not start exiting 2 for
switching off something that no longer exists.

The deprecation release costs about thirty lines and three tests.

---

## 6. Replacing it

The issue asks what it would cost to replace VulnerableCode with **REI**.

**REI could not be identified.** It appears nowhere in this repository, in the
`SemClone` organisation, or in public vulnerability-data tooling. This section
therefore states the contract any replacement has to meet, so the answer is a
short one once REI is named.

### What a replacement has to provide

VulnerableCode's slot in vulnq is narrow. A replacement needs exactly this:

| Requirement | Why |
|---|---|
| PURL-keyed lookup, version included | `BaseClient.query_purl` is the only entry point; a CPE-only source is an NVD, not a fourth source |
| Affected **and** fixed, distinguished | the whole reason the distro fix is blocked |
| Severity, CVSS vector, CWE, references | `Vulnerability` carries them; a source that omits them contributes nothing over OSV |
| CVE or GHSA aliases on every record | deduplication and merge priority are alias-keyed; a record with no aliases becomes a phantom finding (see section 2) |
| A rate limit above two queries a minute | anything less cannot serve an SBOM |

A source meeting that contract is one `SourceSpec` and one client — the same
shape as the removal, in reverse. Call it a week for the client, its fixtures
and its tests, plus whatever the source's own quirks cost.

### What it would have to beat

Not VulnerableCode. **OSV, GitHub and NVD together**, which is what a fourth
source has to add to. On the evidence in section 2 that bar is high: the three
returned 152 findings where VulnerableCode returned 122, with a severity on 147
of them and a CWE classification on 142.

### The circular-dependency check

If REI is a consolidation layer that consumes `vulnq` as an input, it cannot be
a `vulnq` source — the dependency runs the other way. In that case the answer to
this issue is simply section 1, with no replacement at all: remove the source,
close the Alpine gap in the OSV client, and let the consolidation layer consume
the result.

---

## 7. Removal versus the fix, side by side

| | Remove | Fix the distro gap |
|---|---|---|
| Work | 328 lines deleted, 3 paths gone, 1 day | ~1 week |
| Requests per query | −2 | 3–4, against 10/min |
| Findings gained | 0 | 0 that OSV does not already return for `deb` and `rpm` |
| Findings lost | 19, all one package (`pkg:gem/rails`), 2 of them from 2006 | — |
| Findings *stopped* | 11 confirmed false positives, 5 phantom duplicates | — |
| Ecosystems newly covered | none (Alpine, via the OSV client, for ~1 day more) | `deb`, `rpm`, `apk` — two of which OSV already answers |
| Maintenance after | none | a v3 API that already withdrew a v1, plus three version comparators |
| Risk | callers using an opt-in, non-default source break loudly | reports clean for genuinely vulnerable packages, quietly |

Removal wins on every column. The fix's best case is a slower, rate-limited,
second-hand version of an answer vulnq already has.

---

## Reproducing the probes

Every number above came from the live API on 2026-09-03. To re-run:

```bash
# Unique coverage: one package, both ways
vulnq pkg:pypi/urllib3@1.24.1 --sources vulnerablecode -f json
vulnq pkg:pypi/urllib3@1.24.1 --sources osv --sources github --sources nvd -f json

# The distro coordinate from the issue, through a default source
vulnq pkg:deb/debian/curl@7.64.0-4 --sources osv -f json

# What VulnerableCode holds for the same coordinate
curl -s -X POST https://public.vulnerablecode.io/api/v3/packages/ \
  -H 'User-Agent: VCIO_API_AGENT' -H 'Content-Type: application/json' \
  -d '{"purls":["pkg:deb/debian/curl@7.64.0-4"],"details":true}'
```

The public instance throttles anonymous callers at ten requests a minute and
each vulnq query costs two, so leave fifteen seconds between VulnerableCode
probes or the answers come back as throttling errors rather than data.
