"""Tests for snapshot-based KEV and EPSS enrichment."""

import gzip
import json
from datetime import datetime, timedelta, timezone

import pytest

from vulnq.enrichment import (
    SNAPSHOT_SCHEMA,
    Enricher,
    EPSSReader,
    KEVReader,
    Snapshot,
    build_enricher,
    cve_keys,
    mine_epss,
    mine_kev,
    write_snapshot,
)
from vulnq.enrichment.epss import EPSS_SOURCE
from vulnq.enrichment.kev import KEV_MIN_PLAUSIBLE_RECORDS, KEV_SOURCE
from vulnq.models import Configuration, QueryResult, Vulnerability, VulnerabilitySource
from vulnq.models import IdentifierType


def make_vuln(vuln_id="CVE-2021-44228", aliases=None, source=VulnerabilitySource.OSV):
    """Build a minimal vulnerability for enrichment tests."""
    return Vulnerability(
        id=vuln_id,
        source=source,
        summary="test vulnerability",
        aliases=aliases or [],
    )


def default_kev_records():
    """Build a plausibly-sized KEV catalog holding the CVE under test.

    Padded past KEV_MIN_PLAUSIBLE_RECORDS on purpose: an undersized catalog is
    refused as a broken mine, so a one-row fixture would exercise the wrong
    path in every test that just wants a working join.
    """
    records = {
        "CVE-2021-44228": {
            "date_added": "2021-12-10",
            "known_ransomware": True,
            "required_action": "Apply updates per vendor instructions.",
        }
    }
    for i in range(KEV_MIN_PLAUSIBLE_RECORDS):
        records[f"CVE-2020-{i:04d}"] = {"date_added": "2020-01-01"}
    return records


def write_kev_snapshot(tmp_path, records=None, fetched_at=None, version="2026.08.14"):
    """Write a KEV snapshot to a temp directory and return the directory."""
    snapshot = Snapshot(
        source=KEV_SOURCE,
        version=version,
        fetched_at=fetched_at or datetime.now(timezone.utc),
        records=default_kev_records() if records is None else records,
    )
    write_snapshot(snapshot, str(tmp_path))
    return str(tmp_path)


def write_epss_snapshot(tmp_path, records=None, fetched_at=None, version="2026-08-16"):
    """Write an EPSS snapshot to a temp directory and return the directory."""
    snapshot = Snapshot(
        source=EPSS_SOURCE,
        version=version,
        fetched_at=fetched_at or datetime.now(timezone.utc),
        records=(
            records
            if records is not None
            else {"CVE-2021-44228": {"score": 0.97512, "percentile": 0.99981}}
        ),
    )
    write_snapshot(snapshot, str(tmp_path))
    return str(tmp_path)


class TestCVEKeys:
    """Test join key extraction."""

    def test_cve_in_id(self):
        """A CVE-identified record joins on its own id."""
        assert cve_keys(make_vuln("CVE-2021-44228")) == ["CVE-2021-44228"]

    def test_cve_in_aliases_when_id_is_ghsa(self):
        """De-duplication keeps a GHSA id, so aliases must be searched."""
        vuln = make_vuln("GHSA-jfh8-c2jp-5v3q", aliases=["CVE-2021-44228"])
        assert cve_keys(vuln) == ["CVE-2021-44228"]

    def test_multiple_cve_aliases_all_returned(self):
        """A record with two CVE aliases must offer both as join keys."""
        vuln = make_vuln("GHSA-xxxx", aliases=["CVE-2021-44228", "CVE-2021-45046"])
        assert cve_keys(vuln) == ["CVE-2021-44228", "CVE-2021-45046"]

    def test_ghsa_only_has_no_keys(self):
        """A GHSA with no CVE alias can never be joined."""
        assert cve_keys(make_vuln("GHSA-xxxx", aliases=["GHSA-yyyy"])) == []

    def test_keys_are_normalized_and_deduplicated(self):
        """Case differences must not produce duplicate keys."""
        vuln = make_vuln("cve-2021-44228", aliases=["CVE-2021-44228"])
        assert cve_keys(vuln) == ["CVE-2021-44228"]


class TestSnapshotFormat:
    """Test the shared snapshot document format."""

    def test_roundtrip(self, tmp_path):
        """A written snapshot reloads with its header intact."""
        fetched = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
        path = write_snapshot(
            Snapshot(KEV_SOURCE, "2026.08.14", fetched, {"CVE-1999-0001": {}}), str(tmp_path)
        )

        with gzip.open(path, "rt", encoding="utf-8") as handle:
            document = json.load(handle)

        assert document["schema"] == SNAPSHOT_SCHEMA
        assert document["count"] == 1

        restored = Snapshot.from_document(document)
        assert restored.version == "2026.08.14"
        assert restored.fetched_at == fetched

    def test_unknown_schema_rejected(self):
        """A document from another format must not be silently accepted."""
        with pytest.raises(ValueError):
            Snapshot.from_document({"schema": "something-else", "records": {}})

    def test_age_never_negative(self):
        """A snapshot stamped slightly in the future reports zero age, not negative."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert Snapshot(KEV_SOURCE, "v", future, {}).age_seconds() == 0.0

    def test_undated_snapshot_has_no_age(self):
        """An undated snapshot reports None rather than guessing."""
        assert Snapshot(KEV_SOURCE, "v", None, {}).age_seconds() is None


class TestKEVReader:
    """Test CISA KEV enrichment."""

    def test_cve_in_catalog(self, tmp_path):
        """A listed CVE is stamped with every KEV fact."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is True
        assert vuln.kev_date_added.isoformat() == "2021-12-10"
        assert vuln.kev_known_ransomware is True
        assert vuln.kev_required_action.startswith("Apply updates")

    def test_cve_absent_from_catalog(self, tmp_path):
        """A fresh catalog is exhaustive, so an absent CVE is a real negative."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        vuln = make_vuln("CVE-2019-11111")
        reader.apply([vuln])

        assert vuln.known_exploited is False
        assert vuln.kev_date_added is None

    def test_join_uses_cve_alias(self, tmp_path):
        """A GHSA-identified record joins through its CVE alias."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        vuln = make_vuln("GHSA-jfh8-c2jp-5v3q", aliases=["CVE-2021-44228"])
        reader.apply([vuln])

        assert vuln.known_exploited is True

    def test_missing_snapshot_yields_unknown(self, tmp_path):
        """A missing snapshot must leave the fact unknown, never False."""
        reader = KEVReader(str(tmp_path / "absent"))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is None
        assert reader.provenance().available is False

    def test_stale_snapshot_is_not_joined(self, tmp_path):
        """Past the configured age, a snapshot is refused rather than trusted."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        reader = KEVReader(write_kev_snapshot(tmp_path, fetched_at=old), max_age_days=7)
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is None
        assert reader.provenance().stale is True

    def test_stale_snapshot_joined_when_no_maximum_set(self, tmp_path):
        """With no maximum configured, age is advisory and the join still runs."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        reader = KEVReader(write_kev_snapshot(tmp_path, fetched_at=old))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is True
        assert reader.provenance().stale is False
        assert reader.provenance().age_seconds > 29 * 86400

    def test_ghsa_without_cve_stays_unknown(self, tmp_path):
        """An unjoinable advisory must not be marked not-exploited."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        vuln = make_vuln("GHSA-xxxx", aliases=["GHSA-yyyy"])
        reader.apply([vuln])

        assert vuln.known_exploited is None

    def test_provenance_reports_catalog_version(self, tmp_path):
        """The version joined against is exposed for reproducibility."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        provenance = reader.provenance()

        assert provenance.available is True
        assert provenance.version == "2026.08.14"
        assert provenance.record_count == KEV_MIN_PLAUSIBLE_RECORDS + 1

    def test_snapshot_loaded_once(self, tmp_path):
        """The snapshot is held resident rather than re-read per call."""
        reader = KEVReader(write_kev_snapshot(tmp_path))
        first = reader.load()
        second = reader.load()

        assert first is second


class TestEPSSReader:
    """Test FIRST EPSS enrichment."""

    def test_score_present(self, tmp_path):
        """A scored CVE carries score, percentile, and score date."""
        reader = EPSSReader(write_epss_snapshot(tmp_path))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.epss_score == pytest.approx(0.97512)
        assert vuln.epss_percentile == pytest.approx(0.99981)
        assert vuln.epss_score_date.isoformat() == "2026-08-16"

    def test_cve_absent_stays_none_not_zero(self, tmp_path):
        """Zero is a real EPSS value and must not double as unknown."""
        reader = EPSSReader(write_epss_snapshot(tmp_path))
        vuln = make_vuln("CVE-2019-11111")
        reader.apply([vuln])

        assert vuln.epss_score is None
        assert vuln.epss_percentile is None

    def test_genuine_zero_score_preserved(self, tmp_path):
        """A published 0.0 must survive as 0.0, distinct from a miss."""
        location = write_epss_snapshot(
            tmp_path, records={"CVE-2019-11111": {"score": 0.0, "percentile": 0.0}}
        )
        reader = EPSSReader(location)
        vuln = make_vuln("CVE-2019-11111")
        reader.apply([vuln])

        assert vuln.epss_score == 0.0
        assert vuln.epss_score is not None

    def test_missing_snapshot_yields_none(self, tmp_path):
        """A missing snapshot leaves scores unknown and does not raise."""
        reader = EPSSReader(str(tmp_path / "absent"))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.epss_score is None
        assert reader.provenance().available is False

    def test_stale_snapshot_reports_age(self, tmp_path):
        """A stale snapshot is distinguishable from a fresh one."""
        old = datetime.now(timezone.utc) - timedelta(days=10)
        reader = EPSSReader(write_epss_snapshot(tmp_path, fetched_at=old), max_age_days=3)
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        provenance = reader.provenance()
        assert provenance.stale is True
        assert provenance.age_seconds > 9 * 86400
        assert vuln.epss_score is None

    def test_percentile_preserved_not_recomputed(self, tmp_path):
        """The published percentile is copied verbatim, not derived locally.

        A low percentile on the only scored CVE in a corpus would be impossible
        to reproduce from that corpus alone, so seeing it survive proves it was
        copied rather than recalculated.
        """
        location = write_epss_snapshot(
            tmp_path,
            records={
                "CVE-2021-44228": {"score": 0.5, "percentile": 0.12345},
                "CVE-2019-11111": {"score": 0.9, "percentile": 0.98765},
            },
        )
        reader = EPSSReader(location)
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.epss_percentile == pytest.approx(0.12345)


class TestEPSSParsing:
    """Test the daily CSV parser."""

    def test_parses_header_and_rows(self):
        """The score date comes from the header comment, not the filename."""
        from vulnq.enrichment.epss import _parse_csv

        payload = (
            "#model_version:v2025.03.14,score_date:2026-08-16T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2021-44228,0.975120000,0.999810000\n"
            "cve-2019-11111,0.000420000,0.050000000\n"
        ).encode("utf-8")

        score_date, records = _parse_csv(payload)

        assert score_date == "2026-08-16"
        assert records["CVE-2021-44228"]["score"] == pytest.approx(0.97512)
        # Ids are upper-cased so the join key is stable.
        assert "CVE-2019-11111" in records

    def test_malformed_rows_skipped(self):
        """A bad row must not take the whole snapshot down."""
        from vulnq.enrichment.epss import _parse_csv

        payload = (
            "cve,epss,percentile\n" "CVE-2021-44228,not-a-number,0.9\n" "CVE-2019-11111,0.5,0.5\n"
        ).encode("utf-8")

        _, records = _parse_csv(payload)

        assert "CVE-2021-44228" not in records
        assert "CVE-2019-11111" in records


class TestEnricher:
    """Test the combined enrichment layer."""

    def test_disabled_without_configuration(self):
        """No snapshot configured means no enrichment and no cost."""
        assert build_enricher(Configuration()) is None

    def test_applies_both_sources_and_records_provenance(self, tmp_path):
        """Both joins run and both report where they came from."""
        kev_dir = tmp_path / "kev"
        epss_dir = tmp_path / "epss"
        kev_dir.mkdir()
        epss_dir.mkdir()

        config = Configuration(
            kev_snapshot=write_kev_snapshot(kev_dir),
            epss_snapshot=write_epss_snapshot(epss_dir),
        )
        result = QueryResult(
            query="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            query_type=IdentifierType.PURL,
            vulnerabilities=[make_vuln("CVE-2021-44228")],
        )

        Enricher(config).enrich(result)

        vuln = result.vulnerabilities[0]
        assert vuln.known_exploited is True
        assert vuln.epss_score == pytest.approx(0.97512)
        assert set(result.enrichment) == {KEV_SOURCE, EPSS_SOURCE}
        assert result.enrichment[KEV_SOURCE].version == "2026.08.14"

    def test_none_survives_json_serialization(self, tmp_path):
        """Unknown must reach a subprocess consumer as null, not as 0 or false."""
        config = Configuration(
            kev_snapshot=str(tmp_path / "absent"),
            epss_snapshot=str(tmp_path / "absent"),
        )
        result = QueryResult(
            query="pkg:npm/left-pad@1.0.0",
            query_type=IdentifierType.PURL,
            vulnerabilities=[make_vuln("CVE-2021-44228")],
        )

        Enricher(config).enrich(result)
        payload = json.loads(json.dumps(result.model_dump(mode="json")))

        assert payload["vulnerabilities"][0]["known_exploited"] is None
        assert payload["vulnerabilities"][0]["epss_score"] is None
        assert payload["enrichment"][KEV_SOURCE]["available"] is False


class TestFailureModes:
    """Test that broken snapshots degrade to unknown rather than to a verdict."""

    def test_empty_kev_snapshot_confers_no_negatives(self, tmp_path):
        """A mine that parsed nothing must not mark the world not-exploited."""
        reader = KEVReader(write_kev_snapshot(tmp_path, records={}))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is None
        assert reader.provenance().available is False

    def test_undersized_kev_snapshot_confers_no_negatives(self, tmp_path):
        """A truncated catalog is as dangerous as an empty one."""
        records = {f"CVE-2020-{i:04d}": {"date_added": "2020-01-01"} for i in range(5)}
        reader = KEVReader(write_kev_snapshot(tmp_path, records=records))
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is None

    def test_mine_kev_refuses_implausible_catalog(self, monkeypatch):
        """An upstream schema change must fail the mine, not publish an empty one."""

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                # "vulnerabilities" renamed upstream: every row is lost.
                return {"catalogVersion": "2026.08.14", "items": [{"cveID": "CVE-2021-44228"}]}

        monkeypatch.setattr("vulnq.enrichment.kev.requests.get", lambda *a, **k: FakeResponse())

        with pytest.raises(ValueError, match="below the plausible floor"):
            mine_kev()

    def test_corrupt_record_does_not_kill_the_query(self, tmp_path):
        """One bad published snapshot must not take vulnerability results down."""
        location = write_epss_snapshot(tmp_path, records={"CVE-2021-44228": "not-a-record"})
        reader = EPSSReader(location)
        vuln = make_vuln("CVE-2021-44228")

        reader.apply([vuln])  # must not raise

        assert vuln.epss_score is None
        assert reader.provenance().available is False

    def test_undated_snapshot_fails_a_configured_freshness_gate(self, tmp_path):
        """Freshness that cannot be proven does not pass a gate that demands it."""
        write_snapshot(
            Snapshot(KEV_SOURCE, "2026.08.14", None, default_kev_records()), str(tmp_path)
        )
        reader = KEVReader(str(tmp_path), max_age_days=7)
        vuln = make_vuln("CVE-2021-44228")
        reader.apply([vuln])

        assert vuln.known_exploited is None
        assert reader.provenance().stale is True

    def test_unparseable_fetched_at_is_refused(self):
        """A corrupt timestamp must not silently become "no age"."""
        with pytest.raises(ValueError, match="fetched_at"):
            Snapshot.from_document(
                {
                    "schema": SNAPSHOT_SCHEMA,
                    "source": KEV_SOURCE,
                    "fetched_at": "not-a-date",
                    "records": {},
                }
            )

    def test_invalid_max_age_env_is_loud(self, monkeypatch):
        """Silently ignoring this would disable a gate the operator switched on."""
        from vulnq.core import VulnerabilityQuery

        monkeypatch.setenv("VULNQ_SNAPSHOT_MAX_AGE_DAYS", "7d")

        with pytest.raises(ValueError, match="must be an integer"):
            VulnerabilityQuery.load_config()

    def test_presigned_url_query_string_is_preserved(self, monkeypatch):
        """Appending after a query string would break every S3 and GCS URL."""
        from vulnq.enrichment import snapshot as snapshot_module

        seen = {}

        class FakeResponse:
            content = b""

            def raise_for_status(self):
                return None

        def fake_get(url, timeout=None):
            seen["url"] = url
            return FakeResponse()

        monkeypatch.setattr(snapshot_module.requests, "get", fake_get)
        try:
            snapshot_module._read_document(
                "https://bucket.s3.amazonaws.com/snaps?X-Amz-Signature=abc",
                "cisa-kev.json.gz",
                30,
            )
        except Exception:
            pass  # the empty body fails to decompress; the URL is what matters

        assert seen["url"] == (
            "https://bucket.s3.amazonaws.com/snaps/cisa-kev.json.gz?X-Amz-Signature=abc"
        )

    def test_mine_epss_explicit_date_is_not_substituted(self, monkeypatch):
        """A named day must be fetched exactly, not silently swapped for another."""
        from datetime import date

        attempted = []

        def fake_get(url, timeout=None):
            attempted.append(url)
            import requests as requests_module

            raise requests_module.RequestException("404")

        monkeypatch.setattr("vulnq.enrichment.epss.requests.get", fake_get)

        with pytest.raises(Exception):
            mine_epss(score_date=date(2026, 8, 17))

        assert len(attempted) == 1

    def test_mine_epss_falls_back_past_a_corrupt_file(self, monkeypatch):
        """A corrupt file for one day is what the walk-back exists to survive."""
        import gzip as gziplib

        calls = []

        class FakeResponse:
            def __init__(self, content):
                self.content = content

            def raise_for_status(self):
                return None

        def fake_get(url, timeout=None):
            calls.append(url)
            if len(calls) == 1:
                # Downloads fine, then decompresses to garbage.
                return FakeResponse(b"not-gzip-at-all")
            payload = (
                "#model_version:v1,score_date:2026-08-16T00:00:00+0000\n"
                "cve,epss,percentile\n"
                "CVE-2021-44228,0.9,0.99\n"
            ).encode("utf-8")
            return FakeResponse(gziplib.compress(payload))

        monkeypatch.setattr("vulnq.enrichment.epss.requests.get", fake_get)
        snapshot = mine_epss()

        assert len(calls) == 2
        assert snapshot.records["CVE-2021-44228"]["score"] == pytest.approx(0.9)

    def test_concurrent_first_load_sees_the_snapshot(self, tmp_path):
        """A second thread arriving mid-load must not observe an absent snapshot."""
        import threading

        reader = KEVReader(write_kev_snapshot(tmp_path))
        results = []

        def query():
            vuln = make_vuln("CVE-2021-44228")
            reader.apply([vuln])
            results.append(vuln.known_exploited)

        threads = [threading.Thread(target=query) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert results == [True] * 8


class TestCoreWiring:
    """Test that enrichment reaches every query path."""

    def test_enriches_multi_source_path(self, tmp_path, monkeypatch):
        """The de-duplicated multi-source path is enriched."""
        from vulnq.core import VulnerabilityQuery

        config = Configuration(kev_snapshot=write_kev_snapshot(tmp_path))
        engine = VulnerabilityQuery(config=config)

        async def fake_sources(identifier, id_type, package_info, result):
            return [make_vuln("CVE-2021-44228"), make_vuln("CVE-2021-44228")]

        monkeypatch.setattr(engine, "_query_all_sources", fake_sources)
        result = engine.query("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")

        # Found twice, de-duplicated to one, stamped once.
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].known_exploited is True
        assert result.enrichment[KEV_SOURCE].available is True

    def test_enriches_findings_from_vulnerablecode(self, tmp_path, monkeypatch):
        """It used to take its own path that returned early, and enrichment
        had to be reached from both. There is one path now, and this pins that
        a VulnerableCode-only query still gets enriched."""
        from vulnq.core import VulnerabilityQuery

        config = Configuration(
            kev_snapshot=write_kev_snapshot(tmp_path),
            sources=[VulnerabilitySource.VULNERABLECODE],
        )
        engine = VulnerabilityQuery(config=config)
        client = engine._clients[VulnerabilitySource.VULNERABLECODE]

        async def no_session():
            return None

        async def one_finding(purl):
            return [make_vuln("CVE-2021-44228")]

        monkeypatch.setattr(client, "start_session", no_session)
        monkeypatch.setattr(client, "close_session", no_session)
        monkeypatch.setattr(client, "query_purl", one_finding)

        result = engine.query("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")

        assert result.vulnerabilities[0].known_exploited is True
        assert result.enrichment[KEV_SOURCE].available is True
        assert result.sources_checked == [VulnerabilitySource.VULNERABLECODE]

    def test_env_configures_snapshots(self, tmp_path, monkeypatch):
        """A subprocess caller can only reach configuration through the env."""
        from vulnq.core import VulnerabilityQuery

        monkeypatch.setenv("VULNQ_KEV_SNAPSHOT", write_kev_snapshot(tmp_path))
        monkeypatch.setenv("VULNQ_SNAPSHOT_MAX_AGE_DAYS", "7")

        config = VulnerabilityQuery.load_config()

        assert config.kev_snapshot.endswith(str(tmp_path))
        assert config.snapshot_max_age_days == 7

    def test_no_enricher_without_snapshots(self):
        """An unconfigured engine pays nothing and reports no provenance."""
        from vulnq.core import VulnerabilityQuery

        engine = VulnerabilityQuery(config=Configuration())
        assert engine._enricher is None


class TestMining:
    """Test the mining entry points against stubbed HTTP responses."""

    def test_mine_kev_normalizes_catalog(self, monkeypatch):
        """The catalog is reshaped into CVE-keyed records with a version."""

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                entries = [
                    {
                        "cveID": "CVE-2021-44228",
                        "dateAdded": "2021-12-10",
                        "knownRansomwareCampaignUse": "Known",
                        "requiredAction": "Apply updates.",
                    },
                    {
                        "cveID": "CVE-2019-11111",
                        "dateAdded": "2019-01-01",
                        "knownRansomwareCampaignUse": "Unknown",
                        "requiredAction": "Apply updates.",
                    },
                    {"cveID": ""},
                ]
                # Padded past the plausibility floor so this exercises
                # normalization rather than the undersized-catalog refusal.
                entries += [
                    {"cveID": f"CVE-2020-{i:04d}", "dateAdded": "2020-01-01"}
                    for i in range(KEV_MIN_PLAUSIBLE_RECORDS)
                ]
                return {"catalogVersion": "2026.08.14", "vulnerabilities": entries}

        monkeypatch.setattr("vulnq.enrichment.kev.requests.get", lambda *a, **k: FakeResponse())
        snapshot = mine_kev()

        assert snapshot.version == "2026.08.14"
        # The two named rows plus the padding; the blank cveID is dropped.
        assert snapshot.count == KEV_MIN_PLAUSIBLE_RECORDS + 2
        assert snapshot.records["CVE-2021-44228"]["known_ransomware"] is True
        # "Unknown" is unestablished, not a denial.
        assert snapshot.records["CVE-2019-11111"]["known_ransomware"] is None

    def test_mine_epss_falls_back_to_previous_day(self, monkeypatch):
        """Today's file may not be published yet; yesterday's is still valid."""
        import gzip as gziplib

        attempted = []

        class FakeResponse:
            def __init__(self, content):
                self.content = content

            def raise_for_status(self):
                return None

        def fake_get(url, timeout=None):
            attempted.append(url)
            if len(attempted) == 1:
                import requests as requests_module

                raise requests_module.RequestException("404")
            payload = (
                "#model_version:v1,score_date:2026-08-16T00:00:00+0000\n"
                "cve,epss,percentile\n"
                "CVE-2021-44228,0.9,0.99\n"
            ).encode("utf-8")
            return FakeResponse(gziplib.compress(payload))

        monkeypatch.setattr("vulnq.enrichment.epss.requests.get", fake_get)
        snapshot = mine_epss()

        assert len(attempted) == 2
        # The version comes from the published header, not the attempted date.
        assert snapshot.version == "2026-08-16"
        assert snapshot.records["CVE-2021-44228"]["score"] == pytest.approx(0.9)
