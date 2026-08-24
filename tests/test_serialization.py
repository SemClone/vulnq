"""The output envelope must survive pydantic v3, byte for byte."""

import json
import pathlib
import warnings
from datetime import date, datetime, timezone

from vulnq.models import Severity, Vulnerability, VulnerabilitySource


def _vuln(**kwargs):
    base = dict(id="CVE-2021-0001", source=VulnerabilitySource.OSV, summary="x")
    base.update(kwargs)
    return Vulnerability(**base)


def test_no_pydantic_deprecations_are_raised():
    """v1-era config is what breaks on v3, so treat any deprecation as failure.

    Both deprecated APIs warn while the class is being built, so the model has
    to be imported fresh to see them. That happens in a subprocess rather than
    through importlib.reload: reloading rebinds Severity and every module-level
    table keyed by it, leaving later tests holding enum members that no longer
    match the ones the reloaded module uses.
    """
    import subprocess
    import sys

    script = """
import warnings, sys
warnings.simplefilter("error", DeprecationWarning)
from datetime import datetime, timezone
import vulnq.models as m
v = m.Vulnerability(id="C", source=m.VulnerabilitySource.OSV, summary="x",
                    published_date=datetime(2021, 10, 22, tzinfo=timezone.utc))
v.model_dump(mode="json")
v.model_dump_json()
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(pathlib.Path(__file__).parent.parent),
    )
    assert proc.returncode == 0, proc.stderr


def test_utc_is_still_spelled_as_an_offset():
    """Consumers have always read +00:00 here. Pydantic's default is Z."""
    vuln = _vuln(
        published_date=datetime(2021, 10, 22, 0, 0, tzinfo=timezone.utc),
        modified_date=datetime(2022, 1, 5, 12, 30, tzinfo=timezone.utc),
    )
    dumped = vuln.model_dump(mode="json")
    assert dumped["published_date"] == "2021-10-22T00:00:00+00:00"
    assert dumped["modified_date"] == "2022-01-05T12:30:00+00:00"
    # model_dump_json goes through the same serializer, so the two agree.
    assert json.loads(vuln.model_dump_json())["published_date"] == dumped["published_date"]


def test_absent_timestamps_stay_null():
    dumped = _vuln().model_dump(mode="json")
    assert dumped["published_date"] is None
    assert dumped["modified_date"] is None


def test_naive_timestamps_are_not_given_an_offset():
    """A naive datetime carries no zone, and inventing one would be a claim."""
    dumped = _vuln(published_date=datetime(2021, 10, 22, 0, 0)).model_dump(mode="json")
    assert dumped["published_date"] == "2021-10-22T00:00:00"


def test_date_only_fields_are_unaffected():
    dumped = _vuln(kev_date_added=date(2021, 11, 3)).model_dump(mode="json")
    assert dumped["kev_date_added"] == "2021-11-03"


def test_unknown_exploitability_stays_none_not_false():
    """None means unknown here. False would read as a verified negative."""
    dumped = _vuln(severity=Severity.HIGH).model_dump(mode="json")
    assert dumped["known_exploited"] is None
    assert dumped["epss_score"] is None


def test_python_mode_dump_still_returns_real_datetimes():
    """json_encoders never touched model_dump(), so neither may its replacement.

    An in-process caller reading model_dump()["published_date"] has always got
    a datetime. Handing back a string instead would break arithmetic on it.
    """
    published = datetime(2021, 10, 22, tzinfo=timezone.utc)
    dumped = _vuln(published_date=published).model_dump()
    assert dumped["published_date"] == published
    assert isinstance(dumped["published_date"], datetime)
