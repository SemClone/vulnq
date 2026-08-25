"""A declared field that is always empty says the wrong thing.

`cwe_ids` was hardcoded to an empty list in the OSV and VulnerableCode
clients, under a comment claiming OSV does not provide them. OSV does: the
classification sits in `database_specific.cwe_ids`, which is where
GitHub-sourced advisories put it. Always empty, the field read as "this
advisory has no classification" rather than "we did not extract one".

That distinction carries weight here. CWE-506 is Embedded Malicious Code and
CWE-912 is Hidden Functionality, and together they are what separates a
package that IS malware from one whose description merely mentions malicious
input.
"""

import pytest

from vulnq.clients.base import BaseClient
from vulnq.clients.osv import OSVClient
from vulnq.clients.vulnerablecode import VulnerableCodeClient


@pytest.mark.parametrize(
    "raw,expected",
    [
        (["CWE-506", "CWE-912"], ["CWE-506", "CWE-912"]),
        (["cwe-506"], ["CWE-506"]),
        ([{"cwe_id": "CWE-79"}], ["CWE-79"]),
        ([{"cwe_id": 79}], ["CWE-79"]),
        ([{"cweId": "CWE-89"}], ["CWE-89"]),
        ([79], ["CWE-79"]),
        (["CWE-506", "CWE-506"], ["CWE-506"]),
        (["NOT-A-CWE", "CWE-22"], ["CWE-22"]),
        ([{"name": "no identifier here"}], []),
        ([], []),
        (None, []),
        ("CWE-506", []),
        ([None, "", {}], []),
    ],
)
def test_every_shape_a_source_uses_is_read(raw, expected):
    """OSV writes strings, VulnerableCode objects whose cwe_id may be a bare
    integer, GitHub objects with a cweId. Anything that is not a CWE
    identifier is dropped rather than reported as one."""
    assert BaseClient._normalize_cwe_ids(raw) == expected


def test_osv_reads_the_block_the_classification_lives_in():
    """The shape api.osv.dev returns for GHSA-pjwm-rvh2-c87w, the ua-parser-js
    malware advisory."""
    vuln = OSVClient()._parse_vulnerability(
        {
            "id": "GHSA-pjwm-rvh2-c87w",
            "summary": "Embedded malicious code in ua-parser-js",
            "database_specific": {
                "cwe_ids": ["CWE-506", "CWE-912"],
                "severity": "HIGH",
                "github_reviewed": True,
            },
        }
    )
    assert vuln.cwe_ids == ["CWE-506", "CWE-912"]


def test_an_advisory_with_no_classification_still_reports_none():
    """Empty must remain possible, or the field means something new."""
    vuln = OSVClient()._parse_vulnerability(
        {"id": "PYSEC-1", "summary": "x", "database_specific": {"severity": "HIGH"}}
    )
    assert vuln.cwe_ids == []


def test_an_advisory_with_no_database_specific_block_does_not_raise():
    vuln = OSVClient()._parse_vulnerability({"id": "PYSEC-2", "summary": "x"})
    assert vuln.cwe_ids == []


def test_malware_is_separable_from_a_description_mentioning_malice():
    """The point of the field, stated as the test.

    Prose matching fails in both directions: a credentials leak "via malicious
    URLs" is not malware, and a genuinely compromised package need not use the
    word at all.
    """
    malware = OSVClient()._parse_vulnerability(
        {
            "id": "GHSA-pjwm-rvh2-c87w",
            "summary": "Embedded malicious code in ua-parser-js",
            "database_specific": {"cwe_ids": ["CWE-506", "CWE-912"]},
        }
    )
    not_malware = OSVClient()._parse_vulnerability(
        {
            "id": "GHSA-9hjg-9r4m-mvj7",
            "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
            "database_specific": {"cwe_ids": ["CWE-522"]},
        }
    )

    malware_classifications = {"CWE-506", "CWE-912"}
    assert malware_classifications & set(malware.cwe_ids)
    assert not malware_classifications & set(not_malware.cwe_ids)
