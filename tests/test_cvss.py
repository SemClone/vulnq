"""CVSS base scores are computed, or not reported.

The client used to invent a score by grepping the vector for a few substrings,
ignoring AV, PR, UI and S entirely. The number landed in the same field as
NVD's real ones, so a consumer sorting or gating on it was acting on something
nobody computed.

Expected values below are taken from NVD records that publish the vector and
the score together, so they are the scores the rest of the industry reports.
"""

import pytest

from vulnq.cvss import base_score, parse_vector

# vector, expected base score
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.2),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.9),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize("vector,expected", KNOWN)
def test_base_score_matches_published_values(vector, expected):
    assert base_score(vector) == expected


def test_the_metrics_the_old_code_ignored_change_the_answer():
    """AV, PR, UI and S were not read at all, which is why it was wrong.

    Both vectors carry /C:H and /AC:L, so the substring approach called both
    9.0 CRITICAL. They differ by four whole points.
    """
    remote_unauth = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    local_privileged = "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N"

    assert base_score(remote_unauth) == 7.5
    assert base_score(local_privileged) == 4.2


def test_scope_changed_raises_the_score():
    """Scope is worth up to 8 percent plus a different privileges table."""
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert changed > unchanged


def test_no_impact_scores_zero_not_none():
    """Zero is a computed answer. None is the absence of one."""
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/",
        "not a vector",
        "",
    ],
)
def test_unscorable_vectors_return_none(vector):
    """4.0 scores through a lookup table and 2.0 uses different metrics.

    A partial 3.x vector is refused too: every base metric moves the score, so
    there is no honest answer from a subset of them.
    """
    assert base_score(vector) is None


def test_temporal_metrics_do_not_disturb_the_base_score():
    """They may follow the base metrics and do not belong in a base score."""
    plain = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with_temporal = plain + "/E:F/RL:O/RC:C"
    assert base_score(with_temporal) == base_score(plain) == 9.8


def test_parse_vector_reports_the_version():
    assert parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")[0] == "3.0"
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")[0] == "3.1"
