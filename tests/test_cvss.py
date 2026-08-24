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
    # Adjacent is the only AV weight no other row reaches.
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
    # Scope changed uses its own privileges table, and these are the only two
    # rows that reach its Low and High weights at an exact value.
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
    # Scope changed below the 10.0 cap and at an ISS where the -3.25 tail term
    # is worth more than a rounding error, so dropping it changes the answer.
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 6.8),
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


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:P",
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/S:C/C:H/I:H/A:H",
    ],
)
def test_a_repeated_base_metric_is_refused(vector):
    """A vector stating one base metric twice has no single meaning.

    Taking the first value and scoring anyway puts a confident number on a
    contradictory input, which is the shape of bug this module exists to end.
    """
    assert base_score(vector) is None


def test_repeating_a_temporal_metric_is_still_fine():
    """Only the base metrics decide a base score."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/E:H"
    assert base_score(vector) == 9.8


@pytest.mark.parametrize(
    "raw,expected",
    [
        (9.8, 9.8),
        (10, 10.0),
        (0, 0.0),
        ("9.8", 9.8),
        ("10", 10.0),
        (" 7.5 ", 7.5),
        (None, None),
        ("", None),
        ("N/A", None),
        ("HIGH", None),
        (True, None),
        (False, None),
        (float("nan"), None),
        (float("inf"), None),
        (10.1, None),
        (-0.1, None),
        (99, None),
        ([], None),
        ({}, None),
    ],
)
def test_coerce_score_takes_whatever_a_source_sends(raw, expected):
    """Sources disagree about the type, and one bad value used to take the lot.

    NVD and GitHub send a JSON number that arrives as int or float depending on
    whether it has a fraction, OSV sends a string, VulnerableCode sends either.
    A string reaching cvss_to_severity raised TypeError, which is not caught
    per advisory, so a single odd record failed the whole source.
    """
    from vulnq.cvss import coerce_score

    assert coerce_score(raw) == expected if expected is not None else coerce_score(raw) is None


def test_a_bool_is_not_a_score():
    """bool subclasses int, so float(True) is 1.0 and would score LOW."""
    from vulnq.cvss import coerce_score

    assert coerce_score(True) is None
    assert coerce_score(False) is None
