"""CVSS base score computation.

Scores are computed from the vector, or not reported at all. A score invented
from a partial reading of the vector is worse than no score: it lands in the
same field as NVD's real ones, sorts alongside them, and gates builds.

Only CVSS 3.0 and 3.1 are computed here. Version 4.0 scores through a
MacroVector lookup table that is a different algorithm entirely, and version
2.0 uses different metrics; both are reported as vectors with no score rather
than approximated.

Formula and metric weights: https://www.first.org/cvss/v3.1/specification-document
"""

import math
import re
from typing import Dict, Optional, Tuple

# Attack Vector, Attack Complexity, User Interaction, and the three impacts are
# scope independent. Privileges Required is not: a changed scope raises the
# weight of every non-None value.
_WEIGHTS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_PREFIX = re.compile(r"^CVSS:(3\.[01])/(.+)$")


def parse_vector(vector: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Split a CVSS 3.x vector into its version and base metrics.

    Args:
        vector: CVSS vector string, with its CVSS:3.x prefix

    Returns:
        Tuple of (version, metrics), or None if this is not a well formed 3.x
        base vector. A vector missing any base metric returns None rather than
        a partial reading, because every metric changes the score.
    """
    if not vector:
        return None

    match = _PREFIX.match(vector.strip())
    if not match:
        return None

    version, body = match.groups()

    metrics: Dict[str, str] = {}
    for part in body.split("/"):
        key, _, value = part.partition(":")
        if not value:
            return None
        if key in _REQUIRED and key in metrics:
            # A base metric stated twice contradicts itself. Taking the first
            # and scoring anyway would put a number on a vector that has no
            # single meaning.
            return None
        # Temporal and environmental metrics may follow the base ones. They do
        # not change the base score, so they are ignored rather than refused.
        metrics.setdefault(key, value)

    if any(key not in metrics for key in _REQUIRED):
        return None

    if metrics["S"] not in ("U", "C"):
        return None
    for key in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[key] not in _WEIGHTS[key]:
            return None
    if metrics["PR"] not in _PR_UNCHANGED:
        return None

    return version, metrics


def _roundup(value: float, version: str) -> float:
    """Round up to one decimal place, the way the given spec version says to.

    Args:
        value: Score before rounding
        version: "3.0" or "3.1"

    Returns:
        The rounded score
    """
    if version == "3.1":
        # 3.1 replaced a plain ceiling with integer arithmetic, because binary
        # floats made scores like 8.6 round to 8.7 on some inputs.
        scaled = int(round(value * 100000))
        if scaled % 10000 == 0:
            return scaled / 100000.0
        return (math.floor(scaled / 10000) + 1) / 10.0
    return math.ceil(value * 10) / 10.0


def base_score(vector: str) -> Optional[float]:
    """Compute the CVSS base score for a 3.0 or 3.1 vector.

    Args:
        vector: CVSS vector string

    Returns:
        The base score, or None if the vector is not a complete 3.x base
        vector. None means "not computed", never "computed as zero": a genuine
        0.0 is returned as 0.0.
    """
    parsed = parse_vector(vector)
    if parsed is None:
        return None

    version, metrics = parsed
    changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - _WEIGHTS["C"][metrics["C"]])
        * (1 - _WEIGHTS["I"][metrics["I"]])
        * (1 - _WEIGHTS["A"][metrics["A"]])
    )

    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        # No impact means no base score, whatever the exploitability metrics
        # say. Nothing is at stake, so nothing can be scored.
        return 0.0

    privileges = _PR_CHANGED if changed else _PR_UNCHANGED
    exploitability = (
        8.22
        * _WEIGHTS["AV"][metrics["AV"]]
        * _WEIGHTS["AC"][metrics["AC"]]
        * privileges[metrics["PR"]]
        * _WEIGHTS["UI"][metrics["UI"]]
    )

    combined = impact + exploitability
    if changed:
        combined *= 1.08

    return _roundup(min(combined, 10.0), version)


# CVSS base scores run 0.0 to 10.0 on every version of the specification.
_MIN_SCORE, _MAX_SCORE = 0.0, 10.0


def coerce_score(value: object) -> Optional[float]:
    """Turn a source's score field into a float, or into nothing.

    Sources are inconsistent about the type. NVD and GitHub send a JSON number
    that arrives as int or float depending on whether it has a fraction, and
    OSV sends a string. Comparing those raw is how a str reaches
    cvss_to_severity and raises TypeError, which takes down the whole source
    rather than the one advisory.

    Anything that is not a number in range comes back as None, because a score
    outside 0 to 10 is not a CVSS score whatever else it may be.

    Args:
        value: Whatever the source put in its score field

    Returns:
        The score as a float, or None if it is not a usable one
    """
    if value is None or isinstance(value, bool):
        # bool is an int subclass, and float(True) is 1.0.
        return None

    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None

    if score != score or not _MIN_SCORE <= score <= _MAX_SCORE:
        # NaN fails every comparison, including the range check above, so it is
        # tested for explicitly rather than left to slip through.
        return None

    return score
