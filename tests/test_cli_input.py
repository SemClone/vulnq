"""Identifiers reach vulnq the ways the README says they do.

Every pipe recipe in the README failed: click validated --input as an existing
path before the branch handling "-" could run, and a bare pipe was never read
at all. A documented way in that returns a usage error is the same class of
defect as a source reporting itself checked without being queried.
"""

import io

import pytest
from click.testing import CliRunner

from vulnq.cli import _read_identifiers, main


def test_dash_is_accepted_by_the_option_itself():
    """click.Path(exists=True) rejected "-" before any code saw it."""
    result = CliRunner().invoke(main, ["--input", "-", "--help"])
    assert "does not exist" not in result.output


@pytest.mark.parametrize(
    "lines,expected",
    [
        ("pkg:npm/lodash@4.17.20\n", ["pkg:npm/lodash@4.17.20"]),
        ("a\nb\n", ["a", "b"]),
        ("a\n\n  \nb\n", ["a", "b"]),
        ("  a  \n", ["a"]),
        ("# a comment\na\n", ["a"]),
        ("", []),
        ("\n\n", []),
    ],
)
def test_identifiers_are_read_a_line_at_a_time(lines, expected):
    assert _read_identifiers(io.StringIO(lines)) == expected


def test_a_comment_line_is_not_treated_as_an_identifier():
    """An identifier file is the sort of thing people annotate."""
    assert _read_identifiers(io.StringIO("# vendored\npkg:npm/x@1\n")) == ["pkg:npm/x@1"]


def test_nothing_on_standard_input_is_still_a_usage_error():
    """An empty pipe must not read as a clean scan of nothing."""
    result = CliRunner().invoke(main, ["--input", "-"], input="")
    assert result.exit_code == 1
    assert "No identifier provided" in result.output


def test_no_arguments_and_no_pipe_is_a_usage_error():
    result = CliRunner().invoke(main, [], input="")
    assert result.exit_code == 1
    assert "No identifier provided" in result.output


def test_there_is_no_config_file_to_speak_of():
    """The README advertised one for a long time. Nothing ever read it.

    Someone putting their tokens in the advertised file got defaults instead,
    with nothing saying the file had been ignored.
    """
    import pathlib

    root = pathlib.Path(__file__).parent.parent
    readme = (root / "README.md").read_text()
    assert "config file" not in readme.lower() or "no config file" in readme.lower()

    pyproject = (root / "pyproject.toml").read_text()
    dependencies = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    # Both were carried only for the config-file support that never existed.
    assert "pyyaml" not in dependencies
    assert "jsonschema" not in dependencies
