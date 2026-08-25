"""Identifiers reach vulnq the ways the README says they do.

Every pipe recipe in the README failed: click validated --input as an existing
path before the branch handling "-" could run, and a bare pipe was never read
at all. A documented way in that returns a usage error is the same class of
defect as a source reporting itself checked without being queried.
"""

import io
import pathlib

import pytest
from click.testing import CliRunner

from vulnq.cli import _read_identifiers, main


def test_dash_is_accepted_by_the_option_itself():
    """click.Path(exists=True) rejected "-" before any code saw it.

    Not asserted through --help: click handles that eagerly and exits before
    path validation runs, so the test would pass with allow_dash reverted.
    """
    result = CliRunner().invoke(main, ["--input", "-"], input="")
    assert "does not exist" not in result.output
    assert result.exit_code == 1


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


def _run(args, stdin_text=None, close_stdin=False):
    """Run the CLI as a real process.

    CliRunner always presents a non-tty stdin, so the bare-pipe branch and the
    terminal branch are indistinguishable under it. Only a real process tells
    them apart.

    Args:
        args: Arguments after the program name
        stdin_text: Text to pipe in, or None for no pipe
        close_stdin: Close the descriptor entirely, as a daemon might

    Returns:
        The completed process
    """
    import subprocess
    import sys as _sys

    kwargs = {"capture_output": True, "text": True, "timeout": 120}
    if close_stdin:
        kwargs["stdin"] = subprocess.DEVNULL
    return subprocess.run(
        [_sys.executable, "-m", "vulnq.cli", *args],
        input=stdin_text,
        **kwargs,
    )


@pytest.mark.parametrize("args", [[], ["--input", "-"]])
def test_a_bare_pipe_is_read_as_identifiers(args):
    """The headline case, and one CliRunner cannot distinguish.

    Under CliRunner stdin is always non-tty, so mutating the bare-pipe branch
    away left the whole suite green. This runs a real process.
    """
    proc = _run([*args, "--sources", "osv", "-f", "json"], stdin_text="pkg:npm/lodash@4.17.20\n")
    assert proc.returncode in (0, 1), proc.stderr
    assert "pkg:npm/lodash@4.17.20" in proc.stdout


@pytest.mark.parametrize("args", ["", "--input -"])
def test_a_closed_descriptor_is_not_a_traceback(args):
    """sys.stdin is None when fd 0 is closed, so asking it anything raises.

    Closed, not /dev/null: subprocess.DEVNULL hands over a real stream, which
    exercises a different path entirely. `<&-` in a shell is the real thing,
    and is what a daemon spawner does.
    """
    import subprocess
    import sys as _sys

    proc = subprocess.run(
        f"{_sys.executable} -m vulnq.cli {args} --sources osv <&-",
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(pathlib.Path(__file__).parent.parent),
    )
    assert "Traceback" not in proc.stderr
    assert "No identifier provided" in proc.stdout
    assert proc.returncode == 1


def test_devnull_is_also_just_no_input():
    proc = _run(["--sources", "osv"], close_stdin=True)
    assert "Traceback" not in proc.stderr
    assert "No identifier provided" in proc.stdout
    assert proc.returncode == 1


def test_input_that_is_not_utf8_is_named_rather_than_dumped():
    """Piping an archive is an easy mistake; a decode traceback does not say so."""
    import subprocess
    import sys as _sys

    proc = subprocess.run(
        [_sys.executable, "-m", "vulnq.cli", "--sources", "osv"],
        input=b"\xff\xfe\x00\x01binary\x00rubbish\xc3\x28",
        capture_output=True,
        timeout=120,
    )
    assert b"Traceback" not in proc.stderr
    assert b"not UTF-8 text" in proc.stdout
    assert proc.returncode == 1


def test_a_byte_order_mark_does_not_ride_into_the_first_identifier():
    """A list written on Windows starts with one, and it would break entry one."""
    assert _read_identifiers(io.StringIO("﻿pkg:npm/a@1\npkg:npm/b@2\n")) == [
        "pkg:npm/a@1",
        "pkg:npm/b@2",
    ]
