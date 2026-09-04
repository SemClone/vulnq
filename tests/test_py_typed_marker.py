"""vulnq ships its PEP 561 marker (issue #57).

vulnq is annotated throughout, but without `py.typed` in the installed package
a type checker will not read those annotations, and every consumer sees the
package as untyped:

    error: Skipping analyzing "vulnq.enrichment.snapshot": module is installed,
           but missing library stubs or py.typed marker  [import-untyped]

The failure this guards against is not a missing file in the repository but a
marker that never reaches the installed package: setuptools silently ignores a
package-data glob that matches nothing, which is how this went unnoticed.
"""

from pathlib import Path

import vulnq


def test_the_marker_sits_in_the_installed_package():
    """Located through the imported package, not the source tree.

    Under a real install that is site-packages, so a marker that was not
    packaged fails here rather than passing on the repository copy.
    """
    assert (Path(vulnq.__file__).parent / "py.typed").is_file()


def test_the_marker_is_declared_as_package_data():
    """Without this, the file exists in the tree and never ships.

    Read as text rather than parsed: this package supports Python 3.8, which
    has no tomllib, and the declaration is a fixed one-liner.
    """
    root = Path(__file__).resolve().parent.parent
    pyproject = (root / "pyproject.toml").read_text()
    assert 'vulnq = ["py.typed"]' in pyproject


def test_the_two_declared_versions_agree():
    """pyproject.toml is what PyPI publishes; __version__ is what `vulnq
    --version` and any consumer reading the attribute report.

    They are written by hand in two files and drifted once already: 1.5.1 went
    out with __version__ still saying 1.5.0, so an installed copy misreported
    itself and a bug report naming a version named the wrong one. Nothing was
    checking, which is why nothing noticed.

    Read as text rather than parsed: this package supports Python 3.8, which
    has no tomllib.
    """
    root = Path(__file__).resolve().parent.parent
    pyproject = (root / "pyproject.toml").read_text()
    assert f'version = "{vulnq.__version__}"' in pyproject
