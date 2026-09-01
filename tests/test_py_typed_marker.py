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

import tomllib
from pathlib import Path

import vulnq


def test_the_marker_sits_in_the_installed_package():
    """Located through the imported package, not the source tree.

    Under a real install that is site-packages, so a marker that was not
    packaged fails here rather than passing on the repository copy.
    """
    assert (Path(vulnq.__file__).parent / "py.typed").is_file()


def test_the_marker_is_declared_as_package_data():
    """Without this, the file exists in the tree and never ships."""
    root = Path(__file__).resolve().parent.parent
    config = tomllib.loads((root / "pyproject.toml").read_text())
    package_data = config["tool"]["setuptools"]["package-data"]
    assert "py.typed" in package_data["vulnq"]
