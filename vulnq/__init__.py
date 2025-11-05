"""vulnq - Vulnerability Query Tool

A lightweight, multi-source vulnerability query tool for software composition analysis.
"""

__version__ = "1.0.1"
__author__ = "Oscar Valenzuela B."
__email__ = "oscar.valenzuela.b@gmail.com"

from .core import VulnerabilityQuery
from .models import QueryResult, Vulnerability

__all__ = ["VulnerabilityQuery", "Vulnerability", "QueryResult", "__version__"]
