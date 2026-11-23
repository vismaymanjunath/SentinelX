"""Imports every intelligence source module so each one registers itself with core.SOURCES."""
from . import vuln, cloud, ris, ioda, atlas  # noqa: F401
