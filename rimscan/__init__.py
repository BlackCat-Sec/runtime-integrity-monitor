"""Repository and SBOM risk scanner."""

from rimscan.cli import main
from rimscan.scanner import Scanner

__all__ = ["Scanner", "main"]
