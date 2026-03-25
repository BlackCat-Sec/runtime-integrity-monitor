from __future__ import annotations

from collections import Counter
from pathlib import Path

from rimscan.models import ScanReport, ScanSummary, SourceMetadata
from rimscan.osv import OsvClient
from rimscan.parsers import parse_manifests
from rimscan.risk import assess_risk
from rimscan.sbom import parse_sbom


class Scanner:
    def __init__(self, *, offline: bool = False, timeout: float = 20.0) -> None:
        self.offline = offline
        self.osv = OsvClient(timeout=timeout)

    def scan_path(self, source_path: Path, metadata: SourceMetadata) -> ScanReport:
        components, manifests, warnings = parse_manifests(source_path)
        return self._build_report(components, manifests, warnings, metadata)

    def scan_sbom(self, sbom_path: Path, metadata: SourceMetadata) -> ScanReport:
        components, manifests, warnings, sbom_format = parse_sbom(sbom_path)
        metadata.sbom_format = sbom_format
        return self._build_report(components, manifests, warnings, metadata)

    def _build_report(
        self,
        components,
        manifests,
        warnings,
        metadata: SourceMetadata,
    ) -> ScanReport:
        vulnerabilities = []
        runtime_warnings = list(warnings)
        if not self.offline:
            vulnerabilities, osv_warnings = self.osv.query(components)
            runtime_warnings.extend(osv_warnings)

        severity_counts = Counter(finding.severity for finding in vulnerabilities)
        vulnerable_components = {
            (finding.ecosystem.lower(), finding.package.lower(), finding.version)
            for finding in vulnerabilities
        }
        summary = ScanSummary(
            total_components=len(components),
            pinned_components=sum(1 for component in components if component.locked),
            unpinned_components=sum(1 for component in components if not component.locked),
            vulnerable_components=len(vulnerable_components),
            vulnerabilities_by_severity={
                key: severity_counts.get(key, 0)
                for key in ("critical", "high", "medium", "low", "unknown")
            },
            manifests=manifests,
        )
        risk = assess_risk(components, vulnerabilities, runtime_warnings)
        return ScanReport(
            source=metadata,
            summary=summary,
            components=components,
            vulnerabilities=sorted(
                vulnerabilities,
                key=lambda finding: (
                    _severity_rank(finding.severity),
                    finding.package,
                    finding.osv_id,
                ),
            ),
            risk=risk,
            warnings=runtime_warnings,
        )


def _severity_rank(severity: str) -> int:
    ranking = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "unknown": 4,
    }
    return ranking.get(severity, 5)
