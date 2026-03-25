from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class Component:
    name: str
    ecosystem: str
    version: str | None
    source_file: str
    dependency_type: str
    locked: bool
    specifier: str | None = None
    purl: str | None = None
    scope: str | None = None

    def key(self) -> tuple[str, str, str | None]:
        return (self.ecosystem.lower(), self.name.lower(), self.version)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Manifest:
    kind: str
    path: str
    component_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SourceMetadata:
    source_type: str
    target: str
    resolved_path: str
    scanned_at: str = field(default_factory=utc_now)
    repo_url: str | None = None
    sbom_format: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VulnerabilityFinding:
    osv_id: str
    package: str
    ecosystem: str
    version: str
    severity: str
    cvss_score: float | None
    summary: str
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanSummary:
    total_components: int
    pinned_components: int
    unpinned_components: int
    vulnerable_components: int
    vulnerabilities_by_severity: dict[str, int]
    manifests: list[Manifest]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["manifests"] = [manifest.to_dict() for manifest in self.manifests]
        return payload


@dataclass(slots=True)
class RiskAssessment:
    score: int
    level: str
    reasons: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    source: SourceMetadata
    summary: ScanSummary
    components: list[Component]
    vulnerabilities: list[VulnerabilityFinding]
    risk: RiskAssessment
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "summary": self.summary.to_dict(),
            "components": [component.to_dict() for component in self.components],
            "vulnerabilities": [finding.to_dict() for finding in self.vulnerabilities],
            "risk": self.risk.to_dict(),
            "warnings": list(self.warnings),
        }
