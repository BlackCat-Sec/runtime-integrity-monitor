from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

import httpx

from rimscan.models import Component, VulnerabilityFinding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class OsvClient:
    def __init__(self, *, timeout: float = 20.0, base_url: str = OSV_BATCH_URL) -> None:
        self.timeout = timeout
        self.base_url = base_url

    def query(
        self,
        components: Iterable[Component],
    ) -> tuple[list[VulnerabilityFinding], list[str]]:
        findings: list[VulnerabilityFinding] = []
        warnings: list[str] = []
        queryable = [component for component in components if _is_queryable(component)]
        if not queryable:
            return findings, warnings

        with httpx.Client(timeout=self.timeout) as client:
            for chunk in _chunk(queryable, 200):
                payload = {
                    "queries": [
                        {
                            "package": {
                                "name": component.name,
                                "ecosystem": _ecosystem_for_osv(component.ecosystem),
                            },
                            "version": component.version,
                        }
                        for component in chunk
                    ]
                }
                try:
                    response = client.post(self.base_url, json=payload)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    warnings.append(f"OSV query failed: {exc}")
                    return findings, warnings
                batch = response.json().get("results", [])
                for component, result in zip(chunk, batch, strict=False):
                    for vuln in result.get("vulns", []):
                        findings.append(_to_finding(component, vuln))
        return findings, warnings


def _chunk(items: list[Component], size: int) -> Iterable[list[Component]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _is_queryable(component: Component) -> bool:
    return component.version is not None and _ecosystem_for_osv(component.ecosystem) is not None


def _ecosystem_for_osv(ecosystem: str) -> str | None:
    mapping = {
        "PyPI": "PyPI",
        "npm": "npm",
    }
    return mapping.get(ecosystem)


def _to_finding(component: Component, vulnerability: dict[str, Any]) -> VulnerabilityFinding:
    fixed_versions = _fixed_versions(vulnerability)
    cvss_score = _cvss_score(vulnerability)
    severity = _severity_label(vulnerability, cvss_score)
    references = [
        reference.get("url")
        for reference in vulnerability.get("references", [])
        if reference.get("url")
    ]
    return VulnerabilityFinding(
        osv_id=vulnerability["id"],
        package=component.name,
        ecosystem=component.ecosystem,
        version=component.version or "unknown",
        severity=severity,
        cvss_score=cvss_score,
        summary=(
            vulnerability.get("summary")
            or vulnerability.get("details")
            or "No advisory summary provided"
        ),
        aliases=vulnerability.get("aliases", []),
        fixed_versions=fixed_versions,
        references=references,
    )


def _fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    fixed_versions: set[str] = set()
    for affected in vulnerability.get("affected", []):
        for range_entry in affected.get("ranges", []):
            for event in range_entry.get("events", []):
                if "fixed" in event:
                    fixed_versions.add(str(event["fixed"]))
        for version in affected.get("versions", []):
            if version:
                fixed_versions.add(str(version))
    return sorted(fixed_versions)


def _cvss_score(vulnerability: dict[str, Any]) -> float | None:
    database_severity = vulnerability.get("database_specific", {}).get("severity")
    if isinstance(database_severity, int | float):
        return float(database_severity)

    for severity_entry in vulnerability.get("severity", []):
        score = severity_entry.get("score")
        if score is None:
            continue
        if isinstance(score, int | float):
            return float(score)
        if isinstance(score, str):
            numeric = _extract_numeric_score(score)
            if numeric is not None:
                return numeric
    return None


def _extract_numeric_score(value: str) -> float | None:
    value = value.strip()
    try:
        numeric = float(value)
    except ValueError:
        return None
    if math.isnan(numeric):
        return None
    return numeric


def _severity_label(vulnerability: dict[str, Any], cvss_score: float | None) -> str:
    database_severity = vulnerability.get("database_specific", {}).get("severity")
    if isinstance(database_severity, str):
        return database_severity.lower()
    ecosystem_severity = vulnerability.get("ecosystem_specific", {}).get("severity")
    if isinstance(ecosystem_severity, str):
        return ecosystem_severity.lower()
    if cvss_score is None:
        return "unknown"
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"
