from __future__ import annotations

from collections import Counter

from rimscan.models import Component, RiskAssessment, VulnerabilityFinding

SEVERITY_WEIGHTS = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 4,
    "unknown": 7,
}


def assess_risk(
    components: list[Component],
    vulnerabilities: list[VulnerabilityFinding],
    warnings: list[str],
) -> RiskAssessment:
    severity_counts = Counter(finding.severity for finding in vulnerabilities)
    pinned_count = sum(1 for component in components if component.locked)
    unpinned_count = len(components) - pinned_count
    vulnerable_packages = {(
        finding.ecosystem.lower(),
        finding.package.lower(),
        finding.version,
    ) for finding in vulnerabilities}

    score = 0
    reasons: list[str] = []

    for severity, count in severity_counts.items():
        if count <= 0:
            continue
        score += SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["unknown"]) * count
        reasons.append(f"{count} {severity} vulnerability finding(s)")

    if unpinned_count:
        score += min(15, unpinned_count * 3)
        reasons.append(f"{unpinned_count} dependency entry/entries are not version-pinned")

    if len(vulnerable_packages) >= 3:
        score += 10
        reasons.append(f"{len(vulnerable_packages)} unique packages are affected")

    if warnings:
        score += min(10, len(warnings) * 2)
        reasons.append(f"{len(warnings)} parser or network warning(s) reduced confidence")

    score = min(100, score)
    level = _risk_level(score)
    recommendations = _recommendations(vulnerabilities, unpinned_count)
    return RiskAssessment(
        score=score,
        level=level,
        reasons=reasons or ["No material risk factors detected"],
        recommendations=recommendations,
    )


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _recommendations(vulnerabilities: list[VulnerabilityFinding], unpinned_count: int) -> list[str]:
    recommendations: list[str] = []
    if vulnerabilities:
        fixable = [finding for finding in vulnerabilities if finding.fixed_versions]
        if fixable:
            recommendations.append("Upgrade affected packages to a fixed version where available")
        else:
            recommendations.append(
                "Review vulnerable packages and vendor advisories before deployment"
            )
    if unpinned_count:
        recommendations.append("Pin direct dependencies to exact versions to make scans actionable")
    if not recommendations:
        recommendations.append("Maintain lock files and re-scan in CI to keep the risk score low")
    return recommendations
