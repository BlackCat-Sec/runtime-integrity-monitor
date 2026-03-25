from __future__ import annotations

import json
from pathlib import Path

from packageurl import PackageURL

from rimscan.models import Component, Manifest
from rimscan.parsers import dedupe_components, read_text


def parse_sbom(path: Path) -> tuple[list[Component], list[Manifest], list[str], str]:
    payload = json.loads(read_text(path))
    if payload.get("bomFormat") == "CycloneDX":
        components = _parse_cyclonedx_json(payload, path)
        sbom_format = "CycloneDX JSON"
    elif str(payload.get("spdxVersion", "")).startswith("SPDX-"):
        components = _parse_spdx_json(payload, path)
        sbom_format = "SPDX JSON"
    else:
        raise ValueError("Unsupported SBOM format. Supported formats: CycloneDX JSON, SPDX JSON.")
    manifests = [Manifest(kind=sbom_format, path=str(path), component_count=len(components))]
    return dedupe_components(components), manifests, [], sbom_format


def _parse_cyclonedx_json(payload: dict, path: Path) -> list[Component]:
    components: list[Component] = []
    for entry in payload.get("components", []):
        name = entry.get("name")
        version = entry.get("version")
        if not name:
            continue
        ecosystem = _ecosystem_from_purl(
            entry.get("purl")
        ) or _infer_ecosystem_from_cyclonedx(entry)
        components.append(
            Component(
                name=name,
                ecosystem=ecosystem,
                version=version,
                source_file=str(path),
                dependency_type="direct",
                locked=version is not None,
                purl=entry.get("purl"),
                scope=entry.get("scope"),
            )
        )
    return components


def _parse_spdx_json(payload: dict, path: Path) -> list[Component]:
    components: list[Component] = []
    for package in payload.get("packages", []):
        if package.get("name") in {"DOCUMENT", "SPDXRef-DOCUMENT"}:
            continue
        name = package.get("name")
        version = package.get("versionInfo")
        if not name:
            continue
        purl = None
        for reference in package.get("externalRefs", []):
            if reference.get("referenceType") == "purl":
                purl = reference.get("referenceLocator")
                break
        ecosystem = _ecosystem_from_purl(purl) or "unknown"
        components.append(
            Component(
                name=name,
                ecosystem=ecosystem,
                version=version,
                source_file=str(path),
                dependency_type="direct",
                locked=version is not None,
                purl=purl,
            )
        )
    return components


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl:
        return None
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    mapping = {
        "pypi": "PyPI",
        "npm": "npm",
    }
    return mapping.get(parsed.type, parsed.type)


def _infer_ecosystem_from_cyclonedx(entry: dict) -> str:
    evidence = str(entry.get("group") or entry.get("type") or "").lower()
    if "npm" in evidence:
        return "npm"
    if "python" in evidence or "pypi" in evidence:
        return "PyPI"
    version = entry.get("version")
    if version and entry.get("name"):
        for ecosystem, purl_type in (("PyPI", "pypi"), ("npm", "npm")):
            try:
                PackageURL(type=purl_type, name=entry["name"], version=version)
                return ecosystem
            except ValueError:
                continue
    return "unknown"
