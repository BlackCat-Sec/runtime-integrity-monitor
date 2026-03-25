from __future__ import annotations

from pathlib import Path

from rimscan.sbom import parse_sbom

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_parse_cyclonedx_json():
    components, manifests, warnings, sbom_format = parse_sbom(FIXTURE_DIR / "sample_cyclonedx.json")

    assert warnings == []
    assert sbom_format == "CycloneDX JSON"
    assert manifests[0].component_count == 2
    assert any(
        component.name == "jinja2" and component.ecosystem == "PyPI"
        for component in components
    )


def test_parse_spdx_json():
    components, manifests, warnings, sbom_format = parse_sbom(FIXTURE_DIR / "sample_spdx.json")

    assert warnings == []
    assert sbom_format == "SPDX JSON"
    assert manifests[0].component_count == 1
    assert components[0].purl == "pkg:pypi/jinja2@2.10"
