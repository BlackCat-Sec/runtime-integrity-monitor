from __future__ import annotations

from pathlib import Path

from rimscan.parsers import parse_manifests

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sample_project"


def test_parse_manifests_extracts_python_and_node_dependencies():
    components, manifests, warnings = parse_manifests(FIXTURE_ROOT)

    assert warnings == []
    assert {manifest.kind for manifest in manifests} == {
        "package-lock.json",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
    }
    assert any(
        component.name == "jinja2"
        and component.version == "2.10"
        and component.locked
        for component in components
    )
    assert any(
        component.name == "requests"
        and component.version is None
        and not component.locked
        for component in components
    )
    assert any(
        component.name == "lodash"
        and component.version == "4.17.11"
        and component.ecosystem == "npm"
        for component in components
    )
    assert any(
        component.name == "jest"
        and component.dependency_type == "development"
        for component in components
    )


def test_parse_requirements_with_utf8_bom(tmp_path):
    project = tmp_path / "bom-project"
    project.mkdir()
    (project / "requirements.txt").write_text("\ufeffjinja2==2.10\n", encoding="utf-8")

    components, manifests, warnings = parse_manifests(project)

    assert warnings == []
    assert manifests[0].component_count == 1
    assert components[0].name == "jinja2"
