from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

from packageurl import PackageURL
from packaging.requirements import InvalidRequirement, Requirement

from rimscan.models import Component, Manifest

SUPPORTED_MANIFESTS = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "package.json",
}


def discover_manifests(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in SUPPORTED_MANIFESTS:
            manifests.append(path)
    return sorted(manifests)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def parse_manifests(root: Path) -> tuple[list[Component], list[Manifest], list[str]]:
    components: list[Component] = []
    manifests: list[Manifest] = []
    warnings: list[str] = []
    for manifest_path in discover_manifests(root):
        parser = MANIFEST_PARSERS.get(manifest_path.name)
        if parser is None:
            continue
        try:
            parsed = parser(manifest_path)
        except Exception as exc:
            warnings.append(f"Failed to parse {manifest_path}: {exc}")
            continue
        components.extend(parsed)
        manifests.append(
            Manifest(
                kind=manifest_path.name,
                path=str(manifest_path),
                component_count=len(parsed),
            )
        )
    return dedupe_components(components), manifests, warnings


def dedupe_components(components: Iterable[Component]) -> list[Component]:
    deduped: dict[tuple[str, str, str | None, str], Component] = {}
    for component in components:
        key = (
            component.ecosystem.lower(),
            component.name.lower(),
            component.version,
            component.source_file,
        )
        deduped[key] = component
    return sorted(
        deduped.values(),
        key=lambda item: (item.ecosystem, item.name, item.version or ""),
    )


def _component(
    *,
    name: str,
    ecosystem: str,
    version: str | None,
    source_file: str,
    dependency_type: str,
    locked: bool,
    specifier: str | None = None,
    scope: str | None = None,
) -> Component:
    purl_type = ecosystem_to_purl_type(ecosystem)
    purl = None
    if purl_type and version:
        purl = str(PackageURL(type=purl_type, name=name, version=version))
    return Component(
        name=name,
        ecosystem=ecosystem,
        version=version,
        source_file=source_file,
        dependency_type=dependency_type,
        locked=locked,
        specifier=specifier,
        purl=purl,
        scope=scope,
    )


def ecosystem_to_purl_type(ecosystem: str) -> str | None:
    mapping = {
        "PyPI": "pypi",
        "npm": "npm",
    }
    return mapping.get(ecosystem)


def parse_requirements_txt(path: Path) -> list[Component]:
    components: list[Component] = []
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-r", "--")):
            continue
        line = line.split(" #", 1)[0].strip()
        if " @ " in line:
            name, reference = line.split(" @ ", 1)
            components.append(
                _component(
                    name=name.strip(),
                    ecosystem="PyPI",
                    version=None,
                    source_file=str(path),
                    dependency_type="direct",
                    locked=False,
                    specifier=reference.strip(),
                )
            )
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            egg_match = re.search(r"#egg=([A-Za-z0-9_.-]+)", line)
            if egg_match:
                components.append(
                    _component(
                        name=egg_match.group(1),
                        ecosystem="PyPI",
                        version=None,
                        source_file=str(path),
                        dependency_type="direct",
                        locked=False,
                        specifier=line,
                    )
                )
            continue
        pinned_version = extract_pinned_version(str(requirement.specifier))
        components.append(
            _component(
                name=requirement.name,
                ecosystem="PyPI",
                version=pinned_version,
                source_file=str(path),
                dependency_type="direct",
                locked=pinned_version is not None,
                specifier=str(requirement.specifier) or None,
            )
        )
    return components


def parse_pyproject(path: Path) -> list[Component]:
    payload = tomllib.loads(read_text(path))
    components: list[Component] = []
    project = payload.get("project", {})
    for entry in project.get("dependencies", []):
        components.append(_component_from_requirement(entry, path))
    optional_groups = project.get("optional-dependencies", {})
    for group_name, requirements in optional_groups.items():
        for entry in requirements:
            component = _component_from_requirement(entry, path)
            component.scope = group_name
            components.append(component)

    poetry = payload.get("tool", {}).get("poetry", {})
    for name, constraint in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        components.append(_component_from_poetry_entry(name, constraint, path, scope="direct"))
    for group_name, group in poetry.get("group", {}).items():
        for name, constraint in group.get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            components.append(
                _component_from_poetry_entry(
                    name,
                    constraint,
                    path,
                    scope=group_name,
                )
            )
    return components


def _component_from_requirement(entry: str, path: Path) -> Component:
    requirement = Requirement(entry)
    pinned_version = extract_pinned_version(str(requirement.specifier))
    return _component(
        name=requirement.name,
        ecosystem="PyPI",
        version=pinned_version,
        source_file=str(path),
        dependency_type="direct",
        locked=pinned_version is not None,
        specifier=str(requirement.specifier) or None,
    )


def _component_from_poetry_entry(
    name: str,
    constraint: str | dict[str, object],
    path: Path,
    scope: str,
) -> Component:
    if isinstance(constraint, str):
        pinned_version = extract_pinned_version(constraint)
        return _component(
            name=name,
            ecosystem="PyPI",
            version=pinned_version,
            source_file=str(path),
            dependency_type="direct",
            locked=pinned_version is not None,
            specifier=constraint,
            scope=scope,
        )
    version_constraint = str(constraint.get("version", "")) if isinstance(constraint, dict) else ""
    pinned_version = extract_pinned_version(version_constraint)
    return _component(
        name=name,
        ecosystem="PyPI",
        version=pinned_version,
        source_file=str(path),
        dependency_type="direct",
        locked=pinned_version is not None,
        specifier=version_constraint or None,
        scope=scope,
    )


def parse_poetry_lock(path: Path) -> list[Component]:
    payload = tomllib.loads(read_text(path))
    components: list[Component] = []
    for package in payload.get("package", []):
        components.append(
            _component(
                name=package["name"],
                ecosystem="PyPI",
                version=package.get("version"),
                source_file=str(path),
                dependency_type="transitive" if package.get("optional") else "direct",
                locked=True,
                scope=package.get("category"),
            )
        )
    return components


def parse_pipfile_lock(path: Path) -> list[Component]:
    payload = json.loads(read_text(path))
    components: list[Component] = []
    for section_name in ("default", "develop"):
        for name, details in payload.get(section_name, {}).items():
            version = str(details.get("version", "")).lstrip("=") or None
            components.append(
                _component(
                    name=name,
                    ecosystem="PyPI",
                    version=version,
                    source_file=str(path),
                    dependency_type="direct" if section_name == "default" else "development",
                    locked=version is not None,
                    specifier=details.get("version"),
                    scope=section_name,
                )
            )
    return components


def parse_package_json(path: Path) -> list[Component]:
    payload = json.loads(read_text(path))
    components: list[Component] = []
    for section_name in ("dependencies", "devDependencies"):
        for name, specifier in payload.get(section_name, {}).items():
            pinned_version = extract_npm_locked_version(str(specifier))
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=pinned_version,
                    source_file=str(path),
                    dependency_type="direct" if section_name == "dependencies" else "development",
                    locked=pinned_version is not None,
                    specifier=str(specifier),
                )
            )
    return components


def parse_package_lock(path: Path) -> list[Component]:
    payload = json.loads(read_text(path))
    components: list[Component] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, details in packages.items():
            if package_path == "":
                continue
            name = details.get("name") or package_path.rsplit("node_modules/", 1)[-1]
            version = details.get("version")
            if not name or not version:
                continue
            dependency_type = "development" if details.get("dev") else "direct"
            if package_path.count("node_modules/") > 1:
                dependency_type = "transitive"
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=str(version),
                    source_file=str(path),
                    dependency_type=dependency_type,
                    locked=True,
                )
            )
        return components

    dependencies = payload.get("dependencies", {})
    _walk_npm_dependencies(dependencies, components, path, parent_depth=0)
    return components


def _walk_npm_dependencies(
    dependencies: dict[str, dict[str, object]],
    components: list[Component],
    path: Path,
    *,
    parent_depth: int,
) -> None:
    for name, details in dependencies.items():
        version = details.get("version")
        if not version:
            continue
        components.append(
            _component(
                name=name,
                ecosystem="npm",
                version=str(version),
                source_file=str(path),
                dependency_type="direct" if parent_depth == 0 else "transitive",
                locked=True,
            )
        )
        child_dependencies = details.get("dependencies", {})
        if isinstance(child_dependencies, dict):
            _walk_npm_dependencies(
                child_dependencies,
                components,
                path,
                parent_depth=parent_depth + 1,
            )


def extract_pinned_version(specifier: str) -> str | None:
    for token in specifier.split(","):
        token = token.strip()
        if token.startswith("==="):
            return token[3:].strip()
        if token.startswith("==") and not token.startswith("==="):
            return token[2:].strip()
    return None


def extract_npm_locked_version(specifier: str) -> str | None:
    stripped = specifier.strip()
    if not stripped:
        return None
    if re.fullmatch(r"\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?", stripped):
        return stripped
    return None


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
}
