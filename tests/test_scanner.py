from __future__ import annotations

from pathlib import Path

from rimscan.models import VulnerabilityFinding
from rimscan.scanner import Scanner
from rimscan.sources import prepare_source

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_scanner_risk_and_summary(monkeypatch):
    fixture_path = FIXTURE_ROOT / "sample_project"

    def fake_query(_components):
        return (
            [
                VulnerabilityFinding(
                    osv_id="OSV-TEST-1",
                    package="jinja2",
                    ecosystem="PyPI",
                    version="2.10",
                    severity="high",
                    cvss_score=8.1,
                    summary="Template injection issue",
                    fixed_versions=["2.11.3"],
                )
            ],
            [],
        )

    scanner = Scanner()
    monkeypatch.setattr(scanner.osv, "query", fake_query)
    with prepare_source(
        local_path=str(fixture_path),
        repo_url=None,
        sbom_path=None,
    ) as (source_path, metadata):
        report = scanner.scan_path(source_path, metadata)

    assert report.summary.total_components >= 6
    assert report.summary.vulnerable_components == 1
    assert report.risk.level in {"medium", "high", "critical"}
    assert any("version-pinned" in reason for reason in report.risk.reasons)


def test_prepare_source_clones_local_git_url(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")

    import subprocess

    subprocess.run(
        ["git", "init"],
        cwd=repo_root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "config", "user.email", "tests@example.com"],
        cwd=repo_root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "config", "user.name", "Tests"],
        cwd=repo_root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "add", "."],
        cwd=repo_root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "commit", "-m", "fixture"],
        cwd=repo_root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    scanner = Scanner(offline=True)
    repo_url = repo_root.resolve().as_uri()
    with prepare_source(
        local_path=None,
        repo_url=repo_url,
        sbom_path=None,
    ) as (source_path, metadata):
        report = scanner.scan_path(source_path, metadata)

    assert metadata.source_type == "repo_url"
    assert report.summary.total_components == 1
