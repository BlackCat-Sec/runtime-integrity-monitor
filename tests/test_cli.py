from __future__ import annotations

import json
from pathlib import Path

from rimscan.cli import build_parser, infer_target_type, main, resolve_target

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_cli_json_output(monkeypatch, capsys, tmp_path):
    output_path = tmp_path / "report.json"

    from rimscan.models import VulnerabilityFinding
    from rimscan.scanner import Scanner

    def fake_query(_components):
        return (
            [
                VulnerabilityFinding(
                    osv_id="OSV-CLI-1",
                    package="jinja2",
                    ecosystem="PyPI",
                    version="2.10",
                    severity="high",
                    cvss_score=8.0,
                    summary="Fixture advisory",
                    fixed_versions=["2.11.3"],
                )
            ],
            [],
        )

    original_init = Scanner.__init__

    def wrapped_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        monkeypatch.setattr(self.osv, "query", fake_query)

    monkeypatch.setattr(Scanner, "__init__", wrapped_init)
    exit_code = main(
        [
            "--path",
            str(FIXTURE_ROOT / "sample_project"),
            "--json",
            "--json-output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["risk"]["score"] >= 20
    assert output_path.exists()


def test_resolve_target_infers_positional_path():
    parser = build_parser()
    args = parser.parse_args([str(FIXTURE_ROOT / "sample_project")])

    local_path, repo_url, sbom_path = resolve_target(args)

    assert local_path is not None
    assert repo_url is None
    assert sbom_path is None


def test_infer_target_type_covers_common_kali_shortcuts():
    assert infer_target_type("https://github.com/pallets/flask.git") == "repo_url"
    assert infer_target_type("tests/fixtures/sample_cyclonedx.json") == "sbom"
    assert infer_target_type("tests/fixtures/sample_project") == "path"
