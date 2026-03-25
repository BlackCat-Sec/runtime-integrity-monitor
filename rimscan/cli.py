from __future__ import annotations

import argparse
import json
from pathlib import Path

from rimscan.scanner import Scanner
from rimscan.sources import prepare_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a local path, Git repository URL, or SBOM for dependency "
            "risk and known vulnerabilities."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Target to scan. Local directories are treated as --path, URLs as "
            "--repo-url, and JSON files as --sbom."
        ),
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--path", help="Local directory to scan for dependency manifests")
    target.add_argument("--repo-url", help="Git repository URL to clone and scan")
    target.add_argument("--sbom", help="CycloneDX JSON or SPDX JSON file to scan")
    parser.add_argument("--ref", help="Git branch or tag to clone when using --repo-url")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip online OSV vulnerability checks",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout for OSV queries")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report")
    parser.add_argument("--json-output", help="Write the JSON report to a file")
    parser.add_argument(
        "--fail-on-score",
        type=int,
        default=None,
        help=(
            "Exit with code 3 when the computed risk score is greater than "
            "or equal to this threshold"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        local_path, repo_url, sbom_path = resolve_target(args)
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")

    scanner = Scanner(offline=args.offline, timeout=args.timeout)

    try:
        with prepare_source(
            local_path=local_path,
            repo_url=repo_url,
            sbom_path=sbom_path,
            git_ref=args.ref,
        ) as (source_path, metadata):
            if metadata.source_type == "sbom":
                report = scanner.scan_sbom(source_path, metadata)
            else:
                report = scanner.scan_path(source_path, metadata)
    except Exception as exc:
        parser.exit(2, f"error: {exc}\n")

    payload = report.to_dict()
    if args.json_output:
        output_path = Path(args.json_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(render_summary(report))

    if args.fail_on_score is not None and report.risk.score >= args.fail_on_score:
        return 3
    return 0


def resolve_target(
    args: argparse.Namespace,
) -> tuple[str | None, str | None, str | None]:
    explicit_values = [args.path, args.repo_url, args.sbom]
    explicit_count = sum(1 for value in explicit_values if value)
    if explicit_count > 1:
        raise ValueError("use only one of --path, --repo-url, or --sbom")
    if explicit_count == 1 and args.target:
        raise ValueError(
            "use either a positional target or an explicit "
            "--path/--repo-url/--sbom flag"
        )
    if args.path or args.repo_url or args.sbom:
        return args.path, args.repo_url, args.sbom
    if not args.target:
        raise ValueError("a target is required")

    inferred_type = infer_target_type(args.target)
    if inferred_type == "repo_url":
        return None, args.target, None
    if inferred_type == "sbom":
        return None, None, args.target
    return args.target, None, None


def infer_target_type(target: str) -> str:
    lowered = target.lower()
    if lowered.startswith(("http://", "https://", "ssh://", "git://", "file://", "git@")):
        return "repo_url"

    target_path = Path(target).expanduser()
    if target_path.exists():
        if target_path.is_dir():
            return "path"
        if target_path.suffix.lower() in {".json", ".spdx"}:
            return "sbom"
        return "sbom"

    if lowered.endswith(".git"):
        return "repo_url"
    if lowered.endswith((".json", ".spdx")):
        return "sbom"
    return "path"


def render_summary(report) -> str:
    severity = report.summary.vulnerabilities_by_severity
    lines = [
        f"Target: {report.source.target}",
        f"Source type: {report.source.source_type}",
        f"Risk score: {report.risk.score}/100 ({report.risk.level})",
        (
            "Dependencies: "
            f"{report.summary.total_components} total, "
            f"{report.summary.pinned_components} pinned, "
            f"{report.summary.unpinned_components} unpinned"
        ),
        (
            "Vulnerabilities: "
            f"{sum(severity.values())} total "
            f"(critical={severity['critical']}, high={severity['high']}, "
            f"medium={severity['medium']}, low={severity['low']}, unknown={severity['unknown']})"
        ),
    ]
    if report.risk.reasons:
        lines.append("Risk drivers: " + "; ".join(report.risk.reasons[:3]))
    if report.vulnerabilities:
        top_findings = [
            f"{finding.package} {finding.version}: {finding.osv_id} [{finding.severity}]"
            for finding in report.vulnerabilities[:3]
        ]
        lines.append("Top findings: " + "; ".join(top_findings))
    if report.warnings:
        lines.append("Warnings: " + "; ".join(report.warnings[:2]))
    return "\n".join(lines)
