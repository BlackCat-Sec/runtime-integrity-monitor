# runtime-integrity-monitor

`runtime-integrity-monitor` is now a production-ready Python CLI for supply-chain and dependency risk scanning. It scans:

- a local source tree
- a Git repository URL
- a CycloneDX JSON or SPDX JSON SBOM

It performs dependency discovery, queries the official [OSV API](https://osv.dev/), computes a risk score, emits JSON, and prints a concise terminal summary.

The default workflow is optimized for Kali Linux, but the scanner also works on Windows and macOS.

## What It Checks

- Python dependencies from `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `Pipfile.lock`
- Node.js dependencies from `package-lock.json` and `package.json`
- SBOM components from CycloneDX JSON and SPDX JSON
- Known vulnerabilities from the OSV public API
- Risk factors such as unpinned dependencies, affected package count, and parser/network warnings

## Why It Helps

This tool is useful when you need a fast, repeatable way to understand supply-chain risk without manually reviewing multiple manifests or SBOMs.

- For Kali users and security engineers, it gives a quick dependency exposure snapshot during recon, triage, or client-side code review.
- For AppSec and DevSecOps teams, it turns dependency discovery and vulnerability lookups into a repeatable CLI step that can be used locally or in CI.
- For incident response and audit work, it helps answer basic questions quickly: what dependencies exist, which ones are pinned, and which ones are already tied to known advisories.
- For teams consuming third-party software, SBOM support helps validate vendor-delivered inventories instead of trusting them blindly.

## How It Works

The scanner follows the same broad flow regardless of whether you scan a path, a repository URL, or an SBOM.

1. It resolves the target.
   A local directory is scanned in place, a Git URL is shallow-cloned to a temporary directory, and an SBOM file is parsed directly.
2. It discovers supported dependency sources.
   For source trees, it recursively looks for common Python and Node manifests such as `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `package.json`, and `package-lock.json`.
3. It extracts dependency components.
   Each package is normalized into a component record with ecosystem, version, source file, dependency type, and whether the dependency is pinned to an exact version.
4. It queries official vulnerability data.
   When online mode is enabled, the tool queries the [OSV API](https://osv.dev/) for components that have both a supported ecosystem and an exact version.
5. It computes a risk score.
   The score combines vulnerability findings with hygiene signals such as unpinned dependencies, affected package breadth, and scan warnings.
6. It prints a concise summary and can also emit structured JSON.
   This makes it easy to use for both interactive Kali workflows and automation.

## Choosing a Scan Mode

Use the scan mode that matches where you are in the workflow.

- Use a local path scan when you already have the code checked out and want the fastest feedback.
- Use a Git repository URL when you want to inspect a remote codebase without cloning it manually first.
- Use an SBOM scan when a vendor, build system, or artifact repository gives you inventory data instead of source code.
- Use `--offline` when you are in a restricted environment and still want dependency inventory plus basic risk scoring.
- Use `--fail-on-score` when you want CI or a scripted Kali workflow to stop on higher-risk results.

## Risk Score Explained

The risk score is meant to be a prioritization aid, not a substitute for human review.

- `0-24` low: few or no known issues, and dependency hygiene is relatively good
- `25-54` medium: some meaningful risk signals are present, such as unpinned packages or moderate advisory volume
- `55-79` high: multiple material issues are present and the target should be reviewed before trust or deployment
- `80-100` critical: the target shows heavy exposure, poor dependency hygiene, or both

The score is influenced by:

- vulnerability severity counts returned from OSV
- how many direct dependencies are not pinned to exact versions
- how many unique packages are affected
- parser or network warnings that reduce confidence in the scan

Important limitation:

- unpinned dependencies can still increase the risk score, but they usually cannot be matched precisely to OSV because vulnerability lookup works best with exact versions

## Quick Start on Kali Linux

### 1. Clone the repository

```bash
git clone https://github.com/BlackCat-tec/runtime-integrity-monitor.git
cd runtime-integrity-monitor
```

### 2. Install the Kali-first command

```bash
./install_kali.sh
```

This installs a convenient command into `~/.local/bin`:

```bash
rim-scan --help
```

The installer also appends `~/.local/bin` to the usual Kali shell startup files when needed.
If you prefer, `bash install_kali.sh` works too.

### 3. Scan a local path

```bash
rim-scan --path /opt/my-project
```

### 4. Scan a Git repository URL

```bash
rim-scan --repo-url https://github.com/pallets/flask.git
```

### 5. Scan an SBOM

```bash
rim-scan --sbom /tmp/project.cdx.json
```

### 6. Save full JSON output

```bash
rim-scan --path /opt/my-project --json-output report.json --json
```

### 7. Fastest Kali usage

The Kali wrapper accepts the most common cases without flags:

```bash
rim-scan
rim-scan /opt/my-project
rim-scan https://github.com/pallets/flask.git
rim-scan ./bom.json
```

Behavior:

- `rim-scan` scans the current directory
- `rim-scan /some/dir` treats the argument as a local path
- `rim-scan https://...` treats the argument as a Git repository URL
- `rim-scan ./something.json` treats the argument as an SBOM file

## Kali Linux Notes

- `install_kali.sh` bootstraps a local virtual environment and writes the `rim-scan` wrapper into `~/.local/bin`.
- `run_kali.sh` is safe to call directly if you do not want to install the wrapper yet.
- If `git` or `python3-venv` is missing, `install_kali.sh` installs them with `apt`.
- The installer works in both the usual `sudo` workflow and a root shell.
- If you invoke `run_kali.sh` or `rim-scan` with no arguments, it scans the current directory.
- For air-gapped or tightly firewalled Kali systems, use `--offline` to skip OSV lookups and still get dependency inventory plus risk scoring.

Examples:

```bash
rim-scan
rim-scan /opt/my-project --fail-on-score 60
rim-scan https://github.com/pallets/flask.git
rim-scan ./bom.json --offline --json
./run_kali.sh --repo-url https://github.com/pallets/flask.git --fail-on-score 60
```

## Windows Setup

### PowerShell

```powershell
git clone https://github.com/BlackCat-tec/runtime-integrity-monitor.git
cd runtime-integrity-monitor
.\run_windows.ps1 --help
.\run_windows.ps1 --path .
.\run_windows.ps1 --sbom .\tests\fixtures\sample_cyclonedx.json --json
```

`run_windows.ps1` creates `.venv`, installs requirements, and runs the CLI.

### Manual Windows Setup

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python .\main.py --path .
```

## CLI Usage

```text
python main.py TARGET [--json] [--json-output FILE] [--offline] [--fail-on-score N]
python main.py --path PATH [--json] [--json-output FILE] [--offline] [--fail-on-score N]
python main.py --repo-url URL [--ref BRANCH_OR_TAG]
python main.py --sbom FILE
```

### Main Options

- `TARGET`: positional shortcut that auto-detects local directories, repo URLs, and JSON SBOM files
- `--path PATH`: scan a local directory recursively for supported manifests
- `--repo-url URL`: shallow-clone and scan a Git repository URL
- `--sbom FILE`: scan a CycloneDX JSON or SPDX JSON SBOM
- `--ref NAME`: choose a branch or tag when using `--repo-url`
- `--offline`: skip online OSV vulnerability checks
- `--timeout 20`: set HTTP timeout for OSV requests
- `--json`: print the full report as JSON
- `--json-output FILE`: save the JSON report to disk
- `--fail-on-score N`: exit with code `3` when the risk score is `>= N`

## Output

### Default CLI Summary

```text
Target: /opt/my-project
Source type: path
Risk score: 68/100 (high)
Dependencies: 14 total, 11 pinned, 3 unpinned
Vulnerabilities: 3 total (critical=0, high=2, medium=1, low=0, unknown=0)
Risk drivers: 2 high vulnerability finding(s); 3 dependency entry/entries are not version-pinned
Top findings: jinja2 2.10: GHSA-... [high]
```

### JSON Report Shape

```json
{
  "source": {
    "source_type": "sbom",
    "target": "bom.json",
    "resolved_path": "/tmp/bom.json",
    "scanned_at": "2026-03-26T10:00:00Z",
    "repo_url": null,
    "sbom_format": "CycloneDX JSON"
  },
  "summary": {
    "total_components": 2,
    "pinned_components": 2,
    "unpinned_components": 0,
    "vulnerable_components": 1,
    "vulnerabilities_by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "unknown": 0
    },
    "manifests": [
      {
        "kind": "CycloneDX JSON",
        "path": "/tmp/bom.json",
        "component_count": 2
      }
    ]
  },
  "components": [],
  "vulnerabilities": [],
  "risk": {
    "score": 45,
    "level": "medium",
    "reasons": [
      "1 high vulnerability finding(s)"
    ],
    "recommendations": [
      "Upgrade affected packages to a fixed version where available"
    ]
  },
  "warnings": []
}
```

## Supported Inputs

### Local path and repository scanning

- `requirements.txt`
- `pyproject.toml`
- `poetry.lock`
- `Pipfile.lock`
- `package-lock.json`
- `package.json`

### SBOM scanning

- CycloneDX JSON
- SPDX JSON

## Installation Without the Kali Wrapper

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py --path .
```

## Development

Install tooling:

```bash
python -m pip install -r requirements.txt
```

Run checks:

```bash
ruff check .
pytest
```

## Test Fixtures

The repository includes fixtures under `tests/fixtures/` for:

- a sample mixed Python/Node project
- a CycloneDX JSON SBOM
- an SPDX JSON SBOM

These are used by `pytest` and are also useful for local smoke checks.

## Real Scan Examples

Scan the bundled sample project:

```bash
python main.py --path tests/fixtures/sample_project
```

Scan the bundled CycloneDX fixture and save JSON:

```bash
python main.py --sbom tests/fixtures/sample_cyclonedx.json --json-output out/report.json --json
```

Use a local Git URL:

```bash
python main.py --repo-url file:///tmp/my-local-repo
```

## Troubleshooting

- `error: git is required to scan a repository URL`
  Install Git and retry. Kali installer handles this automatically.

- `OSV query failed`
  Retry with network access, increase `--timeout`, or use `--offline`.

- Empty vulnerability output for a package you expected to match
  Vulnerability lookups require an ecosystem and an exact version. Unpinned dependencies are still counted in risk scoring, but they cannot be matched precisely against OSV.

- `~/.local/bin/rim-scan: command not found`
  Add `~/.local/bin` to `PATH` and open a new shell.
