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
