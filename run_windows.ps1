$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $RepoDir ".venv"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$StampFile = Join-Path $VenvDir ".rim_ready"

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher 'py' is required. Install Python 3.11+ from python.org."
}

if (-not (Test-Path $PythonExe)) {
    py -3 -m venv $VenvDir
}

if (-not (Test-Path $StampFile) -or ((Get-Item (Join-Path $RepoDir "requirements.txt")).LastWriteTimeUtc -gt (Get-Item $StampFile).LastWriteTimeUtc)) {
    & $PythonExe -m pip install --upgrade pip | Out-Null
    & $PythonExe -m pip install -r (Join-Path $RepoDir "requirements.txt")
    New-Item -ItemType File -Path $StampFile -Force | Out-Null
}

& $PythonExe (Join-Path $RepoDir "main.py") @args
