#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${RIM_VENV:-$REPO_DIR/.venv}"
PYTHON_BIN="$VENV_DIR/bin/python"
STAMP_FILE="$VENV_DIR/.rim_ready"

infer_args() {
  if [[ $# -eq 0 ]]; then
    printf '%s\0%s\0' "--path" "$PWD"
    return
  fi

  if [[ $# -eq 1 && "$1" != -* ]]; then
    case "$1" in
      http://*|https://*|ssh://*|git://*|file://*|git@*|*.git)
        printf '%s\0%s\0' "--repo-url" "$1"
        return
        ;;
      *.json|*.spdx)
        printf '%s\0%s\0' "--sbom" "$1"
        return
        ;;
      *)
        if [[ -f "$1" ]]; then
          printf '%s\0%s\0' "--sbom" "$1"
          return
        fi
        printf '%s\0%s\0' "--path" "$1"
        return
        ;;
    esac
  fi

  printf '%s\0' "$@"
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. On Kali, run: sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip git" >&2
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  python3 -m venv "$VENV_DIR"
fi

if [[ ! -f "$STAMP_FILE" || "$REPO_DIR/requirements.txt" -nt "$STAMP_FILE" ]]; then
  "$PYTHON_BIN" -m pip install --upgrade pip >/dev/null
  "$PYTHON_BIN" -m pip install -r "$REPO_DIR/requirements.txt"
  touch "$STAMP_FILE"
fi

mapfile -d '' ARGS < <(infer_args "$@")

exec "$PYTHON_BIN" "$REPO_DIR/main.py" "${ARGS[@]}"
