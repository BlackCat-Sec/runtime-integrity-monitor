#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/rim-scan"
PATH_EXPORT='export PATH="$HOME/.local/bin:$PATH"'

run_privileged() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return
  fi

  echo "Need elevated privileges to install Kali prerequisites." >&2
  echo "Re-run as root or install git/python3/python3-venv/python3-pip first." >&2
  exit 1
}

missing=0
for cmd in git python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing=1
  fi
done

if command -v python3 >/dev/null 2>&1; then
  if ! python3 -m venv --help >/dev/null 2>&1; then
    missing=1
  fi
fi

if [[ $missing -eq 1 ]]; then
  echo "Installing Kali prerequisites with apt..."
  run_privileged apt-get update
  run_privileged apt-get install -y git python3 python3-venv python3-pip
fi

mkdir -p "$BIN_DIR"
chmod +x "$REPO_DIR/run_kali.sh" "$REPO_DIR/install_kali.sh"
"$REPO_DIR/run_kali.sh" --help >/dev/null

cat >"$TARGET" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$REPO_DIR/run_kali.sh" "\$@"
EOF

chmod +x "$TARGET"

for rc_file in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
  if [[ -f "$rc_file" ]] && ! grep -Fq "$PATH_EXPORT" "$rc_file"; then
    printf '\n%s\n' "$PATH_EXPORT" >>"$rc_file"
  fi
done

echo "Installed rim-scan to $TARGET"
echo
echo "Kali quick start:"
echo "  rim-scan                 # scan the current directory"
echo "  rim-scan /path/to/code   # scan a local project"
echo "  rim-scan https://github.com/pallets/flask.git"
echo "  rim-scan ./bom.json"
echo
echo "Open a new shell or run: source ~/.zshrc"
