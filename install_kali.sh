#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/rim-scan"
PATH_EXPORT='export PATH="$HOME/.local/bin:$PATH"'

missing=0
for cmd in git python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing=1
  fi
done

if [[ $missing -eq 1 ]]; then
  echo "Installing Kali prerequisites with apt..."
  sudo apt-get update
  sudo apt-get install -y git python3 python3-venv python3-pip
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
