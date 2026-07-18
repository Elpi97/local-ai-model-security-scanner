#!/usr/bin/env bash
# One-command installer for model-scanner (git-install distribution).
# Creates an isolated venv, installs the [onnx] extra by default, and symlinks
# the CLI into a bin dir on PATH. Idempotent; --uninstall removes everything.
set -euo pipefail

REPO_URL="https://github.com/Elpi97/local-ai-model-security-scanner.git"
APP_HOME="${MODEL_SCANNER_HOME:-$HOME/.local/share/model-scanner}"
BIN_DIR="${MODEL_SCANNER_BIN:-$HOME/.local/bin}"
VENV="$APP_HOME/venv"
SRC="$APP_HOME/src"
WITH_ONNX=1
DO_UNINSTALL=0

usage() {
  cat <<'EOF'
model-scanner installer

Usage: install.sh [OPTIONS]

Options:
  --stdlib       Install without the [onnx] extra (stdlib-only; deep ONNX scan disabled)
  --uninstall    Remove model-scanner (venv + symlink)
  -h, --help     Show this help

Environment:
  MODEL_SCANNER_HOME   Install prefix (default: ~/.local/share/model-scanner)
  MODEL_SCANNER_BIN    Symlink dir for the CLI (default: ~/.local/bin)

After install, verify with:  model-scanner --doctor
EOF
}

for arg in "$@"; do
  case "$arg" in
    --stdlib) WITH_ONNX=0 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option '$arg' (see --help)" >&2; exit 2 ;;
  esac
done

need_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found. Install Python 3.9+ first:" >&2
    echo "  macOS:  brew install python@3.11   (or xcode-select --install)" >&2
    echo "  Debian/Ubuntu: sudo apt install python3 python3-venv" >&2
    echo "  Fedora: sudo dnf install python3" >&2
    exit 1
  fi
}

do_uninstall() {
  echo "Removing model-scanner from $APP_HOME and $BIN_DIR/model-scanner"
  rm -rf "$APP_HOME"
  rm -f "$BIN_DIR/model-scanner"
  echo "Uninstalled."
  exit 0
}

on_path() {
  case ":$PATH:" in *":$BIN_DIR:"*) return 0 ;; *) return 1 ;; esac
}

if [ "$DO_UNINSTALL" -eq 1 ]; then
  do_uninstall
fi

need_python

# Sanitize environment: PYTHONPATH/PYTHONHOME leak into venv creation and break pip.
unset PYTHONPATH PYTHONHOME || true

# Resolve source: prefer the repo we're run from; otherwise clone.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
mkdir -p "$APP_HOME" "$BIN_DIR"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
  echo "Installing from local clone: $SCRIPT_DIR"
  # Install directly from the repo — do NOT cp -R the working tree, which would
  # copy .venv / __pycache__ / build / graphify-out into the install source and
  # contaminate the isolated venv (e.g. a stray broken onnx). pip builds from
  # the source dir without copying those artifacts.
  SRC="$SCRIPT_DIR"
else
  echo "Cloning $REPO_URL"
  rm -rf "$SRC"
  git clone --depth 1 "$REPO_URL" "$SRC"
fi

echo "Creating isolated venv at $VENV"
rm -rf "$VENV"
python3 -m venv "$VENV"

if [ "$WITH_ONNX" -eq 1 ]; then
  echo "Installing model-scanner with [onnx] extra (deep ONNX scan enabled)"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet "$SRC[onnx]"
else
  echo "Installing model-scanner (stdlib-only; deep ONNX scan disabled)"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet "$SRC"
fi

echo "Linking CLI into $BIN_DIR"
ln -sf "$VENV/bin/model-scanner" "$BIN_DIR/model-scanner"

echo ""
echo "✓ model-scanner installed."
echo "  Verify:   model-scanner --doctor"
if ! on_path; then
  echo ""
  echo "NOTE: $BIN_DIR is not on your PATH. Add it with:"
  echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc   # then restart your shell"
fi
