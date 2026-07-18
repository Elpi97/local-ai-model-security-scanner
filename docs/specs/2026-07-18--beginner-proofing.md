# Beginner-Proofing: one-command install, self-diagnosis, louder fallback

**Date:** 2026-07-18
**Status:** Approved design
**Target version:** 0.4.1 (shipped; doctor fix-line refined in 0.4.1)
**Scope:** distribution & UX only — no changes to detection logic or severities.

## Problem

The scanner is easy for a security analyst with Python already set up, but
"easy for anyone" fails on three real friction points observed empirically:

1. **Install friction**: `git clone` + `pip install -e .` requires venv
   knowledge; PATH/venv contamination produces silent wrong-binary resolution
   and broken-dependency leaks (observed: a broken ambient `onnx` shadowed a
   fresh venv, producing no-output confusion).
2. **Silent degradation**: without the `onnx` package, ONNX files fall back to
   the byte-scan with only a per-file REVIEW line — easy to miss among other
   findings. A naive user gets weaker security without realizing it.
3. **No self-diagnosis**: when something's wrong (missing/broken onnx, wrong
   binary, old version), the user has no way to check their own install.

Constraint: **no PyPI.** Distribution stays git-based.

## Goals

- One-command install that yields a working, isolated `model-scanner` on PATH.
- Users can self-diagnose their install with one flag.
- Weak-coverage fallback is impossible to miss.
- Zero changes to scan semantics, verdicts, or report formats.

## Non-goals

- No PyPI publication, no Homebrew formula, no Docker image.
- No Windows `.bat`/PowerShell installer (POSIX `install.sh` only; docs note
  the manual path for Windows users).
- No changes to Tier 1/2/3 detection behavior.

## Components

### 1. `install.sh` — one-command installer

Location: repo root. Usage:

```bash
curl -fsSL https://raw.githubusercontent.com/Elpi97/local-ai-model-security-scanner/main/install.sh | bash
# or after cloning:
./install.sh
```

Behavior:

- Requires `python3` (>= 3.9); if missing, print install guidance per-OS and exit 1.
- Creates an isolated venv at `~/.local/share/model-scanner/venv` (honors
  `MODEL_SCANNER_HOME` override).
- Copies the repo (if run from a clone) or clones it (if run via curl-pipe) to
  `~/.local/share/model-scanner/src`.
- `venv/bin/pip install ".[onnx]"` — **the `[onnx]` extra is installed by
  default** (full deep-scan out of the box). `--stdlib` flag opts out:
  `./install.sh --stdlib` installs with no extras.
- Symlinks `venv/bin/model-scanner` → `~/.local/bin/model-scanner` (creates
  `~/.local/bin` if needed; honors `MODEL_SCANNER_BIN` override).
- Checks whether `~/.local/bin` is on PATH; if not, prints the exact line to
  add to the user's shell rc.
- Idempotent: re-running upgrades (reinstalls package, refreshes symlink).
- Prints a success banner including: install location, how to verify
  (`model-scanner --doctor`), and how to uninstall (`install.sh --uninstall`
  removes venv + symlink).
- `--uninstall` removes `~/.local/share/model-scanner` and the symlink.
- Fails loudly with non-zero exit on any step failure (set -euo pipefail).

### 2. `--doctor` flag — install self-diagnosis

`model-scanner --doctor` (no target needed; mutually compatible with nothing
else — it's a standalone mode). Prints and always exits 0:

```
model-scanner doctor
  version:          0.4.0
  python:           3.11.15 (/path/to/python)
  install:          /path/to/model_scanner.py
  onnx package:     present and working (1.22.0)
                    | absent — deep ONNX scan DISABLED
                    | present but BROKEN (ImportError: ...) — deep ONNX scan DISABLED
  deep ONNX scan:   ENABLED | DISABLED
  verdict:          install OK | action needed: <one-line fix>
```

- "present but BROKEN" catches the `onnx_cpp2py_export` ImportError case
  observed in practice (package imports its top-level `__init__` but the C
  extension is missing) by attempting `import onnx` and catching any Exception.
- `verdict: action needed` prints the exact fix:
  - absent → `pip install ".[onnx]"` from the repo dir, or re-run `install.sh`
  - broken → `pip install --force-reinstall "onnx>=1.15"`
- Implementation: a `run_doctor() -> int` function in `model_scanner.py`
  (reusing `onnx_deep.HAS_ONNX` and a live `import onnx` attempt for the
  broken case). Registered as an argparse flag checked before target parsing.

### 3. Louder fallback warning

When `scan_onnx` takes the byte-scan fallback because the onnx package is
absent **or broken** (not via deliberate `--no-onnx-deep`), additionally print
a one-time stderr banner at scan start:

```
⚠ Deep ONNX scan DISABLED (onnx package unavailable) — byte-scan only.
  Install the [onnx] extra for full validation. Run: model-scanner --doctor
```

- Printed once per CLI invocation (not per file), to stderr, before the report.
- The existing per-file REVIEW finding stays unchanged.
- Not printed when `--no-onnx-deep` is used (deliberate fast path — the INFO
  finding already covers it).
- Not printed when zero ONNX files are in the scan set.

### 4. Docs — install paths

- **README**: replace the Installation section with three paths:
  1. One-command: `curl ... install.sh | bash` (installs with `[onnx]` by default)
  2. uv: `uv tool install --with onnx "git+https://github.com/Elpi97/local-ai-model-security-scanner"`
  3. Manual: clone + `pip install -e ".[onnx]"`
  Plus a "Verify: `model-scanner --doctor`" line and a Windows note
  (manual path; install.sh is POSIX).
- **HOW_TO_USE**: update the Install line to match (one-command first).

## Testing

New tests in `tests/test_scanner.py`:

| Test | Expected |
|---|---|
| `--doctor` with working onnx | prints "ENABLED", "install OK", exit 0 |
| `--doctor` with onnx absent (mock `onnx_deep.HAS_ONNX=False` + failing import) | prints "DISABLED", "action needed", exit 0 |
| `--doctor` with broken onnx (mock import raising ImportError) | prints "BROKEN", exit 0 |
| Fallback warning banner on onnx scan without package | banner on stderr, once |
| No banner with `--no-onnx-deep` | stderr empty |
| No banner when no ONNX files scanned | stderr empty |
| Existing 82 tests | all still pass |

`install.sh` is verified manually (run it, check `model-scanner --doctor`
prints ENABLED, run `--uninstall`, verify clean removal) and its checks are
documented in the report; a `bash -n install.sh` syntax check runs in tests.

## Packaging

- Version `0.3.0` → `0.4.0` in `model_scanner.py`, `pyproject.toml`, `trust.py`
  User-Agent.
- `install.sh` committed executable (`chmod +x`).
- ruff clean; no new dependencies (doctor + banner are stdlib).

## Error handling

- `--doctor` never raises; any diagnostic failure is reported as text.
- The stderr banner never changes exit codes.
- `install.sh` uses `set -euo pipefail`; every failure path prints a human
  message and exits non-zero.
