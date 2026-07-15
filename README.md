# Local AI Model Safety Scanner

A single-file, dependency-free Python CLI that statically checks whether a
local AI model file is safe to load — before you run `torch.load()` or hand it
off to your team.

## Quick start

```bash
# No install needed — stdlib only (Python 3.9+)
python3 model_scanner.py /path/to/model.pt

# Or install as a console script
pip install .
model-scanner /path/to/model --report scan_report.json
```

## Workflow

```
1. Pull the model (from Hugging Face, a vendor, etc.)
2. Run:  python3 model_scanner.py /path/to/model --report scan_report.json
3. Read the verdict:
      SAFE       -> proceed
      REVIEW     -> inspect the flagged finding(s) before deciding
      DANGEROUS  -> do not load it; escalate
4. If cleared, copy the file into your trusted location
```

No automation, no watch-folders, no auto-approval — scan first, decide manually.

## Why this matters

Most AI model malware isn't in the tensor weights — it's in the
**serialization format**. Legacy PyTorch checkpoints (`.pt`, `.pth`, `.bin`,
`.ckpt`) are Python **pickles**, and pickle's `REDUCE` / `INST` opcodes can call
*any* importable function with attacker-chosen arguments the moment someone
runs `torch.load()` or `pickle.load()`.

This scanner **never unpickles or loads the model**. It statically
disassembles the pickle opcode stream (Python's stdlib `pickletools`) to see
*what a real load would try to call*, without calling it. Same core technique
used by tools like Protect AI's `ModelScan` / `picklescan`.

## What it checks, by format

| Format | Extensions | Check |
|---|---|---|
| Legacy pickle | `.pt` `.pth` `.bin` `.ckpt` `.pkl` | Opcode scan for dangerous `GLOBAL` / `STACK_GLOBAL` / `INST` references (`os`, `subprocess`, `eval`, …) and call opcodes (`REDUCE`, `OBJ`, …) that invoke them |
| PyTorch zip checkpoint | `.pt` `.pth` `.bin` (zip-based, PyTorch ≥1.6) | Unzips without executing; scans `data.pkl`; flags zip-slip / path traversal |
| Safetensors | `.safetensors` | Header JSON/structure, offset bounds, suspicious metadata URLs |
| GGUF | `.gguf` | Magic bytes, version, sane tensor/KV counts |
| ONNX | `.onnx` | External data path traversal and custom/vendor ops |

## Usage

```bash
# Scan a single file
python3 model_scanner.py ~/downloads/some_model.pt

# Scan a whole directory recursively (e.g. a HF repo you cloned)
python3 model_scanner.py ~/downloads/some-model-repo/

# Save a JSON report
python3 model_scanner.py ~/downloads/model.safetensors --report scan_report.json

# Show every detail, not just flagged findings
python3 model_scanner.py ~/downloads/model.pt -v

# Treat REVIEW verdicts as a hard fail (stricter gating)
python3 model_scanner.py ~/downloads/model.pt --strict

# Allowlist a vetted module you expect to see
python3 model_scanner.py ~/downloads/model.pt --allow-module some_trusted_pkg
```

Exit codes: `0` = clear, `1` = DANGEROUS (or REVIEW with `--strict`), `2` = usage/tool error.

## Reading a verdict

- **SAFE** — no dangerous globals, well-formed headers, no path traversal.
- **REVIEW** — unrecognized pickle global, odd structure, embedded URLs, etc.
  The tool surfaces it; you decide.
- **DANGEROUS** — a concrete code-execution primitive was found (e.g. `REDUCE` /
  `INST` calling `os.system`, `subprocess.Popen`, `eval`, …). Do not load with
  `torch.load()` until it has been fully reverse-engineered.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check model_scanner.py tests/
```

## Known limitations

- Static, best-effort — not a guarantee. Obfuscated pickle chains that avoid
  the blocklist can still slip through; treat REVIEW / unknown globals from
  untrusted sources with real suspicion.
- ONNX checking is a lightweight byte-level scan, not full protobuf validation.
- Complements (does not replace) verifying publisher/hashes and loading in an
  isolated environment as defense in depth.
- Does not scan for bias, output quality, or model behavior — only file safety
  / code-execution risk.

## License

MIT
