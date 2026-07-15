# Local AI Model Safety Scanner

A single-file, dependency-free Python CLI that checks whether a local AI model
file is safe to load — **before** you run `torch.load()` or hand it to your team.

It never loads or executes the model. It only inspects the file format.

👉 **New here?** Start with **[HOW_TO_USE.md](HOW_TO_USE.md)** — written for both
non-technical and technical readers, including a real Gemma 4 walkthrough.

## Quick start

```bash
# No install needed — Python 3.9+ standard library only
python3 model_scanner.py /path/to/model.pt

# Save a JSON report you can share
python3 model_scanner.py /path/to/model --report scan_report.json
```

### What the verdict means

| Verdict | Plain meaning |
|---|---|
| **SAFE** | No obvious code-execution / format red flags |
| **REVIEW** | Unusual — ask a technical person before trusting |
| **DANGEROUS** | Strong signs of code that would run on load — do not open |

## Why this matters

Most AI model malware isn’t in the tensor weights — it’s in the
**serialization format**. Legacy PyTorch checkpoints (`.pt`, `.pth`, `.bin`,
`.ckpt`) are Python **pickles**. Pickle opcodes can call *any* importable
function the moment someone runs `torch.load()` / `pickle.load()`.

This scanner statically disassembles that opcode stream with Python’s stdlib
`pickletools` — the same core idea behind tools like Protect AI’s `ModelScan`
/ `picklescan`.

## What it checks, by format

| Format | Extensions | Check |
|---|---|---|
| Legacy pickle | `.pt` `.pth` `.bin` `.ckpt` `.pkl` | Dangerous `GLOBAL` / `STACK_GLOBAL` / `INST` refs and call opcodes (`REDUCE`, `OBJ`, …) |
| PyTorch zip checkpoint | `.pt` `.pth` `.bin` (zip-based) | Scans `data.pkl`; flags zip-slip |
| Safetensors | `.safetensors` | Header structure, offset bounds, suspicious metadata URLs |
| GGUF | `.gguf` | Magic bytes, version, sane tensor/KV counts |
| ONNX | `.onnx` | External-data path traversal and custom/vendor ops |

## Common commands

```bash
# Single file
python3 model_scanner.py ~/downloads/some_model.pt

# Whole directory (e.g. a cloned Hugging Face repo)
python3 model_scanner.py ~/downloads/some-model-repo/

# Verbose + JSON report
python3 model_scanner.py ~/downloads/model.safetensors -v --report scan_report.json

# Stricter gating (REVIEW counts as failure)
python3 model_scanner.py ~/downloads/model.pt --strict

# Allowlist a module you already vetted
python3 model_scanner.py ~/downloads/model.pt --allow-module some_trusted_pkg
```

Exit codes: `0` = clear, `1` = DANGEROUS (or REVIEW with `--strict`), `2` = tool/usage error.

## Try it on Gemma 4 (worked example)

```bash
ollama pull gemma4:e2b-it-qat
# then follow the full steps in HOW_TO_USE.md → "Worked example: scan Gemma 4"
```

Expected outcome for that known-good model: **2 SAFE** (weights + aux GGUF).
See [`examples/sample_scan_report.json`](examples/sample_scan_report.json).

## Automated tests (developers)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check model_scanner.py tests/
```

## Known limitations

- Static and best-effort — not a guarantee against obfuscated pickle chains.
- ONNX checks are lightweight (not full protobuf validation).
- Complements source/hash verification and sandboxed loading; does not replace them.
- Does not score bias, quality, or jailbreak resistance — only file / code-execution safety.

## License

MIT
