# Local AI Model Safety Scanner

A Python CLI for cybersecurity analysts who are the **first line of defense**
before a local AI model is handed to the AI department.

Default mode never loads or runs the model. Optional tiers add publisher/hash
checks and (opt-in) lightweight Ollama behavior probes.

👉 **Start here:** **[HOW_TO_USE.md](HOW_TO_USE.md)** (tech + non-tech).

## Analyst workflow (manual)

```
1. Pull the model yourself
2. Run this scanner (Tier 1 always; Tier 2/3 as needed)
3. Manually copy cleared files into the drop folder
4. Manually notify the AI department (attach scan_report.json)
```

No auto-approval, no watch folders, no auto-notify.

## Three tiers

| Tier | What | Changes verdict? | Needs network / runtime? |
|---|---|---|---|
| **1 – File safety** | Pickle / zip / safetensors / GGUF / ONNX static checks | Yes | No |
| **2 – Trust & integrity** | Publisher allowlist, SHA256 vs expected, optional HF metadata | Yes | HF flag only |
| **3 – Behavior** | Checklist always; optional Ollama probes after gate pass | Checklist no; probe FAIL → REVIEW | Ollama for probes |

```bash
# Tier 1 only
python3 model_scanner.py /path/to/model --report scan_report.json --doc-report handoff_report.md

# Tier 1 + 2
python3 model_scanner.py /path/to/model.gguf \
  --publisher ollama:library/gemma4 \
  --expected-sha256 <hex> \
  --report scan_report.json -v

# Tier 1 + 2 + optional HF enrichment
python3 model_scanner.py /path/to/model \
  --publisher google --hf-repo google/gemma-4-E2B-it -v

# After gate pass: Tier 3 Ollama probes
python3 model_scanner.py /path/to/model.gguf \
  --publisher ollama:library/gemma4 \
  --behavior-probes --ollama-model gemma4:e2b-it-qat -v
```

### Verdicts

| Verdict | Meaning |
|---|---|
| **SAFE** | No blocking file/trust issues found |
| **REVIEW** | Unusual / unallowlisted / probe fail / HF unreachable — analyst judgment |
| **DANGEROUS** | Concrete code-exec risk or **hash mismatch** (possible swap) — do not hand off |

## Quick start

```bash
git clone https://github.com/Elpi97/local-ai-model-security-scanner.git
cd local-ai-model-security-scanner
python3 model_scanner.py /path/to/model.pt -v --report scan_report.json
```

Exit codes: `0` clear · `1` DANGEROUS (or REVIEW with `--strict`) · `2` usage error.

## What Tier 1 checks

| Format | Extensions | Check |
|---|---|---|
| Legacy pickle | `.pt` `.pth` `.bin` `.ckpt` `.pkl` | Dangerous `GLOBAL` / `INST` / call opcodes |
| PyTorch zip | `.pt` `.pth` `.bin` | `data.pkl` + zip-slip |
| Safetensors | `.safetensors` | Header / offsets / metadata URLs |
| GGUF | `.gguf` | Magic, version, sanity counts |
| ONNX | `.onnx` | External-data traversal / custom ops |

## Config & examples

- Publisher allowlist: [`config/publishers.allowlist.json`](config/publishers.allowlist.json)
- Behavior probes: [`probes/behavior_probes.json`](probes/behavior_probes.json)
- Sample manifest / report: [`examples/`](examples/)

## Automated tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Known limitations

- Static Tier 1 is best-effort; obfuscated pickle chains can slip through.
- Hash match proves **integrity vs an expected digest**, not that weights are free of semantic backdoors.
- Behavior probes are keyword heuristics — FAIL means REVIEW, not RCE certainty.
- Complements sandboxed loading and human review; does not replace them.

## License

MIT
