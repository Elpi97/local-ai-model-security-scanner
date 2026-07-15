# Local AI Model Safety Scanner

A Python CLI for cybersecurity analysts who are the **first line of defense**
before the AI department receives a **local VLM** (vision-language model),
usually pulled from **Hugging Face**.

Default mode never loads or runs the model. Optional tiers add publisher/hash
checks (including HF LFS digests) and opt-in Ollama behavior probes.

👉 **Start here:** **[HOW_TO_USE.md](HOW_TO_USE.md)** (tech + non-tech).

## Your environment (as configured)

| Role | What they do |
|---|---|
| **You (cybersecurity)** | Pull or receive the model, scan it, manually drop cleared files, notify AI |
| **AI department** | Uses **VLMs**; typically obtains weights via **Hugging Face** |

## Analyst workflow (manual)

```
1. Pull the HF / vendor model yourself (or receive the AI dept request + repo id)
2. Run this scanner against the downloaded folder/files
3. Manually copy cleared artifacts into the drop folder
4. Manually notify the AI department (attach JSON + Markdown doc report)
```

No auto-approval, no watch folders, no auto-notify.

## Primary example: Hugging Face VLM repo

```bash
# 1) Pull (example — use the repo your AI dept requested)
huggingface-cli download google/gemma-4-E2B-it --local-dir ./incoming/gemma-4-E2B-it

# 2) Scan the whole directory (shards, mmproj/GGUF, pickles, etc.)
python3 model_scanner.py ./incoming/gemma-4-E2B-it \
  --publisher google \
  --hf-repo google/gemma-4-E2B-it \
  --modality vlm \
  -v \
  --report scan_report.json \
  --doc-report handoff_report.md
```

`--modality vlm` is the **default** (matches AI dept usage). Use `--modality text` only for pure-text models.

When `--hf-repo` is set, the scanner compares local SHA256 values to Hub LFS sibling digests when available (mismatch → **DANGEROUS**).

## Three tiers

| Tier | What | Changes verdict? | Needs network / runtime? |
|---|---|---|---|
| **1 – File safety** | Pickle / zip / safetensors / GGUF / ONNX static checks | Yes | No |
| **2 – Trust & integrity** | Publisher allowlist, SHA256, optional **HF metadata + LFS hash** | Yes | `--hf-repo` only |
| **3 – Behavior** | Text + **VLM** checklist; optional Ollama probes after gate | Checklist no; probe FAIL → REVIEW | Ollama for probes |

### Verdicts

| Verdict | Meaning |
|---|---|
| **SAFE** | No blocking file/trust issues found |
| **REVIEW** | Unusual / unallowlisted / HF unreachable / VLM tag mismatch — analyst judgment |
| **DANGEROUS** | Code-exec risk or **hash mismatch** (possible swap vs Hub) — do not hand off |

## Quick start

```bash
git clone https://github.com/Elpi97/local-ai-model-security-scanner.git
cd local-ai-model-security-scanner
python3 model_scanner.py /path/to/hf-snapshot -v --hf-repo ORG/NAME --publisher google \
  --report scan_report.json --doc-report handoff_report.md
```

Exit codes: `0` clear · `1` DANGEROUS (or REVIEW with `--strict`) · `2` usage error.

## What Tier 1 checks

| Format | Extensions | Check |
|---|---|---|
| Legacy pickle | `.pt` `.pth` `.bin` `.ckpt` `.pkl` | Dangerous `GLOBAL` / `INST` / call opcodes |
| PyTorch zip | `.pt` `.pth` `.bin` | `data.pkl` + zip-slip |
| Safetensors | `.safetensors` | Header / offsets / metadata URLs (common for HF VLMs) |
| GGUF | `.gguf` | Magic, version, sanity counts (weights + mmproj) |
| ONNX | `.onnx` | External-data traversal / custom ops |

## Config & examples

- Publisher allowlist: [`config/publishers.allowlist.json`](config/publishers.allowlist.json)
- Behavior probes: [`probes/behavior_probes.json`](probes/behavior_probes.json)
- Samples: [`examples/`](examples/)

## Automated tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Known limitations

- Static Tier 1 is best-effort; obfuscated pickle chains can slip through.
- Hash/HF LFS match proves integrity vs an expected digest, not absence of semantic weight backdoors.
- VLM image attacks need a vision-capable runtime for full testing; checklist covers analyst manual steps; Ollama probes are text heuristics.
- Complements sandboxed loading and human review; does not replace them.

## License

MIT
