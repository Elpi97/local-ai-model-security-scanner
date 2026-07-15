# Local AI Model Safety Scanner

A Python CLI for cybersecurity analysts who are the **first line of defense**
before the AI department receives local model weights.

**Org context:** AI department serves models with **[vLLM](https://github.com/vllm-project/vllm)** and typically pulls weights from **Hugging Face**.

Default scanning never loads or runs the model. Optional Ollama-style runtime probes are **temporarily deferred** (checklist + AI-dept vLLM testbed instead).

👉 **Start here:** **[HOW_TO_USE.md](HOW_TO_USE.md)**

## Analyst workflow (manual)

```
1. Pull (or receive) the Hugging Face snapshot the AI dept requested
2. Run this scanner on the downloaded folder/files
3. Manually copy cleared artifacts into the drop folder
4. Manually notify the AI department (attach JSON + Markdown doc report)
```

No auto-approval, no watch folders, no auto-notify. AI dept then loads under **vLLM**.

## Primary example: Hugging Face → vLLM handoff

```bash
huggingface-cli download google/gemma-2-2b-it --local-dir ./incoming/gemma-2-2b-it

python3 model_scanner.py ./incoming/gemma-2-2b-it \
  --publisher google \
  --hf-repo google/gemma-2-2b-it \
  --serving-runtime vllm \
  -v \
  --report scan_report.json \
  --doc-report handoff_report.md
```

`--serving-runtime vllm` is the **default**. With `--hf-repo`, local SHA256 is compared to Hub LFS digests when available (mismatch → **DANGEROUS**).

## Three tiers

| Tier | What | Changes verdict? | Network / runtime? |
|---|---|---|---|
| **1 – File safety** | Pickle / zip / safetensors / GGUF / ONNX | Yes | No |
| **2 – Trust & integrity** | Publisher allowlist, SHA256, optional HF metadata + LFS hash | Yes | `--hf-repo` only |
| **3 – Behavior checklist** | Manual analyst checks (incl. vLLM readiness) | No (unless you later enable deferred probes) | No |

### Verdicts

| Verdict | Meaning |
|---|---|
| **SAFE** | No blocking file/trust issues |
| **REVIEW** | Unusual / unallowlisted / HF unreachable — investigate |
| **DANGEROUS** | Code-exec risk or hash mismatch — do not hand off |

## Quick start

```bash
git clone https://github.com/Elpi97/local-ai-model-security-scanner.git
cd local-ai-model-security-scanner
python3 model_scanner.py /path/to/hf-snapshot -v \
  --hf-repo ORG/NAME --publisher ORG \
  --report scan_report.json --doc-report handoff_report.md
```

## What Tier 1 checks

| Format | Extensions | Check |
|---|---|---|
| Legacy pickle | `.pt` `.pth` `.bin` `.ckpt` `.pkl` | Dangerous opcodes |
| PyTorch zip | `.pt` `.pth` `.bin` | `data.pkl` + zip-slip |
| Safetensors | `.safetensors` | Header / offsets (preferred for vLLM) |
| GGUF | `.gguf` | Magic / version / sanity |
| ONNX | `.onnx` | Path traversal / custom ops |

## Config & examples

- [`config/publishers.allowlist.json`](config/publishers.allowlist.json)
- [`examples/`](examples/)

## Automated tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Known limitations

- Static Tier 1 is best-effort.
- Hash/HF LFS match ≠ absence of semantic backdoors.
- Runtime behavior testing under **vLLM** is done with the AI dept after file clearance (Ollama probes deferred).
- Pickle/ONNX/zip-pickle deep reads cap at **512 MiB** by default (`--max-read-bytes`; `0` = unlimited).
- Directory scans skip symlinks and paths that escape the scan root.

## License

MIT
