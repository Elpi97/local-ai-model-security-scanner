# Local AI Model Safety Scanner

A Python CLI for cybersecurity analysts who are the **first line of defense**
before the AI department receives a **local VLM** (vision-language model),
usually pulled from **Hugging Face**.

Default mode never loads or runs the model. Tier 2 adds publisher / hash / HF
Hub checks. Tier 3 ships an **analyst checklist** (manual). Runtime auto-probes
are **deferred for now**.

👉 **Start here:** **[HOW_TO_USE.md](HOW_TO_USE.md)** (tech + non-tech).

## Your environment

| Role | What they do |
|---|---|
| **You (cybersecurity)** | Receive/pull the model, scan it, manually drop cleared files, notify AI |
| **AI department** | Uses **VLMs**; typically obtains weights via **Hugging Face** |

## Analyst workflow (manual)

```
1. Pull the HF model (or receive the repo id + archive from AI dept)
2. Run this scanner on the downloaded folder/files
3. Manually copy cleared artifacts into the drop folder
4. Manually notify the AI department (attach JSON + Markdown doc report)
```

No auto-approval, no watch folders, no auto-notify.

## Primary example: Hugging Face VLM repo

```bash
huggingface-cli download google/gemma-4-E2B-it --local-dir ./incoming/gemma-4-E2B-it

python3 model_scanner.py ./incoming/gemma-4-E2B-it \
  --publisher google \
  --hf-repo google/gemma-4-E2B-it \
  --modality vlm \
  -v \
  --report scan_report.json \
  --doc-report handoff_report.md
```

`--modality vlm` is the **default**. Use `--modality text` only for pure-text models.

With `--hf-repo`, local SHA256 is compared to Hub LFS sibling digests when available
(mismatch → **DANGEROUS**).

## Three tiers

| Tier | What | Changes verdict? | Network? |
|---|---|---|---|
| **1 – File safety** | Pickle / zip / safetensors / GGUF / ONNX static checks | Yes | No |
| **2 – Trust & integrity** | Publisher allowlist, SHA256, optional HF metadata + LFS hash | Yes | Only if `--hf-repo` |
| **3 – Behavior checklist** | Text + VLM analyst checklist in report / doc | No (manual) | No |

> **Deferred:** automated runtime behavior probes (e.g. local inference runners).
> Use the checklist manually until that lands.

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
python3 model_scanner.py /path/to/hf-snapshot -v \
  --hf-repo ORG/NAME --publisher google \
  --report scan_report.json --doc-report handoff_report.md
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
- Samples: [`examples/`](examples/)

## Automated tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Current limitations

See **[HOW_TO_USE.md → Current limitations](HOW_TO_USE.md#current-limitations)** for the full list.
Highlights:

- Static / best-effort — not a malware “proof”
- Hash match ≠ no semantic weight backdoor
- No automated VLM image probing yet (checklist only)
- Light ONNX checks; no full TF/Keras coverage
- Complements sandbox + human review; does not replace them

## License

MIT
