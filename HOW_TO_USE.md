# How to use the Local AI Model Safety Scanner

This guide is for **everyone** — security analysts and non-technical folks who need
to understand the handoff process.

## Your org setup

- **AI department** runs **VLMs** (vision-language models).
- They typically **pull models from Hugging Face** (repo ids like `google/gemma-4-E2B-it`).
- **You** scan first, then manually drop cleared files and notify them.

## What this tool does (plain English)

Before the AI department opens a local model, you check:

1. **File trickery** — some formats can run code when opened (especially old `.pt` pickles)
2. **Wrong / swapped file** — SHA256 vs vendor/HF Hub digests
3. **Wrong kind of model** — e.g. text-only repo when they need a VLM
4. **Bad behavior** (checklist / optional probes) — including VLM image-injection style risks

You always decide manually. Cleared files go into the drop folder by hand.

| Verdict | Meaning | What you should do |
|---|---|---|
| **SAFE** | No blocking issues in the checks you ran | Usually OK to proceed (still use judgment) |
| **REVIEW** | Something unusual | Ask a technical person / investigate |
| **DANGEROUS** | Strong red flag (e.g. code exec or hash mismatch) | **Do not hand off** |

---

## For non-technical people

### You need

1. Python 3.9+ (`python3 --version`)
2. This project folder (Download ZIP from GitHub)
3. The model folder/files from Hugging Face (or a single `.gguf` / `.safetensors` file)

### Typical handoff (HF VLM)

1. Get the Hugging Face repo name from the AI dept (example: `google/gemma-4-E2B-it`).
2. Have IT/security download it into a folder (or download it yourself if that’s the process).
3. Scan the **folder**:

```bash
python3 model_scanner.py "/full/path/to/hf-folder" \
  --publisher google \
  --hf-repo google/gemma-4-E2B-it \
  --report scan_report.json \
  --doc-report handoff_report.md \
  -v
```

4. Attach **both** reports when you notify the AI team.
5. Only if cleared: copy files into the approved drop folder yourself.

### Single-file scan

```bash
python3 model_scanner.py "/full/path/to/your-model.gguf" \
  --report scan_report.json \
  --doc-report handoff_report.md
```

---

## For technical people

### Modules

| File | Role |
|---|---|
| `model_scanner.py` | Tier 1 + CLI orchestration |
| `trust.py` | Tier 2 allowlist / hash / **HF Hub API** |
| `behavior.py` | Tier 3 checklist (text + **VLM**) + Ollama probes |
| `config/publishers.allowlist.json` | Trusted publisher ids |
| `probes/behavior_probes.json` | Fixed probe prompts / keywords |

### CLI flags (HF / VLM oriented)

| Flag | Purpose |
|---|---|
| `--hf-repo ORG/NAME` | Hub metadata + LFS sibling SHA256 compare |
| `--modality vlm\|text` | Default **`vlm`**. Flags REVIEW if Hub lacks multimodal tags when `vlm` |
| `--publisher ID` | Must be allowlisted or REVIEW |
| `--expected-sha256 HEX` | Explicit digest(s); mismatch → DANGEROUS |
| `--manifest PATH.json` | Multi-file digest map for HF snapshots |
| `--doc-report OUT.md` | Documentation / audit handoff report |
| `--report OUT.json` | Machine-readable archive |
| `--behavior-probes` + `--ollama-model` | Optional text probes after gate pass |

### Recommended command for AI-dept HF VLM pulls

```bash
huggingface-cli download ORG/NAME --local-dir ./incoming/NAME
python3 model_scanner.py ./incoming/NAME \
  --publisher ORG \
  --hf-repo ORG/NAME \
  --modality vlm \
  -v \
  --report scan_report.json \
  --doc-report handoff_report.md
```

Scan the **directory** so every safetensors shard / GGUF / mmproj / pickle is covered.

### Dev tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Worked example: Gemma-class VLM from Hugging Face

```bash
huggingface-cli download google/gemma-4-E2B-it --local-dir ./incoming/gemma-4-E2B-it
python3 model_scanner.py ./incoming/gemma-4-E2B-it \
  --publisher google \
  --hf-repo google/gemma-4-E2B-it \
  --modality vlm \
  -v --report scan_report.json --doc-report handoff_report.md
```

Also supported: Ollama-local GGUF path for offline packs — see earlier Gemma 4 Ollama notes. Prefer Hub digests when AI dept’s source of truth is Hugging Face.

---

## Still stuck?

1. Re-run with `-v`
2. Attach `scan_report.json` + `handoff_report.md` (not the model weights)
3. Open a GitHub issue with format + verdict + HF repo id only
