# How to use the Local AI Model Safety Scanner

## Your org setup

- **AI department** serves models with **vLLM** (not “VLM”).
- They typically **pull weights from Hugging Face**.
- **You** scan first, then manually drop cleared files and notify them.

## What this tool does

1. **File trickery** — pickle / archive tricks that can run code on load  
2. **Wrong / swapped file** — SHA256 vs vendor or Hugging Face LFS digests  
3. **Behavior checklist** — manual checks before/after AI dept loads under vLLM  

Ollama-based automated probes are **temporarily deferred** (not part of the standard path).

| Verdict | Meaning | Action |
|---|---|---|
| **SAFE** | No blocking issues | Usually OK to proceed |
| **REVIEW** | Something unusual | Investigate before handoff |
| **DANGEROUS** | Strong red flag | **Do not hand off** |

---

## For non-technical people

1. Get the Hugging Face repo id from the AI dept (example: `google/gemma-2-2b-it`).
2. Download that repo into a folder.
3. Scan:

```bash
python3 model_scanner.py "/path/to/hf-folder" \
  --publisher google \
  --hf-repo google/gemma-2-2b-it \
  --report scan_report.json \
  --doc-report handoff_report.md \
  -v
```

4. Attach both reports when notifying AI.
5. Only if cleared: copy into the drop folder yourself.

---

## For technical people

### Recommended HF → vLLM handoff command

```bash
huggingface-cli download ORG/NAME --local-dir ./incoming/NAME
python3 model_scanner.py ./incoming/NAME \
  --publisher ORG \
  --hf-repo ORG/NAME \
  --serving-runtime vllm \
  -v \
  --report scan_report.json \
  --doc-report handoff_report.md
```

Scan the **directory** so every safetensors shard / checkpoint is covered.

### Useful flags

| Flag | Purpose |
|---|---|
| `--hf-repo ORG/NAME` | Hub metadata + LFS sibling SHA256 compare (must be `ORG/NAME`) |
| `--serving-runtime vllm` | Default — records intended AI-dept runtime |
| `--publisher ID` | Must be allowlisted or REVIEW |
| `--expected-sha256 HEX` | Explicit digest; mismatch → DANGEROUS |
| `--manifest PATH.json` | Multi-file digest map (prefer relative keys under the scan root) |
| `--max-read-bytes N` | Cap full-memory reads for pickle/ONNX/zip members (default 512 MiB; `0` = unlimited) |
| `--doc-report OUT.md` | Audit / handoff Markdown |
| `--report OUT.json` | Machine-readable archive |

### Path / size notes

- Directory scans **do not follow symlinks** and only include files that resolve under the scan root.
- Manifest `files` keys should be **relative paths** (e.g. `subdir/weights.pkl`). A bare basename still matches for compatibility but adds a **REVIEW** finding.
- Oversize pickle/ONNX/zip-pickle members are marked **REVIEW** and deep-scanned is skipped (raise `--max-read-bytes` or use `0` if you must scan huge artifacts).

### Modules

| File | Role |
|---|---|
| `model_scanner.py` | Tier 1 + CLI |
| `trust.py` | Publisher / hash / HF API |
| `behavior.py` | Checklist (deferred probe helper remains optional/experimental) |

### Dev tests

```bash
pip install -e ".[dev]"
pytest
```

---

## Still stuck?

Re-run with `-v`, attach reports (not weights), open an issue with format + verdict + HF repo id.
