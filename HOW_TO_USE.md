# How to use the Local AI Model Safety Scanner

This guide is for **everyone** — security analysts and non-technical folks who need
to understand the handoff process.

## Your org setup

- **AI department** runs **VLMs** (vision-language models).
- They typically **pull models from Hugging Face**.
- **You** scan first, then manually drop cleared files and notify them.
- **Runtime auto-probes are deferred** — complete the behavior checklist manually for now.

## What this tool does (plain English)

Before the AI department opens a local model, you check:

1. **File trickery** — some formats can run code when opened (especially old `.pt` pickles)
2. **Wrong / swapped file** — SHA256 vs vendor/HF Hub digests
3. **Wrong kind of model** — e.g. text-only repo when they need a VLM
4. **Behavior checklist** — manual text + VLM checks you run in their environment later

You always decide manually. Cleared files go into the drop folder by hand.

| Verdict | Meaning | What you should do |
|---|---|---|
| **SAFE** | No blocking issues in the checks you ran | Usually OK to proceed (still use judgment) |
| **REVIEW** | Something unusual | Ask a technical person / investigate |
| **DANGEROUS** | Strong red flag (e.g. code exec or hash mismatch) | **Do not hand off** |

---

## For non-technical people

### Typical handoff (HF VLM)

1. Get the Hugging Face repo name from the AI dept (example: `google/gemma-4-E2B-it`).
2. Download it into a folder (or have IT do it).
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
python3 model_scanner.py "/full/path/to/model.safetensors" \
  --report scan_report.json \
  --doc-report handoff_report.md
```

---

## For technical people

### Modules

| File | Role |
|---|---|
| `model_scanner.py` | Tier 1 + CLI + doc/JSON reports |
| `trust.py` | Tier 2 allowlist / hash / HF Hub API |
| `behavior.py` | Tier 3 **checklist** (runtime probes deferred) |
| `config/publishers.allowlist.json` | Trusted publisher ids |

### CLI flags (HF / VLM)

| Flag | Purpose |
|---|---|
| `--hf-repo ORG/NAME` | Hub metadata + LFS sibling SHA256 compare |
| `--modality vlm\|text` | Default **`vlm`** |
| `--publisher ID` | Must be allowlisted or REVIEW |
| `--expected-sha256 HEX` | Explicit digest(s); mismatch → DANGEROUS |
| `--manifest PATH.json` | Multi-file digest map |
| `--doc-report OUT.md` | Documentation / audit handoff report |
| `--report OUT.json` | Machine-readable archive |

### Recommended command

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

### Deferred (do not rely on yet)

- `--behavior-probes` / local inference auto-testing — **temporarily deferred**.
  Use the printed **behavior checklist** and test in the AI dept’s VLM stack instead.

### Dev tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Current limitations

Honest boundaries of what this tool **does not** guarantee:

1. **Not a complete malware scanner**  
   Static / best-effort. Obfuscated pickle chains or novel opcodes can slip through → treat REVIEW seriously.

2. **Hash / HF LFS match ≠ “clean weights”**  
   Proves the file matches a published digest (anti-swap). It does **not** prove absence of a semantic / training-time backdoor inside otherwise valid tensors.

3. **Publisher allowlist is policy, not proof**  
   Being on `config/publishers.allowlist.json` only means *your org decided* that id is trusted enough to not auto-REVIEW. Compromised upstream accounts are still possible.

4. **HF metadata needs network**  
   `--hf-repo` fails soft to REVIEW if offline / rate-limited / private+ungated token missing. Sibling SHAs only exist when Hub exposes LFS digests.

5. **VLM behavior is checklist-only (for now)**  
   No automated image prompt-injection / OCR exfil runner yet. Runtime probes via local inference are **deferred**. You (or AI dept) must exercise the model in their stack.

6. **Does not load or execute models (by design)**  
   Good for analyst safety; means no behavioral proof from Tier 1/2 alone.

7. **Format gaps**  
   - ONNX: lightweight byte scan, not full protobuf validation  
   - No first-class TensorFlow SavedModel / Keras H5 scanners (unlike ModelScan)  
   - Tokenizer / `config.json` / processor files are not deeply validated (usually not RCE surfaces)

8. **Directory scan only covers known model extensions**  
   `.safetensors`, `.gguf`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.pkl`, `.onnx` — not arbitrary scripts that might sit beside an HF repo (`*.py` custom code). Review those separately.

9. **No continuous monitoring / auto-drop / auto-notify**  
   Manual SOC workflow only — as requested.

10. **Doc/JSON reports document checks, they are not a warranty**  
    Sign-off is still a human decision.

---

## Still stuck?

1. Re-run with `-v`
2. Attach `scan_report.json` + `handoff_report.md` (not the model weights)
3. Open a GitHub issue with format + verdict + HF repo id only
