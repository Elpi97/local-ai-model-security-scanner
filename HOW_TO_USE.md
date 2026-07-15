# How to use the Local AI Model Safety Scanner

This guide is for **everyone** — security analysts and non-technical folks who need
to understand the handoff process.

## What this tool does (plain English)

Before the AI department opens a local model, you check three kinds of risk:

1. **File trickery** — some formats can run code when opened (especially old `.pt` pickles)
2. **Wrong / swapped file** — does the SHA256 match what the publisher published?
3. **Bad behavior** (optional) — does a quick chat probe look obviously unsafe?

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
3. The model file to check

### Basic scan (file safety only)

```bash
python3 model_scanner.py "/full/path/to/your-model.gguf" \
  --report scan_report.json \
  --doc-report handoff_report.md
```

- `scan_report.json` — machine-readable (automation / archives)
- `handoff_report.md` — human documentation for the ticket, email, or share drive (includes sign-off table)

### Stronger check (hash + known publisher)

Ask your security teammate for:

- Publisher id (example: `google` or `ollama:library/gemma4`)
- The expected SHA256 from the vendor / download page

```bash
python3 model_scanner.py "/path/to/model.gguf" \
  --publisher ollama:library/gemma4 \
  --expected-sha256 PASTE_HEX_HERE \
  --report scan_report.json -v
```

- **Hash mismatch = DANGEROUS** (treat as wrong or swapped file)
- **Unknown publisher = REVIEW**

### Optional behavior probes (needs Ollama)

Only after the file looks OK:

```bash
python3 model_scanner.py "/path/to/model.gguf" \
  --publisher ollama:library/gemma4 \
  --behavior-probes --ollama-model gemma4:e2b-it-qat \
  --report scan_report.json -v
```

The report always includes a **behavior checklist** for manual chat tests even if you skip probes.

---

## For technical people

### Modules

| File | Role |
|---|---|
| `model_scanner.py` | Tier 1 + CLI orchestration |
| `trust.py` | Tier 2 allowlist / hash / HF API |
| `behavior.py` | Tier 3 checklist + Ollama probes |
| `config/publishers.allowlist.json` | Trusted publisher ids |
| `probes/behavior_probes.json` | Fixed probe prompts / keywords |

### CLI flags

| Flag | Tier | Purpose |
|---|---|---|
| `-v` | 1 | Show INFO findings |
| `--report OUT.json` | all | Machine-readable JSON artifact |
| `--doc-report OUT.md` | all | Markdown documentation / audit handoff report |
| `--strict` | all | REVIEW counts as failure (exit 1) |
| `--allow-module PKG` | 1 | Pickle module allowlist |
| `--publisher ID` | 2 | Must be in allowlist or REVIEW |
| `--allowlist PATH` | 2 | Override allowlist file |
| `--expected-sha256 HEX` | 2 | Repeatable; mismatch → DANGEROUS |
| `--manifest PATH.json` | 2 | `{ "publisher": "...", "files": { "name": "sha256" } }` |
| `--hf-repo ORG/NAME` | 2 | Optional online HF metadata |
| `--behavior-probes` | 3 | Run Ollama probes after gate pass |
| `--ollama-model NAME` | 3 | Required with `--behavior-probes` |
| `--ollama-host URL` | 3 | Default `http://127.0.0.1:11434` |

Gate for probes: skipped if any **DANGEROUS**, or any **REVIEW** when `--strict`.

### Manifest example

See [`examples/sample_manifest.json`](examples/sample_manifest.json).

```bash
python3 model_scanner.py models/gemma4-e2b-it-qat \
  --manifest examples/sample_manifest.json -v --report out.json
```

### Dev tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Worked example: Gemma 4 via Ollama

```bash
ollama pull gemma4:e2b-it-qat
ollama show gemma4:e2b-it-qat --modelfile | grep '^FROM'
```

Symlink blobs to `models/…/*.gguf` (see earlier setup), then:

```bash
python3 model_scanner.py models/gemma4-e2b-it-qat \
  --publisher ollama:library/gemma4 \
  --manifest examples/sample_manifest.json \
  --behavior-probes --ollama-model gemma4:e2b-it-qat \
  -v --report scan_report.json
```

Expected for known-good GGUF + matching hash: **SAFE** (probes may add REVIEW if heuristics flag a reply — investigate manually).

Sample enriched report shape: [`examples/sample_scan_report.json`](examples/sample_scan_report.json).

---

## Still stuck?

1. Re-run with `-v`
2. Attach `scan_report.json` (not the model weights)
3. Open a GitHub issue with format + verdict only
