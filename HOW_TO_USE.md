# How to use the Local AI Model Safety Scanner

This guide is for **everyone** — whether you write code every day or you just need
to check that a downloaded AI model file is safe before someone opens it.

## What this tool does (in plain English)

Think of an AI model file like a package that arrives at the office.

Some packaging formats are like sealed cardboard — they only hold data.
Others (especially older PyTorch `.pt` / `.pth` files) can hide a **self-running
script**. The moment someone “opens” the package with a normal AI tool, that
script can run on the computer.

This scanner **looks inside the package without opening it the dangerous way**.
It never loads or runs the model. It only reports:

| Verdict | Meaning | What you should do |
|---|---|---|
| **SAFE** | Nothing obviously dangerous was found | Usually OK to proceed |
| **REVIEW** | Something unusual — not clearly malware, not clearly fine | Ask a technical person to look |
| **DANGEROUS** | Strong signs of code that would run on load | **Do not open/load the model** |

> Important: SAFE is not a lifetime warranty. Prefer models from trusted sources,
> and treat REVIEW / DANGEROUS seriously.

---

## For non-technical people (click-friendly checklist)

### You need

1. A Mac or PC with **Python 3.9+** installed  
   - Mac: open **Terminal** and type `python3 --version`  
   - If it prints something like `Python 3.11.x`, you’re fine  
2. This project folder (clone or download from GitHub)
3. The model file you want to check (often `.gguf`, `.safetensors`, `.pt`, `.onnx`)

### Steps

1. **Get the scanner**
   - Open the GitHub repo: https://github.com/Elpi97/local-ai-model-security-scanner  
   - Click the green **Code** button → **Download ZIP**  
   - Unzip it somewhere easy, e.g. your Desktop  

2. **Open a terminal in that folder**
   - Mac: open **Terminal**, type `cd ` (with a space), drag the unzipped folder
     into the Terminal window, press Enter  
   - Windows: open the folder, click the address bar, type `cmd`, press Enter  

3. **Scan your model file**

```bash
python3 model_scanner.py "/full/path/to/your-model.gguf"
```

Replace the path with your real file. Tip: drag the file onto the Terminal
after typing `python3 model_scanner.py ` (note the space).

4. **Read the last lines of output**
   - Look for `Verdict:` and the **Summary** line  
   - Follow the table above  

5. **Optional: save a report to share**

```bash
python3 model_scanner.py "/full/path/to/your-model.gguf" --report scan_report.json
```

Send `scan_report.json` to your IT / AI teammate along with the verdict.

### Common questions

**“I got `python3: command not found`”**  
Install Python from https://www.python.org/downloads/ (or ask IT). On Windows
try `py model_scanner.py ...` instead of `python3`.

**“It says No recognized model files found”**  
You pointed at a folder that doesn’t contain model files, or the extension isn’t
supported. Point at the actual `.gguf` / `.safetensors` / `.pt` file.

**“Do I need the internet while scanning?”**  
No. After you have the scanner and the model file on disk, the scan is fully offline.

---

## For technical people

### Zero-install run

```bash
git clone https://github.com/Elpi97/local-ai-model-security-scanner.git
cd local-ai-model-security-scanner
python3 model_scanner.py /path/to/model --report scan_report.json -v
```

Exit codes: `0` clear · `1` DANGEROUS (or REVIEW with `--strict`) · `2` usage error.

### Install as a CLI

```bash
pip install .
model-scanner /path/to/model --strict --report out.json
```

### Useful flags

| Flag | Purpose |
|---|---|
| `-v` / `--verbose` | Show INFO findings too |
| `--report OUT.json` | Write machine-readable results |
| `--strict` | Fail CI / scripts on REVIEW as well as DANGEROUS |
| `--allow-module PKG` | Allowlist a vetted pickle module (repeatable) |

### Dev / unit tests

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

---

## Worked example: scan Gemma 4 with Ollama

This is the exact flow we used to validate the scanner on a real small model.

### 1. Pull a small Gemma 4 model

```bash
ollama pull gemma4:e2b-it-qat
```

(~4.3 GB — smallest practical Gemma 4 tag on Ollama at time of writing.)

### 2. Find the on-disk weight files

```bash
ollama show gemma4:e2b-it-qat --modelfile | grep '^FROM'
```

You’ll see paths under `~/.ollama/models/blobs/sha256-…`. Those blobs are GGUF
files (they start with the ASCII magic `GGUF`).

### 3. Point the scanner at them

```bash
# Example: create friendly names (symlinks), then scan the folder
mkdir -p models/gemma4-e2b-it-qat
ln -sf "$(ollama show gemma4:e2b-it-qat --modelfile | awk '/^FROM/{print $2}' | sed -n '1p')" \
  models/gemma4-e2b-it-qat/weights.gguf
ln -sf "$(ollama show gemma4:e2b-it-qat --modelfile | awk '/^FROM/{print $2}' | sed -n '2p')" \
  models/gemma4-e2b-it-qat/aux.gguf

python3 model_scanner.py models/gemma4-e2b-it-qat -v --report scan_report.json
```

### 4. Expected result for this known-good model

```
Verdict:    SAFE
...
Summary: 2 file(s) scanned -- 2 SAFE, 0 REVIEW, 0 DANGEROUS
```

GGUF findings look like: `GGUF OK (version=3, tensors~…, kv~…)`.

A sample report shape lives in [`examples/sample_scan_report.json`](examples/sample_scan_report.json).

---

## What “good” vs “bad” looks like

**Good (SAFE GGUF)** — header sanity only, no code execution surface:

```
Verdict:    SAFE
Findings:
     [INFO] GGUF OK (version=3, tensors~541, kv~43).
```

**Bad (DANGEROUS pickle)** — would run code if loaded:

```
Verdict:    DANGEROUS
Findings:
     [CRITICAL] Pickle references code-execution-capable global 'os.system' ...
     [CRITICAL] REDUCE invokes previously flagged dangerous global ...
```

If you see **DANGEROUS**, stop. Do not `torch.load()`, do not import the file into
shared tooling, escalate to security / the AI team.

---

## Still stuck?

1. Re-run with `-v` and read every finding  
2. Attach `scan_report.json` when asking for help  
3. Open an issue on the repo with the **format** (gguf/pickle/…) and verdict —
   not the whole model file
