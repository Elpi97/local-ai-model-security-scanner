# Demo: scanning real models end-to-end

A live run of the scanner against **real, publicly available models** covering
every format Tier 1 handles — plus a deliberately hostile ONNX model and a real
Hugging Face provenance check. Nothing here is synthetic test fixtures; the
benign models are actual published weights.

## 0. Install & verify (60 seconds)

The fastest way in — one command, then confirm it worked:

```bash
curl -fsSL https://raw.githubusercontent.com/Elpi97/local-ai-model-security-scanner/main/install.sh | bash
model-scanner --doctor
```

```
✓ model-scanner installed.
  Verify:   model-scanner --doctor

model-scanner doctor
  version:        0.4.1
  python:         3.9.6 (~/.local/share/model-scanner/venv/bin/python3)
  install:        ~/.local/share/model-scanner/venv/.../model_scanner.py
  onnx package:   present and working (1.19.1)
  deep ONNX scan: ENABLED
  verdict:        install OK
```

`--doctor` tells you the install is healthy (`install OK`) or prints the exact
fix — e.g. if the `onnx` package is missing or broken, it names the precise
`pip` command for *your* environment. If you ever scan an ONNX file without the
deep-scan package, the scanner prints a one-time stderr banner pointing you
back to `--doctor` so weak coverage is never silent.

## The models

| File | Format | Size | Source |
|---|---|---|---|
| `model.safetensors` | safetensors | 454 KB | `hf-internal-testing/tiny-random-gpt2` |
| `pytorch_model.bin` | pytorch-zip (pickle) | 3.6 MB | `hf-internal-testing/tiny-random-gpt2` |
| `tinyllama.gguf` | GGUF (Q2_K) | 483 MB | `TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF` |
| `mnist.onnx` | ONNX | 26 KB | ONNX Model Zoo (`mnist-8`) |
| `trojan.onnx` | ONNX (hostile) | 124 B | crafted: external-data escape |

## 1. Scan a directory of real models

```bash
pip install -e ".[onnx]"          # enables deep ONNX protobuf parsing
python3 model_scanner.py /path/to/models -v
```

```
File:       mnist.onnx
Format:     onnx
Verdict:    🚦 SAFE
Findings:
     [INFO] ONNX IR version: 3
     [INFO] ONNX opset imports: ai.onnx=8
     [INFO] ONNX external-data tensors: 0
     [INFO] ONNX nodes: 12
     [INFO] ONNX initializers: 8
```

```
File:       model.safetensors
Verdict:    🚦 SAFE
     [INFO] Safetensors header OK (64 tensors).

File:       pytorch_model.bin
Verdict:    🚦 SAFE
     [INFO] [archive/data.pkl] global used: collections.OrderedDict
     [INFO] [archive/data.pkl] global used: torch.FloatStorage

File:       tinyllama.gguf
Verdict:    🚦 SAFE
     [INFO] GGUF OK (version=3, tensors~201, kv~23).

Summary: 4 file(s) scanned -- 4 SAFE, 0 REVIEW, 0 DANGEROUS
```

The deep ONNX path surfaces real structure — IR version, opset imports, node /
initializer counts — instead of the old "byte-level scan complete" guess.

## 2. Catch a hostile ONNX model

A trojaned ONNX whose weights point **outside** the model directory
(`../../../../etc/passwd`) — the classic external-data escape:

```bash
python3 model_scanner.py /path/to/trojan.onnx -v
```

```
File:       trojan.onnx
Format:     onnx
Verdict:    🛑 DANGEROUS
Findings:
     [CRITICAL] ONNX external_data location escapes model dir:
                '../../../../etc/passwd' (tensor 'w').
     [INFO] ONNX external-data tensors: 1
```

**Exit code 1** — do not hand off. The scanner loads with
`load_external_data=False`, so the hostile path reaches the detector instead of
being rejected (and hidden) by the ONNX loader itself.

## 3. Verify provenance against Hugging Face

Compare local weights against the Hub revision you intended, with a publisher
allowlist:

```bash
python3 model_scanner.py /path/to/model.safetensors -v \
  --hf-repo hf-internal-testing/tiny-random-gpt2 \
  --publisher hf-internal-testing
```

```
Verdict:    ⚠️ REVIEW
Provenance:
     publisher:   hf-internal-testing (allowlisted=False)
     hf_repo:     hf-internal-testing/tiny-random-gpt2
Findings:
     [INFO] Safetensors header OK (64 tensors).
     [REVIEW] Publisher 'hf-internal-testing' is not on the allowlist.
     [INFO] HF repo: downloads=1797655, likes=8, gated=False, library=transformers.
     [INFO] Intended serving runtime: vLLM. Prefer safetensors weights.
```

Real metadata pulled live from the Hub. A SHA256 mismatch against the Hub LFS
digest would be **DANGEROUS**; here the only flag is the unallowlisted
publisher, so it's REVIEW.

## 4. All three tiers together (trust + audit report)

With an allowlisted publisher, an expected SHA256, and the HF repo, Tier 2
confirms integrity and Tier 3 emits the audit handoff report:

```bash
python3 model_scanner.py /path/to/model.safetensors -v \
  --publisher google \
  --hf-repo hf-internal-testing/tiny-random-gpt2 \
  --expected-sha256 8111d5af...b4e500 \
  --doc-report handoff_report.md --report scan_report.json
```

```
Verdict:    🚦 SAFE
Provenance:
     publisher:   google (allowlisted=True)
     hash_match:  True
     hf_repo:     hf-internal-testing/tiny-random-gpt2
Findings:
     [INFO] SHA256 matches expected digest: 8111d5af...
     [INFO] Publisher 'google' is on the allowlist. Note: Google / DeepMind ...
     [INFO] HF repo: downloads=1797655, gated=False, library=transformers.
```

The generated `handoff_report.md` is the audit artifact an analyst signs off:

```markdown
# Local AI Model Safety Scan Report
- Scanner version: 0.4.1
- Overall verdict: SAFE
## Analyst sign-off
| Analyst name |  |  Date |  |  Final decision | APPROVE / REJECT / ESCALATE |
```

- **Tier 1** file safety (all formats, incl. deep ONNX)
- **Tier 2** trust & integrity — publisher allowlist + SHA256 vs expected / HF LFS
- **Tier 3** behavior checklist + Markdown audit report for the handoff record

## Takeaway

- **SAFE** across all four benign real models (safetensors, pytorch-zip, GGUF, ONNX).
- **DANGEROUS** on the hostile external-data escape, with the exact path named.
- **REVIEW** on unallowlisted publisher, with live Hub provenance attached.

Static, no model execution, stdlib-only core. The `[onnx]` extra turns ONNX
from a byte-grep into real protobuf validation.
