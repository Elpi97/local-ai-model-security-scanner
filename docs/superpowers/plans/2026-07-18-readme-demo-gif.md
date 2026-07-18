# README Demo GIF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a 35–45 second animated GIF of the live end-to-end scan walkthrough to the GitHub README so visitors can see SAFE vs DANGEROUS outcomes inline.

**Architecture:** Generate the GIF offline from the already-captured real CLI results (doctor → SAFE safetensors → DANGEROUS ONNX → 94 tests), store it under `assets/`, and embed it in a short “See it in action” section immediately after the README “Start here” link. Keep `examples/DEMO.md` as the detailed evidence page.

**Tech Stack:** Python 3.9+, Pillow (temporary build dependency only; not added to runtime scanner deps), repository Markdown, existing pytest packaging checks.

## Global Constraints

- Duration: 35–45 seconds.
- Dimensions: approximately 960×540.
- Content must use the real captured outcomes: deep ONNX enabled; SAFE exit 0; DANGEROUS exit 1; 94/94 tests passed.
- Long hashes/paths may be shortened for readability; verdicts, exit codes, formats, critical finding, and test count must remain exact.
- Do not add Pillow/ffmpeg as a runtime dependency of `model-scanner`.
- Do not replace `examples/DEMO.md`.
- Do not change scanner behavior.

---

### Task 1: Generate optimized demo GIF from real scan evidence

**Files:**
- Create: `assets/e2e-demo.gif`
- Create (build helper, optional to keep): `scripts/render_e2e_demo_gif.py`
- Read-only evidence: `build/e2e-demo/logs/01-doctor.txt`, `build/e2e-demo/logs/03-benign-scan.txt`, `build/e2e-demo/logs/05-hostile-scan.txt`, `build/e2e-demo/logs/06-tests.txt`

**Interfaces:**
- Consumes: real scan logs under `build/e2e-demo/logs/`
- Produces: `assets/e2e-demo.gif` (~960×540, 35–45s, optimized palette)

- [ ] **Step 1: Confirm evidence files exist**

Run:

```bash
ls -la build/e2e-demo/logs/01-doctor.txt build/e2e-demo/logs/03-benign-scan.txt build/e2e-demo/logs/05-hostile-scan.txt build/e2e-demo/logs/06-tests.txt
```

Expected: all four files exist.

- [ ] **Step 2: Install Pillow only in the temporary e2e venv**

Run:

```bash
build/e2e-venv/bin/python -m pip install --quiet "Pillow>=10"
```

Expected: install succeeds. Do **not** add Pillow to `pyproject.toml` / `requirements.txt`.

- [ ] **Step 3: Create the GIF renderer**

Create `scripts/render_e2e_demo_gif.py` that:

1. Renders a dark terminal-style canvas at 960×540.
2. Plays four chapters with captions:
   - Verify install (`--doctor` → deep ONNX ENABLED / install OK)
   - SAFE path (safetensors, hash match, SAFE, exit 0)
   - DANGEROUS path (ONNX external-data escape to `../../../../etc/passwd`, DANGEROUS, exit 1)
   - Tests (94 passed)
3. Uses typewriter / progressive reveal pacing totaling **35–45 seconds**.
4. Saves an optimized GIF to `assets/e2e-demo.gif` with a limited palette and modest frame count (prefer ~8–12 fps effective; longer holds on key verdict frames).

Include this exact critical finding text somewhere fully visible:

```text
[CRITICAL] ONNX external_data location escapes model dir: '../../../../etc/passwd'
```

Include these exact outcome markers:

```text
Verdict:    SAFE
exit code: 0
Verdict:    DANGEROUS
exit code: 1
94 passed
```

- [ ] **Step 4: Render the GIF**

Run:

```bash
mkdir -p scripts
build/e2e-venv/bin/python scripts/render_e2e_demo_gif.py
ls -lh assets/e2e-demo.gif
```

Expected:
- `assets/e2e-demo.gif` exists
- file size preferably under ~8 MiB (hard fail only if > 15 MiB)
- dimensions near 960×540

- [ ] **Step 5: Validate GIF metadata**

Run:

```bash
build/e2e-venv/bin/python - <<'PY'
from PIL import Image
im = Image.open("assets/e2e-demo.gif")
print("format", im.format)
print("size", im.size)
n = 0
duration = 0
try:
    while True:
        duration += im.info.get("duration", 0)
        n += 1
        im.seek(n)
except EOFError:
    pass
print("frames", n)
print("duration_ms", duration)
print("duration_s", round(duration / 1000, 1))
assert im.format == "GIF"
assert 900 <= im.size[0] <= 1024
assert 500 <= im.size[1] <= 600
assert 35000 <= duration <= 45000
print("OK")
PY
```

Expected: prints `OK`.

- [ ] **Step 6: Commit GIF + renderer**

```bash
git add assets/e2e-demo.gif scripts/render_e2e_demo_gif.py
git commit -m "$(cat <<'EOF'
docs: add end-to-end demo GIF for README

EOF
)"
```

---

### Task 2: Embed the GIF in README with accessible summary

**Files:**
- Modify: `README.md` (insert after the “Start here” line, currently around line 14)
- Keep: `examples/DEMO.md` unchanged except optional one-line cross-link if needed
- Test: `tests/test_trust_behavior.py` (`test_readme_documents_oneliner_install` must still pass)

**Interfaces:**
- Consumes: `assets/e2e-demo.gif`
- Produces: README section visitors see on GitHub

- [ ] **Step 1: Insert the README section**

Immediately after this existing line:

```markdown
👉 **Start here:** **[HOW_TO_USE.md](HOW_TO_USE.md)**
```

Insert:

```markdown

## See it in action

![End-to-end scan: doctor OK, real safetensors SAFE (exit 0), hostile ONNX DANGEROUS (exit 1), 94/94 tests passed](assets/e2e-demo.gif)

Live replay of the scanner gate: install self-check → trusted Hugging Face safetensors clears as **SAFE** → hostile ONNX external-data escape is blocked as **DANGEROUS** → full suite **94/94** passing.

Full commands and evidence: [`examples/DEMO.md`](examples/DEMO.md).
```

- [ ] **Step 2: Keep the existing Config & examples screenshot link**

Do not remove the current `assets/demo-terminal.png` reference under Config & examples. The new GIF is the hero visual; the static screenshot remains secondary evidence.

- [ ] **Step 3: Run packaging / README tests**

Run:

```bash
build/e2e-venv/bin/python -m pytest tests/test_trust_behavior.py::TestVersionAndPackaging -q
```

Expected: all tests in that class pass (including `test_readme_documents_oneliner_install`).

- [ ] **Step 4: Run full suite**

Run:

```bash
build/e2e-venv/bin/python -m pytest -q
```

Expected: `94 passed`.

- [ ] **Step 5: Commit README change**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: embed end-to-end demo GIF in README

EOF
)"
```

---

### Task 3: Final verification against the design spec

**Files:**
- Verify: `docs/specs/2026-07-18--readme-demo-gif.md`
- Verify: `README.md`, `assets/e2e-demo.gif`

- [ ] **Step 1: Spec checklist**

Confirm each requirement is met:

| Spec requirement | Evidence |
|---|---|
| 35–45s GIF | duration validation output |
| ~960×540 | size validation output |
| Real doctor / SAFE / DANGEROUS / 94 tests | GIF chapter content |
| Stored under `assets/` | `assets/e2e-demo.gif` |
| README section after Start here | `README.md` |
| Link to `examples/DEMO.md` | README text |
| Descriptive alt text | image markdown alt |
| Text summary under GIF | README paragraph |

- [ ] **Step 2: Visual spot-check**

Open `assets/e2e-demo.gif` and confirm SAFE and DANGEROUS frames are readable.

- [ ] **Step 3: Optional graphify refresh after docs changes**

Run:

```bash
graphify update .
```

Expected: graph updates without error (docs/assets only; no scanner logic change).

---

## Self-review notes

1. **Spec coverage:** Goal, deliverable, presentation, GitHub compatibility, size/accessibility, verification, and out-of-scope items are each covered by Tasks 1–3.
2. **Placeholders:** none.
3. **Consistency:** asset path is always `assets/e2e-demo.gif`; README section title is always “See it in action”.
