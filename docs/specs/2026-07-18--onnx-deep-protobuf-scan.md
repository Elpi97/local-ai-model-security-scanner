# ONNX Deep Protobuf Scanning

**Date:** 2026-07-18
**Status:** Approved design
**Target version:** 0.3.0
**Component:** Tier 1 file-safety scanner (ONNX format)

## Problem

The current ONNX scanner (`model_scanner.py::scan_onnx`) performs byte-level
`find()` searches for the literal strings `location`, `external_data`, and
`custom_op`. It never parses the protobuf. Consequences:

- External-data paths split across protobuf length-delimited chunks are missed.
- Nested subgraphs (control-flow `If`/`Loop`/`Scan` bodies) and
  `model.functions` are invisible to the scan.
- Custom op domains are detected only by the presence of the bytes
  `com.microsoft` / `custom_op` — trivially evaded and not configurable.

## Goals

- Parse ONNX models with the official `onnx` Python package when available.
- Detect external-data path escapes (traversal, absolute paths, URLs) as
  structured facts, not byte heuristics.
- Detect non-standard op domains recursively (graph, subgraphs, functions).
- Preserve the zero-runtime-dependency promise for the default install.

## Non-goals

- No type/shape inference, no execution, no semantic model analysis. Tier 1
  stays static.
- No hand-rolled protobuf wire-format decoder (rejected: maintenance burden,
  parser attack surface, schema drift).
- No new runtime dependency in the default install path.

## Architecture

### Optional dependency

```toml
[project.optional-dependencies]
onnx = ["onnx>=1.15"]
dev  = ["pytest>=7", "ruff>=0.3", "onnx>=1.15"]
```

- Default install remains stdlib-only (README promise unchanged).
- Deep scanning activates when the `onnx` package is importable.

### New module: `onnx_deep.py`

Single-purpose module mirroring the existing `trust.py` / `behavior.py`
pattern. It is the *only* module that imports `onnx`, at one guarded boundary:

```python
try:
    import onnx
    from onnx import TensorProto
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
```

Public surface:

```python
HAS_ONNX: bool
def scan(path: Path, result: ScanResult,
         allow_domains: frozenset[str] = frozenset()) -> None
```

`scan()` populates findings via `result.add(severity, detail)` — the same
vocabulary and report pipeline as every other scanner. No new finding types,
no JSON/Markdown report format changes.

### Integration into `model_scanner.py::scan_onnx`

Order of operations (memory cap unchanged, stays in front):

1. Size check vs `--max-read-bytes` → REVIEW + skip (existing behavior).
2. If `onnx_deep.HAS_ONNX` and not `--no-onnx-deep`:
   `onnx_deep.scan(path, result, allow_domains)`.
3. Else: existing byte-level scan **plus** a new REVIEW finding when the deep
   path was skipped for lack of the package:

   > `onnx package not installed; shallow byte-scan only. Install model-scanner[onnx] for deep validation.`

   The verdict changes to REVIEW when coverage is weaker — a silent shallow
   scan must never report clean.

### New CLI flags

| Flag | Purpose |
|---|---|
| `--no-onnx-deep` | Force the byte-scan fallback even when `onnx` is installed (fast path). |
| `--allow-onnx-domain DOMAIN` | Repeatable. Downgrades the given op domain from CRITICAL to REVIEW. Mirrors the existing `--allow-module` pattern. |

## Detection logic (deep path)

Checked in order of severity:

### CRITICAL — block handoff

1. **External data escaping the model directory.** For every tensor with
   `data_location == TensorProto.EXTERNAL`, resolve each
   `external_data["location"]` against the model file's parent directory.
   Flag when the location: contains `..` segments, is absolute, matches a URL
   scheme (`http://`, `https://`, `file://`, `s3://`, `ftp://`, `gs://`), or
   resolves outside the scan root.
2. **Non-standard op domains.** Walk `model.graph.node` recursively,
   including subgraphs in control-flow attributes (`If`, `Loop`, `Scan`
   bodies) and `model.functions`. Any node whose `domain` is not one of
   `""`, `ai.onnx`, `ai.onnx.ml`, `ai.onnx.preview.training` → CRITICAL,
   unless the domain was passed via `--allow-onnx-domain` (then REVIEW, #3).

### REVIEW — investigate

3. **Allowlisted custom domains in use** — runtime dependency the AI dept
   must satisfy under vLLM.
4. **Suspicious function names** — `model.functions` entries whose name
   contains any of: `eval`, `exec`, `system`, `popen`, `shell` (case-insensitive).
5. **Large embedded initializers** — tensors with inline raw data > 100 MiB
   embedded in the protobuf (possible content smuggling / bloat).

### INFO — report context

6. IR version, opset imports (domain → version), node count, initializer
   count, external-data tensor count. Replaces the current
   "byte-level scan complete" INFO line when the deep path runs.

### Fallback path (byte-scan)

Unchanged heuristics, plus the explicit REVIEW finding above when `onnx` is
not importable. When `--no-onnx-deep` is used deliberately, an INFO finding
notes the fast path instead (no REVIEW — analyst choice, not weak coverage).

## Testing

New `TestOnnxDeep` class in `tests/test_scanner.py`; tests requiring the
`onnx` package are guarded with `@unittest.skipUnless(onnx_deep.HAS_ONNX, ...)`
so the suite is green with and without the extra installed. Dev extras include
`onnx` so CI covers both paths.

| Test | Expected |
|---|---|
| Fallback when `onnx` unimportable | REVIEW finding naming the missing package; byte-scan findings still produced |
| External-data `../escape.bin` | CRITICAL |
| External-data `/etc/passwd` (absolute) | CRITICAL |
| External-data `https://…` URL | CRITICAL |
| Custom domain op (`evil.custom`) | CRITICAL |
| `--allow-onnx-domain com.microsoft` | REVIEW (downgraded) |
| Function named `exec_shell` | REVIEW |
| Embedded raw initializer > 100 MiB | REVIEW |
| Opset/node/initializer counts | INFO findings present |
| Oversized file + deep path | REVIEW + scan skipped (cap precedes parsing) |
| Existing ONNX byte-scan tests | Unchanged, still passing |

Test models are built in-memory with `onnx.helper.make_tensor`,
`make_node`, `make_graph`, `make_model` — no fixture binaries in the repo.

## Packaging & docs

- `pyproject.toml`: `[onnx]` extra added; `dev` extra gains `onnx>=1.15`;
  version `0.2.0` → `0.3.0`.
- `model_scanner.py`: `__version__` → `0.3.0`.
- `trust.py` User-Agent: `model-scanner/0.3`.
- `requirements.txt`: comment noting `pip install -e ".[onnx]"`.
- README: one line — default install is stdlib-only; the `[onnx]` extra
  enables deep ONNX validation.
- HOW_TO_USE: flags table gains `--no-onnx-deep` and `--allow-onnx-domain`.
- `ruff` stays clean (120-char lines, type hints,
  `from __future__ import annotations`).

## Error handling

- Corrupt/truncated protobuf (`onnx.load` raising `onnx.parser.ParseError`
  or similar) → REVIEW ("could not parse as ONNX protobuf"), never a crash.
- **Loading MUST use `onnx.load(path, load_external_data=False)`.** onnx
  ≥1.16 validates external-data locations inside `onnx.load()` itself and
  raises on traversal/absolute paths — which would convert our CRITICAL
  findings into parse-error REVIEWs. Loading without external data preserves
  the hostile `location` entries for `_check_external_data` to inspect.
  (Discovered during Task 2 implementation; the kwarg exists since ~onnx 1.8,
  so the `onnx>=1.15` floor is safe.)
- Any unexpected exception inside `onnx_deep.scan` → caught at the existing
  `scan_file` boundary → REVIEW ("Scanner error while processing file").
  The scanner never exits non-2 due to its own failure on a single file.
