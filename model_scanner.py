#!/usr/bin/env python3
"""
Static safety scanner for local AI model files (pickle/PyTorch, safetensors, GGUF, ONNX),
with optional Tier-2 provenance (publisher/hash/HF) for AI-dept handoff.

Context: AI department serves models with **vLLM** and typically pulls weights from
**Hugging Face**. Tier 1 never loads models. Optional Ollama runtime probes exist in
code but are TEMPORARILY DEFERRED from the standard handoff path.

Usage:   model-scanner <file-or-directory> [options]
Exit codes: 0=SAFE, 1=DANGEROUS (or REVIEW with --strict), 2=error
"""

from __future__ import annotations

__version__: str = "0.2.0"


import argparse
import hashlib
import json
import os as _os
import pickletools
import struct
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import behavior as behavior_mod
import trust as trust_mod

# Cap for formats that currently slur whole files / zip members into memory.
# 0 via CLI means unlimited. Safetensors/GGUF use header-only reads and are uncapped here.
DEFAULT_MAX_READ_BYTES: int = 512 * 1024 * 1024


DANGEROUS_MODULES: frozenset[str] = frozenset([
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil",
    "ctypes", "ctypes.util", "importlib", "importlib.util", "runpy",
    "pty", "code", "codeop", "commands", "popen2", "multiprocessing",
    "urllib", "urllib.request", "urllib2", "requests", "http",
    "http.client", "ftplib", "telnetlib", "webbrowser", "shlex",
    "platform", "asyncio", "asyncio.subprocess", "signal", "resource",
])

DANGEROUS_BUILTIN_NAMES: frozenset[str] = frozenset([
    "eval", "exec", "compile", "__import__", "open", "input",
    "getattr", "setattr", "delattr", "vars", "globals", "locals",
])

BUILTIN_MODULE_NAMES: frozenset[str] = frozenset(["builtins", "__builtin__"])

# Exact root modules whose name or dotted submodules are trusted in pickles.
# Matching uses module boundaries (numpy OK, numpy.core OK, numpyevil NOT OK).
SAFE_MODULE_ROOTS: frozenset[str] = frozenset([
    "torch", "numpy", "collections",
])

SAFE_EXACT_GLOBALS: frozenset[tuple[str, str]] = frozenset([
    ("collections", "OrderedDict"),
    ("builtins", "set"), ("builtins", "dict"),
    ("builtins", "list"), ("builtins", "tuple"),
    ("builtins", "bytearray"), ("builtins", "complex"),
    ("__builtin__", "set"), ("__builtin__", "dict"),
])

# Opcodes that construct/call an object (concrete invocation, not a mere import ref).
CALL_OPCODES: frozenset[str] = frozenset([
    "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX",
])

MAGIC_ZIP: bytes = b"PK\x03\x04"
MAGIC_GGUF: bytes = b"GGUF"


def _module_is_or_under(mod: str, root: str) -> bool:
    """True if mod == root or mod is a dotted submodule of root."""
    return mod == root or mod.startswith(root + ".")


def is_dangerous_global(mod: str, name: str) -> bool:
    if any(_module_is_or_under(mod, root) for root in DANGEROUS_MODULES):
        return True
    if mod in BUILTIN_MODULE_NAMES and name in DANGEROUS_BUILTIN_NAMES:
        return True
    return False


def is_allowlisted_global(mod: str, name: str, allow_modules: frozenset[str]) -> bool:
    if mod in allow_modules or (mod, name) in SAFE_EXACT_GLOBALS:
        return True
    if any(_module_is_or_under(mod, root) for root in SAFE_MODULE_ROOTS):
        return True
    return False


@dataclass
class Finding:
    severity: str
    detail: str


@dataclass
class ScanResult:
    path: str
    format: str
    sha256: str
    size_bytes: int
    verdict: str = "SAFE"
    findings: list[Finding] = field(default_factory=list)
    provenance: Optional[dict[str, Any]] = None
    behavior_checklist: list[dict[str, str]] = field(default_factory=behavior_mod.default_checklist)
    behavior_results: Optional[dict[str, Any]] = None

    def add(self, severity: str, detail: str) -> None:
        self.findings.append(Finding(severity, detail))
        if severity == "CRITICAL" and self.verdict != "DANGEROUS":
            self.verdict = "DANGEROUS"
        elif severity == "REVIEW" and self.verdict == "SAFE":
            self.verdict = "REVIEW"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sniff_format(path: Path) -> str:
    ext = path.suffix.lower()
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:4] == MAGIC_GGUF or ext == ".gguf":
        return "gguf"
    if head[:4] == MAGIC_ZIP:
        return "pytorch-zip"
    if ext == ".safetensors":
        return "safetensors"
    if ext == ".onnx":
        return "onnx"
    if ext in (".pt", ".pth", ".bin", ".ckpt", ".pkl"):
        return "pickle"
    try:
        n = struct.unpack("<Q", head)[0]
        if 0 < n < 100_000_000:
            with open(path, "rb") as f:
                f.seek(8)
                maybe_json = f.read(min(n, 2048))
            if maybe_json.strip().startswith(b"{"):
                return "safetensors"
    except Exception:
        pass
    return "pickle"


def _parse_module_name_arg(arg: object) -> tuple[str, str]:
    """Parse pickle GLOBAL/INST style 'module name' argument."""
    if isinstance(arg, str):
        parts = arg.split(" ")
        mod = parts[0]
        name = parts[1] if len(parts) >= 2 else ""
        return mod, name
    return "?", str(arg)


def scan_pickle_bytes(data: bytes, result: ScanResult, verbose: bool,
                       allow_modules: frozenset[str], label: str = "") -> None:
    prefix = f"[{label}] " if label else ""
    try:
        ops = list(pickletools.genops(data))
    except Exception as e:
        result.add("REVIEW", f"{prefix}Could not fully disassemble pickle stream: {e}")
        return
    pending_danger_call = False
    globals_found: list[tuple[str, str]] = []
    str_ops = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
               "SHORT_BINSTRING", "BINSTRING", "STRING"}
    stack: list[str] = []
    for opcode, arg, _pos in ops:
        if opcode.name in str_ops and isinstance(arg, str):
            stack.append(arg)
        elif opcode.name in ("GLOBAL", "STACK_GLOBAL", "INST"):
            if opcode.name == "STACK_GLOBAL" and len(stack) >= 2:
                name = stack.pop()
                mod = stack.pop()
            elif opcode.name in ("GLOBAL", "INST"):
                mod, name = _parse_module_name_arg(arg)
            else:
                mod, name = "?", str(arg)
            globals_found.append((mod, name))
            if is_dangerous_global(mod, name):
                if opcode.name == "INST":
                    result.add(
                        "CRITICAL",
                        f"{prefix}Pickle INST invokes code-execution-capable global "
                        f"'{mod}.{name}' -- concrete call, will run when loaded.",
                    )
                    pending_danger_call = False
                else:
                    result.add(
                        "CRITICAL",
                        f"{prefix}Pickle references code-execution-capable global "
                        f"'{mod}.{name}' -- will run arbitrary code when loaded.",
                    )
                    pending_danger_call = True
            elif not is_allowlisted_global(mod, name, allow_modules):
                result.add(
                    "REVIEW",
                    f"{prefix}Pickle references unrecognized global '{mod}.{name}'. "
                    f"Verify expected before approving.",
                )
        elif opcode.name in CALL_OPCODES and pending_danger_call:
            result.add(
                "CRITICAL",
                f"{prefix}{opcode.name} invokes previously flagged dangerous global "
                f"-- concrete code-execution call, not just a reference.",
            )
            pending_danger_call = False
    if verbose:
        for mod, name in sorted(set(globals_found)):
            result.findings.append(Finding("INFO", f"{prefix}global used: {mod}.{name}"))
    if not globals_found:
        result.findings.append(
            Finding("INFO", f"{prefix}No GLOBAL/INST opcodes found (pure data pickle).")
        )


def _exceeds_max_read(size: int, max_read_bytes: int) -> bool:
    """True when size is over the cap. max_read_bytes <= 0 means unlimited."""
    if max_read_bytes <= 0:
        return False
    return size > max_read_bytes


def scan_pickle_file(
    path: Path,
    result: ScanResult,
    verbose: bool,
    allow_modules: frozenset[str],
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
) -> None:
    size = path.stat().st_size
    if _exceeds_max_read(size, max_read_bytes):
        result.add(
            "REVIEW",
            f"Pickle file size {size:,} bytes exceeds max-read-bytes "
            f"({max_read_bytes:,}); deep scan skipped to avoid memory exhaustion.",
        )
        return
    with open(path, "rb") as f:
        data = f.read()
    scan_pickle_bytes(data, result, verbose, allow_modules)


def scan_pytorch_zip(
    path: Path,
    result: ScanResult,
    verbose: bool,
    allow_modules: frozenset[str],
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            pkl_mems = [n for n in names if n.endswith("data.pkl") or n.endswith(".pkl")]
            if not pkl_mems:
                result.add(
                    "REVIEW",
                    "Zip archive has no data.pkl / .pkl member -- unexpected PyTorch checkpoint structure.",
                )
                return
            for member in pkl_mems:
                info = zf.getinfo(member)
                if _exceeds_max_read(info.file_size, max_read_bytes):
                    result.add(
                        "REVIEW",
                        f"[{member}] Zip pickle member size {info.file_size:,} bytes exceeds "
                        f"max-read-bytes ({max_read_bytes:,}); deep scan skipped.",
                    )
                    continue
                data = zf.read(member)
                scan_pickle_bytes(data, result, verbose, allow_modules, label=member)
            for n in names:
                normalized = _os.path.normpath(n)
                if normalized.startswith("..") or _os.path.isabs(normalized):
                    result.add("CRITICAL", f"Zip member '{n}' uses path traversal -- zip-slip risk on extraction.")
    except zipfile.BadZipFile as e:
        result.add("REVIEW", f"Could not open as zip archive: {e}")


def scan_safetensors(path: Path, result: ScanResult) -> None:
    size = path.stat().st_size
    with open(path, "rb") as f:
        hdr_len_bytes = f.read(8)
        if len(hdr_len_bytes) < 8:
            result.add("CRITICAL", "File too short to contain a valid safetensors header.")
            return
        hdr_len = struct.unpack("<Q", hdr_len_bytes)[0]
        if hdr_len <= 0 or hdr_len > size:
            result.add("CRITICAL", "Safetensors header length invalid (out of file bounds).")
            return
        if hdr_len > 100_000_000:
            result.add("CRITICAL", "Safetensors header claims implausibly large size (>100 MB)")
            return
        hdr_bytes = f.read(hdr_len)
        try:
            header = json.loads(hdr_bytes)
        except json.JSONDecodeError as e:
            result.add("CRITICAL", f"Safetensors header is not valid JSON: {e}")
            return
    metadata = header.get("__metadata__", {})
    if metadata:
        result.findings.append(Finding("INFO", f"Metadata fields present: {list(metadata.keys())}"))
        for k, v in metadata.items():
            if isinstance(v, str) and ("http://" in v or "https://" in v):
                result.add("REVIEW", f"Metadata field '{k}' contains a URL -- review before trusting: {v[:200]}")
    declared_end = 0
    for key, spec in header.items():
        if key == "__metadata__":
            continue
        if not isinstance(spec, dict) or "data_offsets" not in spec:
            result.add("REVIEW", f"Tensor entry '{key}' missing expected 'data_offsets' field.")
            continue
        start, end = spec["data_offsets"]
        declared_end = max(declared_end, end)
    expected_total = 8 + hdr_len + declared_end
    if declared_end and expected_total > size:
        result.add("CRITICAL", "Tensor data offsets extend beyond file size -- truncated or crafted.")
    elif declared_end and expected_total < size - 1024:
        result.add("REVIEW", f"File has {size - expected_total} trailing bytes beyond declared tensor data.")
    num_tensors = len(header) - (1 if "__metadata__" in header else 0)
    result.findings.append(Finding("INFO", f"Safetensors header OK ({num_tensors} tensors)."))


def scan_gguf(path: Path, result: ScanResult) -> None:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC_GGUF:
            result.add("CRITICAL", "File extension mismatch: expected GGUF magic bytes not found.")
            return
        ver_bytes = f.read(4)
        if len(ver_bytes) < 4:
            result.add("CRITICAL", "GGUF file truncated after magic bytes.")
            return
        version = struct.unpack("<I", ver_bytes)[0]
        if version not in (1, 2, 3):
            result.add("REVIEW", f"Unrecognized GGUF version {version} -- parser may be out of date.")
        rest = f.read(16)
        if len(rest) < 16:
            result.add("REVIEW", "GGUF header shorter than expected for tensor/metadata counts.")
            return
        tensor_count, kv_count = struct.unpack("<QQ", rest)
        if tensor_count > 100_000 or kv_count > 100_000:
            result.add("REVIEW", f"GGUF declares unusually high counts (tensors={tensor_count}, kv={kv_count})")
    result.findings.append(Finding("INFO", f"GGUF OK (version={version}, tensors~{tensor_count}, kv~{kv_count})."))


def scan_onnx(
    path: Path,
    result: ScanResult,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
) -> None:
    size = path.stat().st_size
    if _exceeds_max_read(size, max_read_bytes):
        result.add(
            "REVIEW",
            f"ONNX file size {size:,} bytes exceeds max-read-bytes "
            f"({max_read_bytes:,}); deep scan skipped to avoid memory exhaustion.",
        )
        return
    with open(path, "rb") as f:
        data = f.read()
    if b"external_data" in data or b"location" in data:
        idx = 0
        suspicious: list[str] = []
        while True:
            idx = data.find(b"location", idx)
            if idx == -1:
                break
            snippet = data[idx:idx+300]
            for token in snippet.split(b"\x00"):
                s = token.decode("utf-8", errors="ignore")
                if ".." in s or (len(s) > 1 and s.startswith("/")):
                    suspicious.append(s)
            idx += 8
        if suspicious:
            result.add("CRITICAL", f"ONNX external_data location references paths outside model dir: {suspicious[:5]}")
    if b"com.microsoft" in data or b"custom_op" in data.lower():
        result.add(
            "REVIEW",
            "ONNX model references custom/vendor ops -- confirm runtime has trusted op implementation.",
        )
    result.findings.append(Finding("INFO", "ONNX byte-level scan complete (full protobuf validation not performed)."))


def scan_file(
    path: Path,
    verbose: bool,
    allow_modules: frozenset[str],
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
) -> ScanResult:
    fmt = sniff_format(path)
    result = ScanResult(path=str(path), format=fmt, sha256=sha256_of(path), size_bytes=path.stat().st_size)
    try:
        if fmt == "pickle":
            scan_pickle_file(path, result, verbose, allow_modules, max_read_bytes=max_read_bytes)
        elif fmt == "pytorch-zip":
            scan_pytorch_zip(path, result, verbose, allow_modules, max_read_bytes=max_read_bytes)
        elif fmt == "safetensors":
            scan_safetensors(path, result)
        elif fmt == "gguf":
            scan_gguf(path, result)
        elif fmt == "onnx":
            scan_onnx(path, result, max_read_bytes=max_read_bytes)
        else:
            result.add("REVIEW", f"Unrecognized format '{fmt}' -- manual review required.")
    except Exception as e:
        result.add("REVIEW", f"Scanner error while processing file: {e}")
    return result


MODEL_EXTENSIONS = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".safetensors", ".gguf", ".onnx"})


def _path_is_under_root(path: Path, root: Path) -> bool:
    """True if resolved path is root itself or a descendant (path jail)."""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def collect_files(target: Path) -> list[Path]:
    """Collect model files under target without following symlinks out of the tree."""
    if target.is_file():
        return [target]
    if target.is_dir():
        root = target.resolve()
        found: list[Path] = []
        for dirpath, _dirnames, filenames in _os.walk(root, followlinks=False):
            for name in filenames:
                path = Path(dirpath) / name
                if path.is_symlink():
                    continue
                if path.suffix.lower() not in MODEL_EXTENSIONS:
                    continue
                if not path.is_file():
                    continue
                if not _path_is_under_root(path, root):
                    continue
                found.append(path)
        return sorted(found)
    raise FileNotFoundError(f"Path not found: {target}")


VERDICT_SYMBOL = {"SAFE": "\U0001f6a6 SAFE", "REVIEW": "\u26a0\ufe0f REVIEW", "DANGEROUS": "\U0001f6d1 DANGEROUS"}


def print_report(results: list[ScanResult], verbose: bool) -> None:
    for r in results:
        print("=" * 78)
        print(f"File:       {r.path}")
        print(f"Format:     {r.format}")
        print(f"Size:       {r.size_bytes:,} bytes")
        print(f"SHA256:     {r.sha256}")
        print(f"Verdict:    {VERDICT_SYMBOL[r.verdict]}")
        if r.provenance:
            pub = r.provenance.get("publisher")
            allow = r.provenance.get("allowlisted")
            hmatch = r.provenance.get("hash_match")
            if pub is not None or allow is not None or hmatch is not None or r.provenance.get("hf_repo"):
                print("Provenance:")
                if pub is not None:
                    print(f"     publisher:   {pub} (allowlisted={allow})")
                if hmatch is not None:
                    print(f"     hash_match:  {hmatch}")
                if r.provenance.get("hf_repo"):
                    print(f"     hf_repo:     {r.provenance.get('hf_repo')}")
        if r.findings:
            print("Findings:")
            for f in r.findings:
                if f.severity == "INFO" and not verbose:
                    continue
                print(f"     [{f.severity}] {f.detail}")
        if r.behavior_checklist:
            print("Behavior checklist (manual — does not change verdict by itself):")
            for item in r.behavior_checklist:
                print(f"     [ ] {item.get('id')}: {item.get('label')}")
        if r.behavior_results and r.behavior_results.get("probes_run"):
            print(
                f"Behavior probes (DEFERRED path): {r.behavior_results.get('summary')} "
                f"(runtime_model={r.behavior_results.get('ollama_model')})"
            )
    print("=" * 78)
    total = len(results)
    safe = sum(1 for r in results if r.verdict == "SAFE")
    review = sum(1 for r in results if r.verdict == "REVIEW")
    danger = sum(1 for r in results if r.verdict == "DANGEROUS")
    print(f"Summary: {total} file(s) scanned -- {safe} SAFE, {review} REVIEW, {danger} DANGEROUS")


def write_json_report(results: list[ScanResult], out_path: Path) -> None:
    payload = [asdict(r) for r in results]
    out_path.write_text(json.dumps(payload, indent=2))


def _overall_verdict(results: list[ScanResult]) -> str:
    if any(r.verdict == "DANGEROUS" for r in results):
        return "DANGEROUS"
    if any(r.verdict == "REVIEW" for r in results):
        return "REVIEW"
    return "SAFE"


def build_doc_report(
    results: list[ScanResult],
    *,
    target: Optional[str] = None,
    include_info: bool = True,
    generated_at: Optional[str] = None,
) -> str:
    """Build a Markdown documentation report for handoff / audit records."""
    ts = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    overall = _overall_verdict(results)
    total = len(results)
    safe = sum(1 for r in results if r.verdict == "SAFE")
    review = sum(1 for r in results if r.verdict == "REVIEW")
    danger = sum(1 for r in results if r.verdict == "DANGEROUS")

    lines: list[str] = [
        "# Local AI Model Safety Scan Report",
        "",
        f"- **Generated:** {ts}",
        f"- **Scanner version:** {__version__}",
        f"- **Target:** `{target or (results[0].path if results else 'n/a')}`",
        f"- **Overall verdict:** **{overall}**",
        f"- **Files:** {total} scanned — {safe} SAFE, {review} REVIEW, {danger} DANGEROUS",
        "- **Context:** AI department serves models with **vLLM**; weights usually "
        "come from **Hugging Face**.",
        "",
        "## Executive summary",
        "",
    ]
    if overall == "SAFE":
        lines.append(
            "No blocking file-format or integrity issues were reported for the scanned "
            "artifact(s). Analyst should still complete the behavior checklist (and any "
            "optional probes) before manual handoff to the AI department."
        )
    elif overall == "DANGEROUS":
        lines.append(
            "**Do not hand off.** One or more artifacts were marked DANGEROUS "
            "(serialization code-execution risk and/or SHA256 mismatch). Escalate and "
            "quarantine until fully investigated."
        )
    else:
        lines.append(
            "**Manual review required.** One or more artifacts were marked REVIEW "
            "(unknown publisher, inconclusive probes, HF unreachable, unrecognized "
            "pickle globals, etc.). Resolve findings before drop-folder handoff."
        )

    lines += [
        "",
        "## Recommendation (manual process)",
        "",
        "1. Review findings below.",
        "2. Complete the behavior checklist (or attach probe results).",
        "3. If cleared: **manually** copy files to the AI drop folder.",
        "4. **Manually** notify the AI department and attach this report (+ JSON if used).",
        "",
        "---",
        "",
    ]

    for idx, r in enumerate(results, start=1):
        lines += [
            f"## File {idx}: `{Path(r.path).name}`",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Path | `{r.path}` |",
            f"| Format | `{r.format}` |",
            f"| Size | {r.size_bytes:,} bytes |",
            f"| SHA256 | `{r.sha256}` |",
            f"| Verdict | **{r.verdict}** |",
            "",
        ]
        if r.provenance:
            lines += ["### Provenance (Tier 2)", ""]
            prov = r.provenance
            lines.append(f"- **Publisher:** {prov.get('publisher') or '_not provided_'}")
            lines.append(f"- **Allowlisted:** {prov.get('allowlisted')}")
            lines.append(f"- **Hash match:** {prov.get('hash_match')}")
            if prov.get("expected_sha256"):
                lines.append("- **Expected SHA256:**")
                for h in prov["expected_sha256"]:
                    lines.append(f"  - `{h}`")
            if prov.get("manifest_path"):
                lines.append(f"- **Manifest:** `{prov.get('manifest_path')}`")
            if prov.get("hf_repo"):
                lines.append(f"- **HF repo:** `{prov.get('hf_repo')}`")
                lines.append(f"- **Distribution:** {prov.get('distribution')}")
                lines.append(f"- **Serving runtime:** {prov.get('serving_runtime')}")
                hf = prov.get("hf") or {}
                if hf:
                    lines.append(
                        f"- **HF snapshot:** downloads={hf.get('downloads')}, "
                        f"likes={hf.get('likes')}, gated={hf.get('gated')}, "
                        f"library={hf.get('library_name')}, pipeline={hf.get('pipeline_tag')}"
                    )
            elif prov.get("serving_runtime"):
                lines.append(f"- **Serving runtime:** {prov.get('serving_runtime')}")
            lines.append("")

        lines += ["### Findings (Tier 1 / 2 / 3)", ""]
        shown = [f for f in r.findings if include_info or f.severity != "INFO"]
        if not shown:
            lines.append("_No findings at the selected verbosity._")
            lines.append("")
        else:
            lines.append("| Severity | Detail |")
            lines.append("|---|---|")
            for f in shown:
                detail = f.detail.replace("|", "\\|")
                lines.append(f"| {f.severity} | {detail} |")
            lines.append("")

        if r.behavior_checklist:
            lines += [
                "### Behavior checklist (Tier 3 — manual)",
                "",
                "Mark when completed by the analyst:",
                "",
            ]
            for item in r.behavior_checklist:
                lines.append(
                    f"- [ ] **{item.get('id')}** — {item.get('label')}: "
                    f"{item.get('prompt')}"
                )
            lines.append("")

        br = r.behavior_results
        if br and br.get("probes_run"):
            lines += [
                "### Behavior probes (DEFERRED — not part of standard handoff)",
                "",
                f"- **Runtime model tag:** `{br.get('ollama_model')}`",
                f"- **Summary:** {br.get('summary')}",
                "",
            ]
            probe_rows = br.get("results") or []
            if probe_rows:
                lines.append("| Probe ID | Category | Outcome | Detail |")
                lines.append("|---|---|---|---|")
                for row in probe_rows:
                    if isinstance(row, dict):
                        detail = str(row.get("detail", "")).replace("|", "\\|")[:200]
                        lines.append(
                            f"| {row.get('id')} | {row.get('category')} | "
                            f"**{row.get('outcome')}** | {detail} |"
                        )
                lines.append("")

    lines += [
        "---",
        "",
        "## Analyst sign-off",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Analyst name |  |",
        "| Date |  |",
        "| Final decision | APPROVE / REJECT / ESCALATE |",
        "| Drop-folder path |  |",
        "| AI dept notified | Yes / No |",
        "| Notes |  |",
        "",
        "---",
        "",
        f"_Generated by model-scanner {__version__}. "
        "This report documents checks performed; it is not a warranty of model safety._",
        "",
    ]
    return "\n".join(lines)


def write_doc_report(
    results: list[ScanResult],
    out_path: Path,
    *,
    target: Optional[str] = None,
    include_info: bool = True,
) -> None:
    text = build_doc_report(results, target=target, include_info=include_info)
    out_path.write_text(text, encoding="utf-8")


def _gate_allows_probes(results: list[ScanResult], strict: bool) -> bool:
    if any(r.verdict == "DANGEROUS" for r in results):
        return False
    if strict and any(r.verdict == "REVIEW" for r in results):
        return False
    return True


def apply_tier2(
    results: list[ScanResult],
    *,
    publisher: Optional[str],
    expected_sha256: list[str],
    manifest: Optional[dict[str, Any]],
    manifest_path: Optional[Path],
    hf_repo: Optional[str],
    allowlist_path: Optional[Path],
    serving_runtime: str = "vllm",
    scan_root: Optional[Path] = None,
) -> None:
    allowlist = trust_mod.load_allowlist(allowlist_path)
    effective_publisher = publisher
    if not effective_publisher and manifest and isinstance(manifest.get("publisher"), str):
        effective_publisher = manifest["publisher"]

    for r in results:
        path = Path(r.path)
        expected, basename_only = trust_mod.expected_hashes_for_file(
            path,
            expected_sha256,
            manifest,
            scan_root=scan_root,
        )
        if basename_only:
            r.add(
                "REVIEW",
                "Manifest digest matched by basename only (prefer a relative path key "
                f"under the scan root for '{path.name}'). Ambiguous in nested trees.",
            )
        prov = trust_mod.build_provenance(
            result=r,
            publisher=effective_publisher,
            allowlist=allowlist,
            expected=expected,
            manifest_path=manifest_path,
            hf_repo=hf_repo,
            Finding=Finding,
            serving_runtime=serving_runtime,
        )
        r.provenance = trust_mod.provenance_asdict(prov)


def apply_tier3_probes(
    results: list[ScanResult],
    *,
    ollama_model: str,
    ollama_host: str,
) -> None:
    # Attach probe results to the first result for a single shared runtime check;
    # findings that affect verdict are added there. Other files get a pointer summary.
    if not results:
        return
    primary = results[0]
    report = behavior_mod.run_behavior_probes(
        model=ollama_model,
        Finding=Finding,
        result=primary,
        host=ollama_host,
    )
    payload = behavior_mod.behavior_asdict(report)
    primary.behavior_results = payload
    for r in results[1:]:
        r.behavior_results = {
            "probes_run": report.probes_run,
            "ollama_model": ollama_model,
            "summary": report.summary,
            "note": f"See primary file report: {primary.path}",
            "checklist": r.behavior_checklist,
            "results": [],
        }


def cli() -> int:
    parser = argparse.ArgumentParser(
        description="Local AI model safety scanner (file format + optional trust/behavior tiers).",
    )
    parser.add_argument("target", help="Path to a model file or directory to scan.")
    parser.add_argument("--report", metavar="OUT.json", help="Write a machine-readable JSON report.")
    parser.add_argument(
        "--doc-report",
        metavar="OUT.md",
        help="Write a Markdown documentation / handoff report for audit records.",
    )
    parser.add_argument("--strict", action="store_true", help="Treat REVIEW as failure.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all findings.")
    parser.add_argument("--allow-module", action="append", default=[], metavar="MODULE",
                        help="Add a pickle module to the trusted allowlist (repeatable).")
    # Tier 2
    parser.add_argument("--publisher", metavar="ID",
                        help="Publisher id to check against config/publishers.allowlist.json")
    parser.add_argument("--allowlist", metavar="PATH.json",
                        help="Override path to publisher allowlist JSON.")
    parser.add_argument("--expected-sha256", action="append", default=[], metavar="HEX",
                        help="Expected SHA256 digest (repeatable). Mismatch -> DANGEROUS.")
    parser.add_argument("--manifest", metavar="PATH.json",
                        help="JSON manifest with publisher and/or files{name: sha256}.")
    parser.add_argument("--hf-repo", metavar="ORG/NAME",
                        help="Hugging Face repo id (AI dept pull source) for metadata / LFS hash checks.")
    parser.add_argument(
        "--serving-runtime",
        default="vllm",
        metavar="NAME",
        help="Intended AI-dept serving runtime (default: vllm).",
    )
    parser.add_argument(
        "--max-read-bytes",
        type=int,
        default=DEFAULT_MAX_READ_BYTES,
        metavar="N",
        help=(
            "Max bytes to fully load for pickle/ONNX/zip-pickle scans "
            f"(default: {DEFAULT_MAX_READ_BYTES}). Use 0 for unlimited."
        ),
    )
    # DEFERRED: optional experimental probes (not part of standard vLLM/HF handoff)
    parser.add_argument(
        "--experimental-behavior-probes",
        action="store_true",
        help=argparse.SUPPRESS,  # deferred — hidden from --help
    )
    parser.add_argument("--experimental-probe-model", metavar="NAME", help=argparse.SUPPRESS)
    parser.add_argument(
        "--experimental-probe-host",
        default="http://127.0.0.1:11434",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    if args.experimental_behavior_probes and not args.experimental_probe_model:
        print(
            "error: --experimental-behavior-probes requires --experimental-probe-model "
            "(deferred feature; not used in standard vLLM handoff)",
            file=sys.stderr,
        )
        return 2

    if args.hf_repo and not trust_mod.validate_hf_repo_id(args.hf_repo):
        print(
            f"error: invalid --hf-repo {args.hf_repo!r}; expected ORG/NAME "
            "(letters, digits, ., _, - only)",
            file=sys.stderr,
        )
        return 2

    if args.max_read_bytes < 0:
        print("error: --max-read-bytes must be >= 0 (0 = unlimited)", file=sys.stderr)
        return 2

    target = Path(args.target).expanduser().resolve()
    try:
        files = collect_files(target)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not files:
        print(f"No recognized model files found under: {target}", file=sys.stderr)
        return 2

    allow_modules = frozenset(args.allow_module)
    results = [
        scan_file(p, args.verbose, allow_modules, max_read_bytes=args.max_read_bytes)
        for p in files
    ]

    manifest = None
    manifest_path = None
    if args.manifest:
        manifest_path = Path(args.manifest).expanduser().resolve()
        try:
            manifest = trust_mod.load_manifest(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error: could not load manifest: {e}", file=sys.stderr)
            return 2

    allowlist_path = Path(args.allowlist).expanduser().resolve() if args.allowlist else None
    scan_root = target if target.is_dir() else target.parent
    apply_tier2(
        results,
        publisher=args.publisher,
        expected_sha256=list(args.expected_sha256),
        manifest=manifest,
        manifest_path=manifest_path,
        hf_repo=args.hf_repo,
        allowlist_path=allowlist_path,
        serving_runtime=args.serving_runtime,
        scan_root=scan_root,
    )

    if args.experimental_behavior_probes:
        print(
            "NOTE: experimental behavior probes are TEMPORARILY DEFERRED from the "
            "standard HF → vLLM handoff. Prefer the checklist + AI-dept vLLM testbed.",
            file=sys.stderr,
        )
        if _gate_allows_probes(results, args.strict):
            apply_tier3_probes(
                results,
                ollama_model=args.experimental_probe_model,
                ollama_host=args.experimental_probe_host,
            )
        else:
            print(
                "Skipping experimental probes: file/trust gate did not pass.",
                file=sys.stderr,
            )

    print_report(results, args.verbose)
    if args.report:
        out_path = Path(args.report).expanduser().resolve()
        write_json_report(results, out_path)
        print(f"\nJSON report written to: {out_path}")
    if args.doc_report:
        doc_path = Path(args.doc_report).expanduser().resolve()
        write_doc_report(
            results,
            doc_path,
            target=str(target),
            include_info=args.verbose,
        )
        print(f"Documentation report written to: {doc_path}")
    has_dangerous = any(r.verdict == "DANGEROUS" for r in results)
    has_review = any(r.verdict == "REVIEW" for r in results)
    if has_dangerous or (args.strict and has_review):
        return 1
    return 0


def main() -> int:
    """Compat alias -- identical to cli()."""
    return cli()


if __name__ == "__main__":
    sys.exit(cli())
