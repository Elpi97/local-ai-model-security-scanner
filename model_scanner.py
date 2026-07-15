#!/usr/bin/env python3
"""
Static safety scanner for local AI model files (pickle/PyTorch, safetensors, GGUF, ONNX).
This tool NEVER executes, unpickles, or loads any model. It uses pickletools.genops()
to statically disassemble opcodes and report what would happen *if* loaded.

Usage:   model-scanner <file-or-directory> [options]
Exit codes: 0=SAFE, 1=DANGEROUS, 2=error
"""

from __future__ import annotations

__version__: str = "0.1.0"


import argparse
import hashlib
import json
import os as _os
import pickletools
import struct
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path


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


def scan_pickle_file(path: Path, result: ScanResult, verbose: bool, allow_modules: frozenset[str]) -> None:
    with open(path, "rb") as f:
        data = f.read()
    scan_pickle_bytes(data, result, verbose, allow_modules)


def scan_pytorch_zip(path: Path, result: ScanResult, verbose: bool, allow_modules: frozenset[str]) -> None:
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


def scan_onnx(path: Path, result: ScanResult) -> None:
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


def scan_file(path: Path, verbose: bool, allow_modules: frozenset[str]) -> ScanResult:
    fmt = sniff_format(path)
    result = ScanResult(path=str(path), format=fmt, sha256=sha256_of(path), size_bytes=path.stat().st_size)
    try:
        if fmt == "pickle":
            scan_pickle_file(path, result, verbose, allow_modules)
        elif fmt == "pytorch-zip":
            scan_pytorch_zip(path, result, verbose, allow_modules)
        elif fmt == "safetensors":
            scan_safetensors(path, result)
        elif fmt == "gguf":
            scan_gguf(path, result)
        elif fmt == "onnx":
            scan_onnx(path, result)
        else:
            result.add("REVIEW", f"Unrecognized format '{fmt}' -- manual review required.")
    except Exception as e:
        result.add("REVIEW", f"Scanner error while processing file: {e}")
    return result


MODEL_EXTENSIONS = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".safetensors", ".gguf", ".onnx"})


def collect_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in MODEL_EXTENSIONS)
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
        if r.findings:
            print("Findings:")
            for f in r.findings:
                if f.severity == "INFO" and not verbose:
                    continue
                print(f"     [{f.severity}] {f.detail}")
    print("=" * 78)
    total = len(results)
    safe = sum(1 for r in results if r.verdict == "SAFE")
    review = sum(1 for r in results if r.verdict == "REVIEW")
    danger = sum(1 for r in results if r.verdict == "DANGEROUS")
    print(f"Summary: {total} file(s) scanned -- {safe} SAFE, {review} REVIEW, {danger} DANGEROUS")


def write_json_report(results: list[ScanResult], out_path: Path) -> None:
    payload = [asdict(r) for r in results]
    out_path.write_text(json.dumps(payload, indent=2))


def cli() -> int:
    parser = argparse.ArgumentParser(description="Static safety scanner for local AI model files.")
    parser.add_argument("target", help="Path to a model file or directory to scan.")
    parser.add_argument("--report", metavar="OUT.json", help="Write a JSON report.")
    parser.add_argument("--strict", action="store_true", help="Treat REVIEW as failure.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all findings.")
    parser.add_argument("--allow-module", action="append", default=[], metavar="MODULE",
                        help="Add a module to the trusted allowlist (repeatable).")
    args = parser.parse_args()
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
    results = [scan_file(p, args.verbose, allow_modules) for p in files]
    print_report(results, args.verbose)
    if args.report:
        out_path = Path(args.report).expanduser().resolve()
        write_json_report(results, out_path)
        print(f"\nJSON report written to: {out_path}")
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
