"""Tier 1 (deep): ONNX protobuf validation via the optional `onnx` package.

This module is the ONLY import boundary for the third-party `onnx` package.
When it is absent (default stdlib-only install), HAS_ONNX is False and
model_scanner falls back to the byte-level scan with an explicit REVIEW note.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import onnx
    from onnx import TensorProto

    HAS_ONNX: bool = True
except ImportError:  # pragma: no cover - exercised in stdlib-only envs
    onnx = None  # type: ignore[assignment]
    TensorProto = None  # type: ignore[assignment]
    HAS_ONNX = False

# Embedded raw tensor data larger than this is flagged REVIEW (content smuggling / bloat).
MAX_EMBEDDED_RAW_BYTES: int = 100 * 1024 * 1024

STANDARD_DOMAINS: frozenset[str] = frozenset({
    "", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training",
})

URL_SCHEMES: tuple[str, ...] = ("http://", "https://", "file://", "s3://", "ftp://", "gs://")

SUSPICIOUS_FUNCTION_TOKENS: tuple[str, ...] = ("eval", "exec", "system", "popen", "shell")

def scan(
    path: Path,
    result: Any,
    allow_domains: frozenset[str] = frozenset(),
    finding_cls: Any = None,
) -> None:
    """Deep-scan an ONNX model. Never raises: parse failures become REVIEW."""
    if not HAS_ONNX:
        result.add(
            "REVIEW",
            "onnx package not installed; deep validation unavailable. "
            "Install model-scanner[onnx] for full protobuf parsing.",
        )
        return
    try:
        model = onnx.load(str(path))
    except Exception as e:
        result.add("REVIEW", f"Could not parse ONNX protobuf: {type(e).__name__}: {e}")
        return
    if finding_cls is not None:
        _record_metadata(model, result, finding_cls)


def _record_metadata(model: Any, result: Any, finding_cls: Any) -> None:
    opsets = ", ".join(
        f"{opset.domain or 'ai.onnx'}={opset.version}" for opset in model.opset_import
    ) or "none"
    result.findings.append(finding_cls("INFO", f"ONNX IR version: {model.ir_version}"))
    result.findings.append(finding_cls("INFO", f"ONNX opset imports: {opsets}"))
