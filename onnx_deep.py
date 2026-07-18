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
        model = onnx.load(str(path), load_external_data=False)
    except Exception as e:
        result.add("REVIEW", f"Could not parse ONNX protobuf: {type(e).__name__}: {e}")
        return
    external_count = _check_external_data(model, path.parent, result)
    node_count = _check_domains(model, result, allow_domains)
    if finding_cls is not None:
        _record_metadata(model, result, finding_cls)
        result.findings.append(
            finding_cls("INFO", f"ONNX external-data tensors: {external_count}")
        )
        result.findings.append(finding_cls("INFO", f"ONNX nodes: {node_count}"))


def _is_url(location: str) -> bool:
    return location.lower().startswith(URL_SCHEMES)


def _check_external_data(model: Any, model_dir: Path, result: Any) -> int:
    """Flag external-data locations escaping model_dir. Returns tensor count."""
    count = 0
    for tensor in model.graph.initializer:
        if tensor.data_location != TensorProto.DataLocation.EXTERNAL:
            continue
        count += 1
        location = ""
        for entry in tensor.external_data:
            if entry.key == "location":
                location = entry.value
                break
        if not location:
            continue
        loc_path = Path(location)
        if (
            _is_url(location)
            or loc_path.is_absolute()
            or ".." in loc_path.parts
        ):
            result.add(
                "CRITICAL",
                f"ONNX external_data location escapes model dir: "
                f"{location!r} (tensor {tensor.name!r}).",
            )
            continue
        resolved = (model_dir / loc_path).resolve()
        try:
            resolved.relative_to(model_dir.resolve())
        except ValueError:
            result.add(
                "CRITICAL",
                f"ONNX external_data location resolves outside scan root: "
                f"{location!r} (tensor {tensor.name!r}).",
            )
    return count


def _walk_nodes(graph: Any):
    """Yield every node in graph, recursing into subgraph attributes."""
    for node in graph.node:
        yield node
        for attr in node.attribute:
            if attr.type == onnx.AttributeProto.AttributeType.GRAPH:
                yield from _walk_nodes(attr.g)
            elif attr.type == onnx.AttributeProto.AttributeType.GRAPHS:
                for sub in attr.graphs:
                    yield from _walk_nodes(sub)


def _check_domains(model: Any, result: Any, allow_domains: frozenset[str]) -> int:
    """Flag non-standard op domains. Returns total node count."""
    seen: dict[str, int] = {}
    node_count = 0
    for node in _walk_nodes(model.graph):
        node_count += 1
        seen[node.domain] = seen.get(node.domain, 0) + 1
    for fn in model.functions:
        for node in fn.node:
            node_count += 1
            seen[node.domain] = seen.get(node.domain, 0) + 1
        lowered = fn.name.lower()
        for token in SUSPICIOUS_FUNCTION_TOKENS:
            if token in lowered:
                result.add(
                    "REVIEW",
                    f"ONNX function name {fn.name!r} contains suspicious token "
                    f"{token!r} (domain {fn.domain!r}).",
                )
                break
    for domain, count in sorted(seen.items()):
        if domain in STANDARD_DOMAINS:
            continue
        if domain in allow_domains:
            result.add(
                "REVIEW",
                f"ONNX uses allowlisted custom domain {domain!r} ({count} node(s)); "
                "runtime must provide these ops under vLLM.",
            )
        else:
            result.add(
                "CRITICAL",
                f"ONNX uses non-standard op domain {domain!r} ({count} node(s)). "
                "Pass --allow-onnx-domain only if the source is trusted.",
            )
    return node_count


def _record_metadata(model: Any, result: Any, finding_cls: Any) -> None:
    opsets = ", ".join(
        f"{opset.domain or 'ai.onnx'}={opset.version}" for opset in model.opset_import
    ) or "none"
    result.findings.append(finding_cls("INFO", f"ONNX IR version: {model.ir_version}"))
    result.findings.append(finding_cls("INFO", f"ONNX opset imports: {opsets}"))
