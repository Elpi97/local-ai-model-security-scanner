"""Tier 2: publisher allowlist, hash integrity, optional Hugging Face metadata."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

_DEFAULT_ALLOWLIST = Path(__file__).resolve().parent / "config" / "publishers.allowlist.json"

# Hugging Face model ids are ORG/NAME with a constrained character set.
_HF_REPO_ID_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)


@dataclass
class Provenance:
    publisher: Optional[str] = None
    allowlisted: Optional[bool] = None
    expected_sha256: list[str] = field(default_factory=list)
    hash_match: Optional[bool] = None
    matched_expected: Optional[str] = None
    manifest_path: Optional[str] = None
    hf_repo: Optional[str] = None
    hf: Optional[dict[str, Any]] = None
    distribution: Optional[str] = None  # e.g. huggingface
    serving_runtime: Optional[str] = None  # e.g. vllm


def validate_hf_repo_id(repo_id: str) -> bool:
    """Return True if repo_id looks like a safe Hugging Face ORG/NAME id."""
    return bool(repo_id) and bool(_HF_REPO_ID_RE.fullmatch(repo_id.strip()))


def load_allowlist(path: Optional[Path] = None) -> dict[str, str]:
    """Return mapping publisher_id -> note."""
    allow_path = path or _DEFAULT_ALLOWLIST
    if not allow_path.is_file():
        return {}
    data = json.loads(allow_path.read_text(encoding="utf-8"))
    publishers = data.get("publishers", data)
    if isinstance(publishers, list):
        out: dict[str, str] = {}
        for item in publishers:
            if isinstance(item, str):
                out[item] = ""
            elif isinstance(item, dict) and "id" in item:
                out[str(item["id"])] = str(item.get("note", ""))
        return out
    if isinstance(publishers, dict):
        return {str(k): str(v) for k, v in publishers.items()}
    return {}


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object")
    return data


def _append_digest(expected: list[str], digest: Any) -> None:
    if isinstance(digest, str) and digest.strip():
        expected.append(digest.lower().strip())
    elif isinstance(digest, dict) and "sha256" in digest:
        expected.append(str(digest["sha256"]).lower().strip())


def expected_hashes_for_file(
    path: Path,
    cli_expected: list[str],
    manifest: Optional[dict[str, Any]],
    scan_root: Optional[Path] = None,
) -> tuple[list[str], bool]:
    """Collect expected digests from CLI and manifest file entries.

    Returns ``(digests, basename_only_match)``. Prefer exact relative path keys
    under ``scan_root``. A key that is only the basename still applies the digest
    for compatibility but sets ``basename_only_match`` so callers can REVIEW.
    """
    expected = [h.lower().strip() for h in cli_expected if h and h.strip()]
    basename_only = False
    if not manifest:
        return list(dict.fromkeys(expected)), False
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        return list(dict.fromkeys(expected)), False

    name = path.name
    resolved = str(path.resolve()) if path.exists() else str(path)
    rel: Optional[str] = None
    if scan_root is not None:
        try:
            rel = path.resolve().relative_to(scan_root.resolve()).as_posix()
        except ValueError:
            try:
                rel = path.relative_to(scan_root).as_posix()
            except ValueError:
                rel = None

    exact_matched = False
    for key, digest in files.items():
        key_s = str(key).replace("\\", "/")
        if key_s == resolved or (rel is not None and key_s == rel) or key_s == str(path):
            _append_digest(expected, digest)
            exact_matched = True

    if not exact_matched:
        for key, digest in files.items():
            key_s = str(key).replace("\\", "/")
            # Basename-tier only when the key itself is a bare filename.
            if "/" not in key_s and key_s == name:
                _append_digest(expected, digest)
                basename_only = True

    return list(dict.fromkeys(expected)), basename_only


def fetch_hf_metadata(repo_id: str, timeout: float = 15.0) -> dict[str, Any]:
    """Fetch public model metadata from the Hugging Face Hub API."""
    if not validate_hf_repo_id(repo_id):
        raise ValueError(f"Invalid Hugging Face repo id: {repo_id!r}")
    url = f"https://huggingface.co/api/models/{repo_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "model-scanner/0.4.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    siblings = data.get("siblings") or []
    sibling_shas: list[dict[str, str]] = []
    for s in siblings:
        if not isinstance(s, dict):
            continue
        entry: dict[str, str] = {"rfilename": str(s.get("rfilename", ""))}
        lfs = s.get("lfs")
        if isinstance(lfs, dict) and lfs.get("sha256"):
            entry["sha256"] = str(lfs["sha256"])
        if s.get("size") is not None:
            entry["size"] = str(s["size"])
        sibling_shas.append(entry)
    return {
        "id": data.get("id") or repo_id,
        "author": data.get("author"),
        "downloads": data.get("downloads"),
        "likes": data.get("likes"),
        "pipeline_tag": data.get("pipeline_tag"),
        "library_name": data.get("library_name"),
        "gated": data.get("gated"),
        "tags": data.get("tags") or [],
        "siblings": sibling_shas[:50],
        "lastModified": data.get("lastModified"),
    }


def match_file_to_hf_siblings(
    *,
    path: Path,
    sha256: str,
    siblings: list[dict[str, str]],
) -> tuple[Optional[bool], Optional[str]]:
    """Return (match, sibling_name). True/False if a named LFS digest exists; None if none."""
    actual = sha256.lower()
    name = path.name
    for sib in siblings:
        rfilename = str(sib.get("rfilename") or "")
        sib_sha = str(sib.get("sha256") or "").lower()
        if not sib_sha:
            continue
        if Path(rfilename).name == name:
            return (sib_sha == actual), rfilename
    for sib in siblings:
        rfilename = str(sib.get("rfilename") or "")
        sib_sha = str(sib.get("sha256") or "").lower()
        if sib_sha and sib_sha == actual:
            return True, rfilename
    return None, None


def build_provenance(
    *,
    result: Any,
    publisher: Optional[str],
    allowlist: dict[str, str],
    expected: list[str],
    manifest_path: Optional[Path],
    hf_repo: Optional[str],
    Finding: type,
    serving_runtime: Optional[str] = "vllm",
) -> Provenance:
    """Apply Tier-2 checks onto result findings; return Provenance for the report."""
    prov = Provenance(
        expected_sha256=list(expected),
        manifest_path=str(manifest_path) if manifest_path else None,
        hf_repo=hf_repo,
        distribution="huggingface" if hf_repo else None,
        serving_runtime=serving_runtime,
    )

    if expected:
        actual = result.sha256.lower()
        if actual in expected:
            prov.hash_match = True
            prov.matched_expected = actual
            result.findings.append(Finding("INFO", f"SHA256 matches expected digest: {actual}"))
        else:
            prov.hash_match = False
            result.add(
                "CRITICAL",
                f"SHA256 mismatch: got {actual}, expected one of {expected}. "
                "Possible weight swap or wrong file.",
            )

    if publisher:
        prov.publisher = publisher
        if publisher in allowlist:
            prov.allowlisted = True
            note = allowlist[publisher]
            detail = f"Publisher '{publisher}' is on the allowlist."
            if note:
                detail += f" Note: {note}"
            result.findings.append(Finding("INFO", detail))
        else:
            prov.allowlisted = False
            result.add(
                "REVIEW",
                f"Publisher '{publisher}' is not on the allowlist. "
                "Confirm legitimacy before handoff.",
            )

    if hf_repo:
        prov.distribution = "huggingface"
        try:
            meta = fetch_hf_metadata(hf_repo)
            prov.hf = meta
            result.findings.append(
                Finding(
                    "INFO",
                    f"HF repo '{meta.get('id')}': downloads={meta.get('downloads')}, "
                    f"likes={meta.get('likes')}, gated={meta.get('gated')}, "
                    f"library={meta.get('library_name')}, pipeline={meta.get('pipeline_tag')}.",
                )
            )
            if serving_runtime == "vllm":
                result.findings.append(
                    Finding(
                        "INFO",
                        "Intended serving runtime: vLLM. Prefer safetensors weights; "
                        "avoid legacy pickle checkpoints when possible.",
                    )
                )
            match, sib_name = match_file_to_hf_siblings(
                path=Path(result.path),
                sha256=result.sha256,
                siblings=list(meta.get("siblings") or []),
            )
            if match is True:
                result.findings.append(
                    Finding("INFO", f"SHA256 matches HF sibling file '{sib_name}'.")
                )
                if prov.hash_match is None:
                    prov.hash_match = True
                    prov.matched_expected = result.sha256.lower()
            elif match is False:
                prov.hash_match = False
                result.add(
                    "CRITICAL",
                    f"SHA256 does not match Hugging Face sibling '{sib_name}'. "
                    "Possible weight swap vs the Hub revision you intended.",
                )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            json.JSONDecodeError,
            OSError,
            ValueError,
        ) as e:
            result.add(
                "REVIEW",
                f"Hugging Face metadata unreachable for '{hf_repo}': {e}. "
                "Could not enrich provenance (offline or invalid repo).",
            )

    return prov


def provenance_asdict(prov: Provenance) -> dict[str, Any]:
    return asdict(prov)
