#!/usr/bin/env python3
"""Tests for model_scanner."""

from __future__ import annotations

import json
import pickle
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

import model_scanner as ms


def _scan_bytes(data: bytes, verbose: bool = False) -> ms.ScanResult:
    result = ms.ScanResult(path="memory", format="pickle", sha256="0", size_bytes=len(data))
    ms.scan_pickle_bytes(data, result, verbose, frozenset())
    return result


def _write_and_scan(tmp: Path, name: str, data: bytes) -> ms.ScanResult:
    path = tmp / name
    path.write_bytes(data)
    return ms.scan_file(path, verbose=False, allow_modules=frozenset())


class TestAllowlistBoundaries(unittest.TestCase):
    def test_numpy_core_is_allowlisted(self) -> None:
        data = b"cnumpy.core.multiarray\n_reconstruct\n."
        self.assertEqual(_scan_bytes(data).verdict, "SAFE")

    def test_numpyevil_prefix_bypass_is_review(self) -> None:
        data = b"cnumpyevil\nhack\n."
        self.assertEqual(_scan_bytes(data).verdict, "REVIEW")

    def test_collections_evil_prefix_bypass_is_review(self) -> None:
        data = b"ccollections_evil\nhack\n."
        self.assertEqual(_scan_bytes(data).verdict, "REVIEW")

    def test_torch_evil_underscore_prefix_is_review(self) -> None:
        data = b"ctorch_evil\nhack\n."
        self.assertEqual(_scan_bytes(data).verdict, "REVIEW")

    def test_torch_nn_is_allowlisted(self) -> None:
        data = b"ctorch.nn\nModule\n."
        self.assertEqual(_scan_bytes(data).verdict, "SAFE")


class TestDangerousPickle(unittest.TestCase):
    def test_os_system_reduce_is_dangerous(self) -> None:
        data = b"cos\nsystem\n(S'id'\ntR."
        result = _scan_bytes(data)
        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertTrue(any(f.severity == "CRITICAL" for f in result.findings))

    def test_inst_opcode_is_dangerous(self) -> None:
        """INST invokes immediately — must not be treated as a pure-data pickle."""
        data = b"ios\nsystem\n(S'id'\nt."
        result = _scan_bytes(data)
        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertTrue(any("INST" in f.detail for f in result.findings if f.severity == "CRITICAL"))

    def test_builtins_eval_is_dangerous(self) -> None:
        data = b"cbuiltins\neval\n(S'1+1'\ntR."
        self.assertEqual(_scan_bytes(data).verdict, "DANGEROUS")

    def test_dangerous_submodule_os_path_is_dangerous(self) -> None:
        data = b"cos.path\njoin\n."
        self.assertEqual(_scan_bytes(data).verdict, "DANGEROUS")

    def test_safe_dict_pickle(self) -> None:
        data = pickle.dumps({"weights": [1, 2, 3]})
        self.assertEqual(_scan_bytes(data).verdict, "SAFE")


class TestFormats(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_safetensors_ok(self) -> None:
        header = b'{"t":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        data = struct.pack("<Q", len(header)) + header + b"\x00\x00\x00\x00"
        result = _write_and_scan(self.tmp, "m.safetensors", data)
        self.assertEqual(result.format, "safetensors")
        self.assertEqual(result.verdict, "SAFE")

    def test_safetensors_truncated_offsets(self) -> None:
        header = b'{"t":{"dtype":"F32","shape":[1],"data_offsets":[0,99999]}}'
        data = struct.pack("<Q", len(header)) + header
        result = _write_and_scan(self.tmp, "bad.safetensors", data)
        self.assertEqual(result.verdict, "DANGEROUS")

    def test_gguf_ok(self) -> None:
        # magic + version 3 + tensor_count=0 + kv_count=0
        data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<QQ", 0, 0)
        result = _write_and_scan(self.tmp, "m.gguf", data)
        self.assertEqual(result.format, "gguf")
        self.assertEqual(result.verdict, "SAFE")

    def test_gguf_wrong_magic_via_extension(self) -> None:
        result = _write_and_scan(self.tmp, "fake.gguf", b"NOTG" + b"\x00" * 20)
        self.assertEqual(result.format, "gguf")
        self.assertEqual(result.verdict, "DANGEROUS")

    def test_pytorch_zip_safe(self) -> None:
        path = self.tmp / "model.pt"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("archive/data.pkl", pickle.dumps({"w": 1}))
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.format, "pytorch-zip")
        self.assertEqual(result.verdict, "SAFE")

    def test_zip_slip_is_dangerous(self) -> None:
        path = self.tmp / "slip.pt"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("../evil.pkl", pickle.dumps(1))
            zf.writestr("archive/data.pkl", pickle.dumps(1))
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.verdict, "DANGEROUS")

    def test_pytorch_zip_with_evil_pickle(self) -> None:
        path = self.tmp / "evil.pt"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("archive/data.pkl", b"cos\nsystem\n(S'id'\ntR.")
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.verdict, "DANGEROUS")


class TestCliHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_collect_files_filters_extensions(self) -> None:
        (self.tmp / "a.pt").write_bytes(pickle.dumps(1))
        (self.tmp / "notes.txt").write_text("hi")
        (self.tmp / "b.safetensors").write_bytes(b"\x00" * 8)
        files = ms.collect_files(self.tmp)
        names = {p.name for p in files}
        self.assertEqual(names, {"a.pt", "b.safetensors"})

    def test_json_report_roundtrip(self) -> None:
        path = self.tmp / "safe.pkl"
        path.write_bytes(pickle.dumps({"ok": True}))
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        out = self.tmp / "report.json"
        ms.write_json_report([result], out)
        payload = json.loads(out.read_text())
        self.assertEqual(payload[0]["verdict"], "SAFE")
        self.assertEqual(payload[0]["format"], "pickle")

    def test_allow_module_suppresses_review(self) -> None:
        data = b"cmy_pkg\nConfig\n."
        result = ms.ScanResult("m", "pickle", "0", 0)
        ms.scan_pickle_bytes(data, result, False, frozenset(["my_pkg"]))
        self.assertEqual(result.verdict, "SAFE")


class TestHelperPredicates(unittest.TestCase):
    def test_module_boundary_helper(self) -> None:
        self.assertTrue(ms._module_is_or_under("numpy", "numpy"))
        self.assertTrue(ms._module_is_or_under("numpy.core", "numpy"))
        self.assertFalse(ms._module_is_or_under("numpyevil", "numpy"))
        self.assertFalse(ms._module_is_or_under("torchevil", "torch"))


if __name__ == "__main__":
    unittest.main()
