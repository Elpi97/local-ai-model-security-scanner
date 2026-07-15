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

    def test_doc_report_markdown(self) -> None:
        path = self.tmp / "safe.pkl"
        path.write_bytes(pickle.dumps({"ok": True}))
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        ms.apply_tier2(
            [result],
            publisher="google",
            expected_sha256=[result.sha256],
            manifest=None,
            manifest_path=None,
            hf_repo=None,
            allowlist_path=None,
        )
        # use default allowlist — google should be allowlisted
        text = ms.build_doc_report(
            [result],
            target=str(path),
            include_info=True,
            generated_at="2026-07-15 00:00:00 UTC",
        )
        out = self.tmp / "handoff.md"
        ms.write_doc_report([result], out, target=str(path))
        self.assertTrue(out.is_file())
        self.assertIn("# Local AI Model Safety Scan Report", text)
        self.assertIn("Overall verdict", text)
        self.assertIn("Analyst sign-off", text)
        self.assertIn("Behavior checklist", text)
        self.assertIn(result.sha256, text)

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


class TestSizeCaps(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_oversize_pickle_is_review_without_deep_scan(self) -> None:
        path = self.tmp / "big.pkl"
        # Dangerous payload would be DANGEROUS if scanned; size cap must skip it.
        path.write_bytes(b"cos\nsystem\n(S'id'\ntR." + b"\x00" * 100)
        result = ms.scan_file(
            path, verbose=False, allow_modules=frozenset(), max_read_bytes=32
        )
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("max-read-bytes" in f.detail for f in result.findings))
        self.assertFalse(any(f.severity == "CRITICAL" for f in result.findings))

    def test_oversize_onnx_is_review(self) -> None:
        path = self.tmp / "big.onnx"
        path.write_bytes(b"ONNX" + b"\x00" * 200)
        result = ms.scan_file(
            path, verbose=False, allow_modules=frozenset(), max_read_bytes=64
        )
        self.assertEqual(result.format, "onnx")
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("max-read-bytes" in f.detail for f in result.findings))

    def test_oversize_zip_pickle_member_is_review(self) -> None:
        path = self.tmp / "big.pt"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("archive/data.pkl", b"x" * 500)
        result = ms.scan_file(
            path, verbose=False, allow_modules=frozenset(), max_read_bytes=100
        )
        self.assertEqual(result.format, "pytorch-zip")
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("max-read-bytes" in f.detail for f in result.findings))

    def test_max_read_bytes_zero_is_unlimited(self) -> None:
        path = self.tmp / "ok.pkl"
        path.write_bytes(pickle.dumps({"ok": True}))
        result = ms.scan_file(
            path, verbose=False, allow_modules=frozenset(), max_read_bytes=0
        )
        self.assertEqual(result.verdict, "SAFE")


class TestCollectFilesSymlinks(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_rejects_symlink_outside_scan_root(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        escape_target = outside / "escaped.pkl"
        escape_target.write_bytes(pickle.dumps(1))

        scan_root = self.tmp / "incoming"
        scan_root.mkdir()
        (scan_root / "legit.pkl").write_bytes(pickle.dumps({"ok": True}))
        link = scan_root / "link.pkl"
        try:
            link.symlink_to(escape_target)
        except OSError:
            self.skipTest("symlinks not supported on this platform/filesystem")

        names = {p.name for p in ms.collect_files(scan_root)}
        self.assertEqual(names, {"legit.pkl"})
        self.assertNotIn("link.pkl", names)

    def test_collects_nested_real_files(self) -> None:
        nest = self.tmp / "a" / "b"
        nest.mkdir(parents=True)
        (nest / "w.safetensors").write_bytes(b"\x00" * 8)
        (self.tmp / "top.pt").write_bytes(pickle.dumps(1))
        names = {p.name for p in ms.collect_files(self.tmp)}
        self.assertEqual(names, {"w.safetensors", "top.pt"})


class TestSniffAndFormatEdges(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_empty_file_does_not_crash(self) -> None:
        path = self.tmp / "empty.bin"
        path.write_bytes(b"")
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertIn(result.verdict, {"SAFE", "REVIEW"})

    def test_bad_zip_file_is_review(self) -> None:
        path = self.tmp / "bad.pt"
        path.write_bytes(b"PK\x03\x04" + b"not-a-real-zip")
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.format, "pytorch-zip")
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("zip archive" in f.detail.lower() for f in result.findings))

    def test_gguf_truncated_after_magic(self) -> None:
        path = self.tmp / "trunc.gguf"
        path.write_bytes(b"GGUF")
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.format, "gguf")
        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertTrue(
            any("truncated" in f.detail.lower() for f in result.findings if f.severity == "CRITICAL")
        )

    def test_empty_pickle_stream_is_safe(self) -> None:
        result = _scan_bytes(b"")
        # Empty stream: genops yields nothing or REVIEW on error — must not crash.
        self.assertIn(result.verdict, {"SAFE", "REVIEW"})


class TestCliSmoke(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_cli_safe_exit_zero_with_reports(self) -> None:
        from unittest import mock

        path = self.tmp / "safe.pkl"
        path.write_bytes(pickle.dumps({"ok": True}))
        report = self.tmp / "out.json"
        doc = self.tmp / "out.md"
        with mock.patch(
            "sys.argv",
            [
                "model_scanner",
                str(path),
                "--report",
                str(report),
                "--doc-report",
                str(doc),
            ],
        ):
            code = ms.cli()
        self.assertEqual(code, 0)
        payload = json.loads(report.read_text())
        self.assertEqual(payload[0]["verdict"], "SAFE")
        self.assertIn("Overall verdict", doc.read_text())

    def test_cli_review_strict_exits_one(self) -> None:
        from unittest import mock

        allow = self.tmp / "allow.json"
        allow.write_text(json.dumps({"publishers": [{"id": "google"}]}))
        path = self.tmp / "safe.pkl"
        path.write_bytes(pickle.dumps(1))
        with mock.patch(
            "sys.argv",
            [
                "model_scanner",
                str(path),
                "--publisher",
                "sketchy",
                "--allowlist",
                str(allow),
                "--strict",
            ],
        ):
            code = ms.cli()
        self.assertEqual(code, 1)

    def test_cli_invalid_hf_repo_exits_two(self) -> None:
        from unittest import mock

        path = self.tmp / "safe.pkl"
        path.write_bytes(pickle.dumps(1))
        with mock.patch(
            "sys.argv",
            ["model_scanner", str(path), "--hf-repo", "../evil"],
        ):
            code = ms.cli()
        self.assertEqual(code, 2)

    def test_cli_dangerous_exits_one(self) -> None:
        from unittest import mock

        path = self.tmp / "evil.pkl"
        path.write_bytes(b"cos\nsystem\n(S'id'\ntR.")
        with mock.patch("sys.argv", ["model_scanner", str(path)]):
            code = ms.cli()
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
