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


class TestOnnxDeepSkeleton(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_module_imports_and_exposes_has_onnx_flag(self) -> None:
        import onnx_deep
        self.assertIsInstance(onnx_deep.HAS_ONNX, bool)
        self.assertTrue(callable(onnx_deep.scan))

    def test_scan_never_raises_on_garbage_bytes(self) -> None:
        import onnx_deep
        path = self.tmp / "garbage.onnx"
        path.write_bytes(b"\xde\xad\xbe\xef" * 64)
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0", size_bytes=256)
        onnx_deep.scan(path, result)  # must not raise
        self.assertIn(result.verdict, {"SAFE", "REVIEW"})


try:
    import onnx as onnx  # noqa: F401
    from onnx import TensorProto, helper
    _HAS_ONNX = True
except ImportError:
    _HAS_ONNX = False


@unittest.skipUnless(_HAS_ONNX, "onnx package not installed")
class TestOnnxExternalData(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _model_with_external(self, location: str) -> bytes:
        t = helper.make_tensor("w", TensorProto.DataType.FLOAT, [1], [0.0])
        t.data_location = TensorProto.DataLocation.EXTERNAL
        del t.external_data[:]
        t.external_data.add(key="location", value=location)
        t.external_data.add(key="offset", value="0")
        t.external_data.add(key="length", value="4")
        g = helper.make_graph([], "g", [], [], initializer=[t])
        m = helper.make_model(g)
        return m.SerializeToString()

    def _scan(self, location: str):
        import onnx_deep
        path = self.tmp / "m.onnx"
        path.write_bytes(self._model_with_external(location))
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0",
                               size_bytes=path.stat().st_size)
        onnx_deep.scan(path, result, finding_cls=ms.Finding)
        return result

    def test_relative_path_traversal_is_critical(self) -> None:
        r = self._scan("../escape.bin")
        self.assertEqual(r.verdict, "DANGEROUS")

    def test_absolute_path_is_critical(self) -> None:
        r = self._scan("/etc/passwd")
        self.assertEqual(r.verdict, "DANGEROUS")

    def test_url_location_is_critical(self) -> None:
        r = self._scan("https://evil.example.com/x.bin")
        self.assertEqual(r.verdict, "DANGEROUS")

    def test_local_external_file_is_not_critical(self) -> None:
        r = self._scan("weights.bin")
        self.assertFalse(any(f.severity == "CRITICAL" for f in r.findings))


@unittest.skipUnless(_HAS_ONNX, "onnx package not installed")
class TestOnnxOpDomains(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _write_model(self, nodes, functions=()) -> Path:
        x = helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])
        y = helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])
        g = helper.make_graph(nodes, "g", [x], [y])
        m = helper.make_model(g, functions=list(functions))
        m.opset_import[0].version = 18
        path = self.tmp / "m.onnx"
        path.write_bytes(m.SerializeToString())
        return path

    def _scan(self, path: Path, allow: frozenset = frozenset()):
        import onnx_deep
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0",
                               size_bytes=path.stat().st_size)
        onnx_deep.scan(path, result, allow_domains=allow, finding_cls=ms.Finding)
        return result

    def test_custom_domain_is_critical(self) -> None:
        node = helper.make_node("CustomOp", ["x"], ["y"], domain="evil.custom")
        r = self._scan(self._write_model([node]))
        self.assertEqual(r.verdict, "DANGEROUS")

    def test_custom_domain_in_subgraph_is_critical(self) -> None:
        inner = helper.make_graph(
            [helper.make_node("CustomOp", ["x"], ["y"], domain="evil.custom")],
            "inner",
            [helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])],
            [helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])],
        )
        if_node = helper.make_node(
            "If", ["cond"], ["y"],
            then_branch=inner, else_branch=inner, domain="",
        )
        x = helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])
        cond = helper.make_tensor_value_info("cond", TensorProto.DataType.BOOL, [1])
        y = helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])
        g = helper.make_graph([if_node], "g", [cond, x], [y])
        m = helper.make_model(g)
        m.opset_import[0].version = 18
        path = self.tmp / "if.onnx"
        path.write_bytes(m.SerializeToString())
        r = self._scan(path)
        self.assertEqual(r.verdict, "DANGEROUS")

    def test_allowlisted_domain_is_review_not_critical(self) -> None:
        node = helper.make_node("FusedOp", ["x"], ["y"], domain="com.microsoft")
        r = self._scan(self._write_model([node]), allow=frozenset({"com.microsoft"}))
        self.assertNotEqual(r.verdict, "DANGEROUS")
        self.assertTrue(any("com.microsoft" in f.detail for f in r.findings))

    def test_standard_domains_are_clean(self) -> None:
        node = helper.make_node("Relu", ["x"], ["y"], domain="")
        r = self._scan(self._write_model([node]))
        self.assertFalse(any(f.severity == "CRITICAL" for f in r.findings))

    def test_suspicious_function_name_is_review(self) -> None:
        f = helper.make_function(
            "evil.custom", "exec_shell", ["x"], ["y"],
            [helper.make_node("Identity", ["x"], ["y"])],
            opset_imports=[helper.make_opsetid("evil.custom", 1)],
        )
        r = self._scan(self._write_model(
            [helper.make_node("exec_shell", ["x"], ["y"], domain="evil.custom")],
            functions=[f],
        ), allow=frozenset({"evil.custom"}))
        self.assertTrue(any("exec_shell" in fd.detail for fd in r.findings))

    def test_evil_domain_in_function_body_subgraph_is_dangerous(self) -> None:
        """Non-standard domain nested in an If subgraph inside a model.functions body."""
        inner = helper.make_graph(
            [helper.make_node("CustomOp", ["x"], ["y"], domain="evil.custom")],
            "fn_inner",
            [helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])],
            [helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])],
        )
        if_node = helper.make_node(
            "If", ["cond"], ["y"], then_branch=inner, else_branch=inner, domain="",
        )
        fn = helper.make_function(
            "my.domain", "my_fn", ["x", "cond"], ["y"], [if_node],
            opset_imports=[helper.make_opsetid("", 18), helper.make_opsetid("my.domain", 1)],
        )
        r = self._scan(
            self._write_model(
                [helper.make_node("my_fn", ["x", "cond"], ["y"], domain="my.domain")],
                functions=[fn],
            ),
            allow=frozenset({"my.domain"}),
        )
        self.assertEqual(r.verdict, "DANGEROUS")
        self.assertTrue(any(
            "evil.custom" in f.detail for f in r.findings if f.severity == "CRITICAL"
        ))


@unittest.skipUnless(_HAS_ONNX, "onnx package not installed")
class TestOnnxWalkCaps(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _scan_path(self, path: Path):
        import onnx_deep
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0",
                               size_bytes=path.stat().st_size)
        onnx_deep.scan(path, result, finding_cls=ms.Finding)
        return result

    def _nested_if_model(self, depth: int):
        """Binary nested If: each level's then+else both wrap the next level."""
        inner = helper.make_node("Identity", ["x"], ["y"])
        for _ in range(depth):
            sub = helper.make_graph(
                [inner], "sub",
                [helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])],
                [helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])],
            )
            inner = helper.make_node(
                "If", ["cond"], ["y"], then_branch=sub, else_branch=sub, domain="",
            )
        x = helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])
        cond = helper.make_tensor_value_info("cond", TensorProto.DataType.BOOL, [1])
        y = helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])
        g = helper.make_graph([inner], "g", [cond, x], [y])
        m = helper.make_model(g)
        m.opset_import[0].version = 18
        return m

    def test_depth_12_nested_if_completes_fast(self) -> None:
        import time
        path = self.tmp / "deep12.onnx"
        path.write_bytes(self._nested_if_model(12).SerializeToString())
        t0 = time.perf_counter()
        r = self._scan_path(path)
        dt = time.perf_counter() - t0
        self.assertLess(dt, 5.0)
        self.assertTrue(any("ONNX nodes:" in f.detail for f in r.findings))

    def test_node_budget_exceeded_adds_exactly_one_review(self) -> None:
        """Node budget hit: walk stops, exactly one truncation REVIEW is added.

        Built with MAX_WALK_NODES monkeypatched to 10 so a small real model
        trips the budget; this is the cap that guards the 2^N nested-If DoS.
        """
        import onnx_deep
        path = self.tmp / "deep12.onnx"
        path.write_bytes(self._nested_if_model(12).SerializeToString())
        import onnx
        model = onnx.load(str(path), load_external_data=False)
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0",
                               size_bytes=path.stat().st_size)
        original = onnx_deep.MAX_WALK_NODES
        onnx_deep.MAX_WALK_NODES = 10
        try:
            node_count = onnx_deep._check_domains(model, result, frozenset())
        finally:
            onnx_deep.MAX_WALK_NODES = original
        self.assertLessEqual(node_count, 10)
        reviews = [
            f for f in result.findings
            if f.severity == "REVIEW" and "exceeds scan cap" in f.detail
        ]
        self.assertEqual(len(reviews), 1)

    def test_depth_cap_stops_walk_and_flags_truncation(self) -> None:
        """Recursion deeper than MAX_WALK_DEPTH sets the truncation flag.

        upb protobuf refuses to build/parse messages nested deeper than ~33
        levels, so a real >100-deep graph cannot exist in this runtime; use a
        mock with the GraphProto shape (.node / .attribute / .g / GRAPH type).
        """
        import onnx
        import onnx_deep

        class FakeAttr:
            def __init__(self, g) -> None:
                self.type = onnx.AttributeProto.AttributeType.GRAPH
                self.g = g

        class FakeNode:
            def __init__(self, attr=None) -> None:
                self.domain = ""
                self.attribute = [attr] if attr is not None else []

        # chain: graph level i holds one node whose GRAPH attr points to level i+1
        leaf = FakeNode()

        class FakeGraph:
            def __init__(self) -> None:
                self.node = []

        deepest = FakeGraph()
        deepest.node.append(leaf)
        current = deepest
        for _ in range(150):
            parent = FakeGraph()
            parent.node.append(FakeNode(FakeAttr(current)))
            current = parent
        budget: list[int] = [0]
        truncated: list[bool] = [False]
        nodes = list(onnx_deep._walk_nodes(current, 0, budget, truncated))
        self.assertTrue(truncated[0])
        self.assertLessEqual(len(nodes), onnx_deep.MAX_WALK_DEPTH + 2)
        self.assertGreater(len(nodes), 50)  # real walk happened before the cap

    def test_budget_bounds_shared_subgraph_walk(self) -> None:
        """A shared subgraph is bounded by the node budget, not a visited-set.

        Under upb, field accesses materialize fresh wrappers, so id()-based
        dedupe is unsound and was removed; the DoS guard is MAX_WALK_NODES.
        Walking the same graph object twice must stop at the budget.
        """
        import onnx_deep

        def vi(name: str):
            return helper.make_tensor_value_info(name, TensorProto.DataType.FLOAT, [1])

        shared = helper.make_graph(
            [helper.make_node("Relu", ["x"], ["y"])], "shared", [vi("x")], [vi("y")],
        )
        original = onnx_deep.MAX_WALK_NODES
        onnx_deep.MAX_WALK_NODES = 3
        try:
            budget: list[int] = [0]
            truncated: list[bool] = [False]
            walks = [list(onnx_deep._walk_nodes(shared, 0, budget, truncated))
                     for _ in range(4)]
        finally:
            onnx_deep.MAX_WALK_NODES = original
        # Budget increments before each yield; MAX=3 allows 3 total nodes across
        # all walks, then the 4th walk hits the cap and truncates.
        self.assertEqual([len(w) for w in walks], [1, 1, 1, 0])
        self.assertTrue(truncated[0])


@unittest.skipUnless(_HAS_ONNX, "onnx package not installed")
class TestOnnxEmbeddedRaw(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_large_embedded_raw_is_review(self) -> None:
        import onnx_deep
        big = b"\x00" * (onnx_deep.MAX_EMBEDDED_RAW_BYTES + 1)
        t = helper.make_tensor("blob", TensorProto.DataType.UINT8,
                               [len(big)], big, raw=True)
        g = helper.make_graph([], "g", [], [], initializer=[t])
        m = helper.make_model(g)
        path = self.tmp / "big.onnx"
        path.write_bytes(m.SerializeToString())
        result = ms.ScanResult(path=str(path), format="onnx", sha256="0",
                               size_bytes=path.stat().st_size)
        onnx_deep.scan(path, result, finding_cls=ms.Finding)
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("embedded" in f.detail.lower() for f in result.findings))


class TestOnnxIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _onnx_bytes(self) -> bytes:
        if not _HAS_ONNX:
            self.skipTest("onnx package not installed")
        x = helper.make_tensor_value_info("x", TensorProto.DataType.FLOAT, [1])
        y = helper.make_tensor_value_info("y", TensorProto.DataType.FLOAT, [1])
        g = helper.make_graph([helper.make_node("Relu", ["x"], ["y"])], "g", [x], [y])
        m = helper.make_model(g)
        m.opset_import[0].version = 18
        return m.SerializeToString()

    def test_scan_file_uses_deep_path_when_available(self) -> None:
        path = self.tmp / "m.onnx"
        path.write_bytes(self._onnx_bytes())
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset())
        self.assertEqual(result.verdict, "SAFE")
        self.assertTrue(any("opset" in f.detail.lower() for f in result.findings))

    def test_no_onnx_deep_flag_forces_fallback_info(self) -> None:
        path = self.tmp / "m.onnx"
        path.write_bytes(self._onnx_bytes())
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset(),
                              onnx_deep=False)
        self.assertTrue(any("fast path" in f.detail.lower()
                            or "byte-level" in f.detail.lower() for f in result.findings))

    def test_cli_allow_onnx_domain_repeatable(self) -> None:
        from unittest import mock
        path = self.tmp / "m.onnx"
        path.write_bytes(self._onnx_bytes())
        with mock.patch("sys.argv", [
            "model_scanner", str(path),
            "--allow-onnx-domain", "com.microsoft",
            "--allow-onnx-domain", "acme.ops",
        ]):
            code = ms.cli()
        self.assertEqual(code, 0)

    def test_size_gate_precedes_deep_parse(self) -> None:
        path = self.tmp / "big.onnx"
        path.write_bytes(b"ONNX" + b"\x00" * 200)
        result = ms.scan_file(path, verbose=False, allow_modules=frozenset(),
                              max_read_bytes=64)
        self.assertEqual(result.verdict, "REVIEW")
        self.assertTrue(any("max-read-bytes" in f.detail for f in result.findings))


if __name__ == "__main__":
    unittest.main()
