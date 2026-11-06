import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load_script("native_dataplane", "test-native-dataplane.py")
prepare = load_script("prepare_dataplane", "prepare-sing-box.py")


class NativeDataplaneTests(unittest.TestCase):
    def test_nested_modules_share_fixed_sources_and_wrong_module_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, module in native.MODULES:
                directory = root / relative
                directory.mkdir(exist_ok=True)
                (directory / "go.mod").write_text("module " + module + "\n")
            workfile = root / "go.work"
            native.write_workspace(root, workfile, "1.27.0")
            for relative, _ in native.MODULES:
                self.assertIn(json.dumps(str(root / relative)), workfile.read_text())
            (root / ".loom-sing-quic/go.mod").write_text("module example.com/demo-wrong\n")
            with self.assertRaisesRegex(ValueError, "unexpected native module"):
                native.write_workspace(root, workfile, "1.27.0")

    def test_failed_process_keeps_module_cwd_log_and_fails_step(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            module = root / "demo-module"
            module.mkdir()
            steps = []
            command = [sys.executable, "-c", "from pathlib import Path; print(Path.cwd()); raise SystemExit(7)"]
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                native.run_step(steps, root, "demo-failure", command, module, os.environ.copy())
            self.assertEqual(failure.exception.returncode, 7)
            self.assertEqual(steps[0]["status"], "failed")
            self.assertEqual(Path(steps[0]["log"]).read_text().strip(), str(module))
            native.write_summary(root, {"status": "failed", "steps": steps})
            self.assertEqual(json.loads((root / "summary.json").read_text())["status"], "failed")

    def test_empty_test_run_does_not_count_as_success(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            steps = []
            with self.assertRaisesRegex(ValueError, "no tests passed"):
                native.run_step(steps, root, "demo-empty", [sys.executable, "-c", "print('no test files')"], root, os.environ.copy(), True)
            self.assertEqual(steps[0]["status"], "failed")

    def test_each_upstream_rejects_wrong_commit_and_module_sum(self):
        sources = ((prepare.COMMIT, prepare.SUM), (prepare.TUN_COMMIT, prepare.TUN_SUM),
                   (prepare.QUIC_COMMIT, prepare.QUIC_SUM), (prepare.SING_COMMIT, prepare.SING_SUM),
                   (prepare.WG_COMMIT, prepare.WG_SUM))
        for index in range(len(sources)):
            for field in ("commit", "sum"):
                with self.subTest(module=index, field=field):
                    replies = []
                    for source_index, (commit, checksum) in enumerate(sources[:index + 1]):
                        if source_index == index:
                            if field == "commit":
                                commit = "demo-wrong"
                            else:
                                checksum = "demo-wrong"
                        replies.append(json.dumps({"Sum": checksum, "Origin": {"Hash": commit}}).encode())
                    with tempfile.TemporaryDirectory() as temporary, \
                            patch.object(prepare, "REPO", Path(temporary)), \
                            patch.object(prepare.subprocess, "check_output", side_effect=replies):
                        with self.assertRaisesRegex(ValueError, "does not match"):
                            prepare.prepare(prepare.REPO / "out/demo-source")


if __name__ == "__main__":
    unittest.main()
