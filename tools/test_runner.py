"""Controls for discovery, failure aggregation and bounded execution."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_tools


class RunnerTests(unittest.TestCase):
    def test_syntax_checks_unexecuted_tools_without_importing_them(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tools").mkdir()
            (root / "tools/helper.py").write_text("raise RuntimeError('must not execute')")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(check_tools.check_syntax(root), 0)
            (root / "tools/helper.py").write_text("def broken(:")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(check_tools.check_syntax(root), 1)
            self.assertIn("tools/helper.py:1:", errors.getvalue())
            self.assertFalse((root / "tools/__pycache__").exists())

    def test_discovery_is_sorted_excludes_outputs_and_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path in check_tools.SELF_TESTS:
                script = root / path
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text("")
            expected = ["tools/release_tests.py", "adapters/example/tools/test_tools.py",
                        "crates/example/tools/guard_tests.py", "tests/selftest.py"]
            for path in [*expected, "tools/target/test_hidden.py", "tools/check_tools.py"]:
                script = root / path
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text("")
            (root / "tools/alias").symlink_to(root / "adapters", target_is_directory=True)
            self.assertEqual(check_tools.discover(root), sorted(
                [(path,) for path in expected]
                + [(path, "--self-test") for path in check_tools.SELF_TESTS]
            ))
            (root / "tools/test_link.py").symlink_to(root / "tools/check_tools.py")
            with self.assertRaisesRegex(ValueError, "symlink"):
                check_tools.discover(root)

    def test_nonzero_and_timeout_failures_do_not_skip_remaining_suites(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "failed.py").write_text("raise SystemExit(7)")
            (root / "timeout.py").write_text("import time; time.sleep(60)")
            (root / "last.py").write_text("from pathlib import Path; Path('ran').touch()")
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = check_tools.run(
                    [(name,) for name in ["failed.py", "timeout.py", "last.py"]], root, 1,
                )
            self.assertEqual(status, 1)
            self.assertTrue((root / "ran").is_file())
            self.assertIn("exit 7", errors.getvalue())
            self.assertIn("timeout after 1s", errors.getvalue())
            self.assertIn("1/3 passed", output.getvalue())

    def test_inherited_optimization_cannot_disable_control_assertions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "assertions.py").write_text("import sys; assert sys.flags.optimize == 0")
            with patch.dict(os.environ, {"PYTHONOPTIMIZE": "1"}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(check_tools.run([("assertions.py",)], root, 5), 0)

    def test_failure_log_and_report_preserve_actual_child_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "failed.py").write_text("print('child diagnostic'); raise SystemExit(9)")
            output = root / "results"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(check_tools.run([("failed.py",)], root, 5, output), 1)
            result = json.loads((output / "result.json").read_text())["suites"][0]
            self.assertEqual(result["exit_code"], 9)
            self.assertEqual(result["failure"], "exit 9")
            self.assertIn("child diagnostic", (output / result["log"]).read_text())
            self.assertIn("child diagnostic", errors.getvalue())
            with self.assertRaises(FileExistsError):
                check_tools.run([], root, 5, output)


if __name__ == "__main__":
    unittest.main()
