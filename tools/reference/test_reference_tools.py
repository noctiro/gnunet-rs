#!/usr/bin/env python3
"""Isolated harness-boundary tests; not reference daemon interoperability."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import bootstrap_dependencies
from statistics_daemons import Harness, artifact, read_dump


def frame(value=7, flags=2, names=b"s\0n\0"):
    return (16 + len(names)).to_bytes(2, "big") + b"\0\xa8" + flags.to_bytes(4, "big") + value.to_bytes(8, "big") + names


class HarnessBoundaries(unittest.TestCase):
    def test_dump_is_official_complete_canonical_and_nonempty(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dump"
            path.write_bytes(frame(1) + frame(2))
            self.assertEqual([row["value"] for row in read_dump(path)], [1, 2])
            for raw in (b"", frame()[:-1], b"\0\x03\0\xa8", b"private header", frame(flags=3), frame(names=b"s\0n\0extra"), frame() + b"\0"):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    read_dump(path)

    def test_failed_command_and_timeout_cannot_be_recorded_as_passed(self):
        with tempfile.TemporaryDirectory() as folder:
            harness = Harness(Path(folder), dict(os.environ))
            with self.assertRaises(ValueError):
                harness.command("nonzero", [sys.executable, "-c", "raise SystemExit(7)"])
            with self.assertRaises(ValueError):
                harness.command("timeout", [sys.executable, "-c", "import time; time.sleep(30)"], timeout=.05)
            self.assertEqual(harness.commands[0]["exit_code"], 7)
            self.assertTrue(harness.commands[1]["timed_out"])
            self.assertEqual([row["passed"] for row in harness.checks], [False, False])

    def test_cleanup_reaps_only_owned_process_group_and_retains_actual_log(self):
        with tempfile.TemporaryDirectory() as folder:
            harness = Harness(Path(folder), dict(os.environ))
            owned = harness.start("owned", [sys.executable, "-u", "-c", "import time; print('owned'); time.sleep(30)"])
            harness.cleanup()
            self.assertIsNotNone(owned["process"].poll())
            self.assertTrue(owned["stdout"].closed)
            self.assertIn("stdout_sha256", owned["row"])

    def test_actual_watch_stdout_must_match_in_order(self):
        with tempfile.TemporaryDirectory() as folder:
            harness = Harness(Path(folder), dict(os.environ))
            watcher = harness.start("watch-unit", [sys.executable, "-u", "-c", "import signal,time; signal.signal(signal.SIGTERM,lambda *_:exit(0)); print(55); print(57); time.sleep(30)"], watch=True)
            try:
                harness.watch_value(watcher, 55)
                with self.assertRaises(ValueError):
                    harness.watch_value(watcher, 99)
                self.assertEqual(watcher["out_path"].read_bytes().splitlines(), [b"55", b"57"])
            finally:
                harness.cleanup()

    def test_image_coverage_distinguishes_verified_epochs_from_one_shot_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            harness = Harness(output, {}, images=object())
            binary, library = output / "actor", output / "library"
            binary.write_bytes(b"staged actor")
            library.write_bytes(b"original library")
            binary_ref, library_ref = artifact(binary, output), artifact(library, output)
            staged = {"actor": {"snapshot": str(binary), "sha256": binary_ref["sha256"]}}
            phase = {"binary": binary_ref, "loaded_files": {"library": library_ref["sha256"]},
                     "mapped_files": [{"device": [8, 1], "inode": 2, "artifact": binary_ref},
                                      {"device": [8, 1], "inode": 3, "artifact": library_ref}]}
            row = {"stdout": "daemon.stdout", "one_shot": False, "argv": [str(binary)],
                   "exit_code": 0, "ready_images": phase, "pre_stop_images": copy.deepcopy(phase)}
            harness.commands.extend([row, {"stdout": "get.stdout", "one_shot": True}])
            harness.diagnostics["commands"].append(
                {"stdout": "known-variance.stdout", "one_shot": False, "exit_code": -signal.SIGKILL}
            )

            result = harness.image_coverage(staged, normal_passed=True)
            self.assertEqual(result["status"], "matched-long-lived-actors")
            self.assertEqual(result["matched_long_lived"], ["daemon.stdout"])
            self.assertEqual(result["unobserved_one_shot"], ["get.stdout"])
            self.assertEqual(result["excluded_diagnostic"], ["known-variance.stdout"])
            self.assertEqual(harness.image_coverage(staged, normal_passed=False)["status"], "incomplete")
            self.assertEqual(Harness(output, {}).image_coverage({}, True), {"status": "not-requested"})

            for change, reason in [
                ({"pre_stop_images": {"unavailable": "process already exited"}}, "missing live"),
                ({"pre_stop_images": {**phase, "mapped_files": []}}, "changed between"),
                ({"argv": [str(library)]}, "differs from the staged actor"),
                ({"forced_kill": True}, "missing normal actor exit"),
            ]:
                with self.subTest(reason=reason), patch.dict(row, change):
                    result = harness.image_coverage(staged, normal_passed=True)
                    self.assertEqual(result["status"], "incomplete")
                    self.assertIn(reason, result["failures"][0]["reason"])
            library.write_bytes(b"replacement")
            result = harness.image_coverage(staged, normal_passed=True)
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("retained mapped-file bytes changed", result["failures"][0]["reason"])

    def test_config_is_bound_to_arguments_and_log_drift_cannot_replace_original_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            harness = Harness(output, dict(os.environ))
            configuration = output / "active.conf"
            harness.retain_config(configuration, output / "socket", output / "database", "retained.conf")
            argv = [sys.executable, "-c", "print('original')", "-c", str(configuration)]
            harness.command("configured", argv)
            row = harness.commands[0]
            self.assertEqual(row["configuration"], artifact(output / "retained.conf", output))
            self.assertTrue(harness.configurations_unchanged())
            configuration.write_bytes(b"edited")
            self.assertFalse(harness.configurations_unchanged())

            original = row["stdout_sha256"]
            (output / row["stdout"]).write_bytes(b"edited output\n")
            harness.cleanup()
            self.assertEqual(row["stdout_sha256"], original)
            self.assertTrue(any("retained log changed" in item["error"] for item in harness.cleanup_errors))


class BootstrapBuildTools(unittest.TestCase):
    def test_rejected_wheel_cannot_fall_back_to_unhashed_build_tools_or_start_c_builds(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder).resolve() / "private-build"
            commands = []

            def run(command, **options):
                commands.append(command)
                options["stdout"].write(b"controlled installer result\n")
                return SimpleNamespace(returncode=1 if "pip" in command else 0)

            with patch.object(bootstrap_dependencies.platform, "system", return_value="Linux"), \
                    patch.object(bootstrap_dependencies.subprocess, "run", side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = bootstrap_dependencies.bootstrap(SimpleNamespace(output=output, jobs=2))
            self.assertEqual(status, 1)
            self.assertEqual(len(commands), 2)
            install = commands[1]
            self.assertEqual(install[:5], [str(output / "venv/bin/python"), "-m", "pip", "install", "--disable-pip-version-check"])
            for option in ("--require-hashes", "--only-binary=:all:", "--no-deps"):
                self.assertIn(option, install)
            requirements = Path(install[install.index("--requirement") + 1])
            self.assertEqual(requirements.name, "requirements-build.txt")
            receipt = json.loads((output / "dependency-result.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["commands"][-1]["name"], "build-tools")
            self.assertEqual(receipt["commands"][-1]["exit_code"], 1)
            self.assertEqual(receipt["build_tools_requirements"]["sha256"], bootstrap_dependencies.digest(requirements))
            self.assertEqual(receipt["packages"], [])

    def test_unsupported_host_is_rejected_before_installing_anything(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder).resolve() / "private-build"
            with patch.object(bootstrap_dependencies.platform, "system", return_value="Windows"), \
                    patch.object(bootstrap_dependencies.subprocess, "run") as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                status = bootstrap_dependencies.bootstrap(SimpleNamespace(output=output, jobs=2))
            self.assertEqual(status, 1)
            run.assert_not_called()
            receipt = json.loads((output / "dependency-result.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("supports macOS and Linux", receipt["failure"])


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun else 1)
