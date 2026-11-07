#!/usr/bin/env python3
"""Isolated harness-boundary tests; not reference daemon interoperability."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from statistics_daemons import Harness, read_dump


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


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(HarnessBoundaries))
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun else 1)
