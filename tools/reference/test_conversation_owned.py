#!/usr/bin/env python3
"""Local owner-lifecycle tests; no child processes or GNUnet participants."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import conversation_owned as owned


class OwnedLifecycle(unittest.TestCase):
    def controller(self, folder):
        return owned.Controller(Path(folder), seconds=120)

    def output_pipe(self, control, name="pipe"):
        owner = owned.Owner(1, name, "command", [])
        owner.row["stdout_file"] = name + ".stdout"
        owner.logs["stdout"] = (control.evidence / owner.row["stdout_file"]).open("xb", buffering=0)
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        owner.stdout = os.fdopen(read_fd, "rb", buffering=0)
        owner.capture_expected.add("stdout")
        owner.open_readers[read_fd] = "stdout"
        control.children.append(owner)
        return owner, write_fd

    def test_forced_close_does_not_turn_truncation_into_eof_on_repeat(self):
        with tempfile.TemporaryDirectory() as folder:
            control = self.controller(folder)
            owner, writer = self.output_pipe(control)
            owner.process = Mock()  # No Popen or native child is created.
            try:
                with self.assertRaises(owned.ObservationError):
                    control.finalize(owner, require_reaped=False)
                self.assertFalse(owner.row["capture_drained"])
                self.assertEqual(owner.row["capture_truncated"], ["stdout"])
                self.assertTrue(owner.row["parent_resources_closed"])
                self.assertFalse(owner.row["reaped"])
                self.assertTrue(owner.finalized)
                original = copy.deepcopy(owner.row)
                errors = copy.deepcopy(control.cleanup_errors)
                control.finalize(owner, require_reaped=False)
                self.assertEqual(owner.row, original)
                self.assertEqual(control.cleanup_errors, errors)
                with self.assertRaises(owned.ObservationError):
                    control.finalize(owner)
                owner.process.assert_not_called()
            finally:
                os.close(writer)

    def test_real_eof_preserves_complete_output_and_independent_resource_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            control = self.controller(folder)
            owner, writer = self.output_pipe(control)
            try:
                os.write(writer, b"original output\n")
            finally:
                os.close(writer)
            control.pump(0)
            self.assertFalse(owner.capture_eof)
            control.pump(0)
            self.assertEqual(owner.capture_eof, {"stdout"})
            control.finalize(owner)
            self.assertTrue(owner.row["capture_drained"])
            self.assertTrue(owner.row["parent_resources_closed"])
            self.assertFalse(owner.row["reaped"])
            self.assertEqual(bytes(owner.output["stdout"]), b"original output\n")
            self.assertEqual((Path(folder) / owner.row["stdout_file"]).read_bytes(), b"original output\n")
            self.assertFalse(control.cleanup_errors)

    def test_missing_reader_registration_cannot_supply_an_expected_eof(self):
        with tempfile.TemporaryDirectory() as folder:
            control = self.controller(folder)
            owner = owned.Owner(1, "partial-acquisition", "command", [])
            owner.capture_expected.update(("stdout", "stderr"))
            with self.assertRaises(owned.ObservationError):
                control.finalize(owner)
            self.assertFalse(owner.row["capture_drained"])
            self.assertEqual(owner.row["capture_truncated"], ["stderr", "stdout"])
            self.assertTrue(owner.row["parent_resources_closed"])

    def test_hash_retry_never_reopens_resources_or_recomputes_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            control = self.controller(folder)
            owner = owned.Owner(1, "log", "command", [])
            owner.row["stdout_file"] = "log.stdout"
            owner.logs["stdout"] = (Path(folder) / "log.stdout").open("xb", buffering=0)
            with patch.object(owned, "file_hash", side_effect=[OSError("hash unavailable"), ("a" * 64, 0)]):
                with self.assertRaises(owned.ObservationError):
                    control.finalize(owner)
                self.assertTrue(owner.row["capture_drained"])
                self.assertTrue(owner.row["parent_resources_closed"])
                self.assertFalse(owner.finalized)
                control.finalize(owner)
            self.assertTrue(owner.finalized)
            self.assertTrue(owner.row["capture_drained"])
            self.assertEqual([e["stage"] for e in control.cleanup_errors], ["stdout-log-hash"])

    def test_business_actions_stop_at_the_existing_cleanup_transition(self):
        with tempfile.TemporaryDirectory() as folder:
            control = self.controller(folder)
            owner = owned.Owner(1, "unused", "command", [])
            deadline = owned.Deadline(1)
            control.active = False  # Existing main-handler arming API.
            self.assertEqual(control.phase, "cleaning")
            with patch.object(owned.subprocess, "Popen") as popen, patch.object(owned.os, "write") as write:
                operations = [
                    lambda: control.start("unused", ["/unused"], {}),
                    lambda: control.send(owner, b"/quit\n", deadline),
                    lambda: control.command("unused", ["/unused"], {}),
                    lambda: control.acquire(owner, lambda: self.fail("acquired after cleanup")),
                    lambda: control.wait(lambda: self.fail("observed after cleanup"), deadline, "unused"),
                    lambda: control.close_stdin(owner),
                    lambda: control.stop_frontend(owner),
                    lambda: control.pump(0),
                ]
                for operation in operations:
                    with self.subTest(operation=operation):
                        with self.assertRaises(owned.ObservationError):
                            operation()
                popen.assert_not_called()
                write.assert_not_called()
            self.assertFalse(control.children)
            self.assertFalse(owner.row["stdin_events"])
            with self.assertRaises(owned.ObservationError):
                control.active = True
            control.cleanup(0)
            self.assertEqual(control.phase, "closed")
            with self.assertRaises(owned.ObservationError):
                control.start("unused", ["/unused"], {})

    def test_cleanup_reentry_and_repetition_keep_the_first_target(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(owned.time, "monotonic", return_value=100):
            control = self.controller(folder)
            def reenter(hard):
                self.assertEqual(hard, 110)
                self.assertEqual(control.phase, "cleaning")
                control.cleanup(100)
            with patch.object(control, "_cleanup_owned", side_effect=reenter) as retire:
                control.cleanup(10)
                original = control.cleanup_report()
                control.cleanup(100)
                retire.assert_called_once_with(110)
            self.assertEqual(control.phase, "closed")
            self.assertEqual(control.cleanup_report(), original)
            self.assertEqual(control.cleanup_started, 100)
            self.assertEqual(control.cleanup_soft, 105)
            self.assertEqual(control.cleanup_hard, 110)

    def test_interrupted_cleanup_resumes_without_a_new_grace(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(owned.time, "monotonic", return_value=100) as clock:
            control = self.controller(folder)
            with patch.object(control, "_cleanup_owned", side_effect=[RuntimeError("interrupted"), None]) as retire:
                with self.assertRaises(RuntimeError):
                    control.cleanup(10)
                self.assertEqual(control.phase, "cleaning")
                self.assertFalse(control.active)
                clock.return_value = 108
                control.cleanup(100)
            self.assertEqual(retire.call_args_list[0].args, (110,))
            self.assertEqual(retire.call_args_list[1].args, (110,))
            self.assertEqual(control.cleanup_hard, 110)
            self.assertEqual(control.cleanup_finished, 108)
            self.assertEqual(control.phase, "closed")

    def test_cleanup_keeps_its_explicit_grace_after_the_business_deadline(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(owned.time, "monotonic", return_value=100) as clock:
            control = owned.Controller(Path(folder), seconds=1)
            clock.return_value = 105
            with patch.object(control, "_cleanup_owned") as retire:
                control.cleanup(10)
            retire.assert_called_once_with(115)
            self.assertEqual(control.cleanup_soft, 110)


if __name__ == "__main__":
    unittest.main()
