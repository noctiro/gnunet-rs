#!/usr/bin/env python3
"""Controls for Linux image observations without running a GNUnet process."""

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from linux_images import Images, executable_mappings, identity


class ImageControls(unittest.TestCase):
    def test_maps_select_file_backed_code_and_deduplicate_its_segments(self):
        rows = b"""1000-2000 r--p 0000 09:12 3 /a/b
2000-3000 r-xp 1000 08:01 62 /a program with spaces
3000-4000 r-xp 2000 08:01 62 /a program with spaces
4000-5000 r-xp 0000 00:00 0 [vdso]
5000-6000 rw-p 0000 08:01 65 /a/data
"""
        self.assertEqual(executable_mappings(rows), {(8, 1, 62): b"/a program with spaces"})
        with self.assertRaisesRegex(ValueError, "absolute file path"):
            executable_mappings(b"1000-2000 r-xp 0000 08:01 62 /../different-root\n")

    def test_store_retains_original_bytes_and_refuses_the_wrong_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            source = output / "image"
            source.write_bytes(b"original image bytes")
            store = Images(output)
            with source.open("rb") as stream:
                dev, minor, inode = identity(os.fstat(stream.fileno()))
                with self.assertRaisesRegex(ValueError, "original file"):
                    store._retain(stream, (dev, minor, inode + 1), 1024)
                with self.assertRaisesRegex(ValueError, "byte bound"):
                    store._retain(stream, (dev, minor, inode), 1)
                reference, count = store._retain(stream, (dev, minor, inode), 1024)
                stream.seek(0)
                with patch("linux_images.tempfile.NamedTemporaryFile", side_effect=AssertionError):
                    duplicate, _ = store._retain(stream, (dev, minor, inode), 1024)
            self.assertEqual(duplicate, reference)
            self.assertEqual(store.retained_bytes, count)
            image = (output / reference["path"]).read_bytes()
            self.assertEqual(image, source.read_bytes())
            self.assertEqual(hashlib.sha256(image).hexdigest(), reference["sha256"])

    @unittest.skipUnless(sys.platform == "linux", "requires Linux /proc")
    def test_actual_process_executable_and_mapped_files(self):
        class Running:
            pid = os.getpid()

            def poll(self):
                return None

        executable = Path(sys.executable).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            observation = Images(output).capture(Running(), executable)
            binary = observation["binary"]
            self.assertEqual((output / binary["path"]).read_bytes(), executable.read_bytes())
            self.assertTrue(observation["mapped_files"])
            for path, digest in observation["loaded_files"].items():
                self.assertEqual(hashlib.sha256((output / path).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
