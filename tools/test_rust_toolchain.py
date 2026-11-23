"""Check that standalone tools resolve the selected repository's channel."""

from pathlib import Path
import tempfile
import unittest

from rust_toolchain import rust_channel


class RustToolchainTests(unittest.TestCase):
    def test_checkout_channel_is_independent_of_its_workspace_msrv(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "Cargo.toml").write_text('[workspace.package]\nrust-version = "1.85"\n')
            (repository / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable" # checkout pin\n')
            self.assertEqual(rust_channel(repository), "stable")
            self.assertEqual(rust_channel(repository, "beta"), "beta")

    def test_duplicate_channel_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\nchannel = ""\n')
            with self.assertRaisesRegex(ValueError, "expected one plain toolchain.channel"):
                rust_channel(repository)


if __name__ == "__main__":
    unittest.main()
