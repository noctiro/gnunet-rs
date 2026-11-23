"""Exercise compiler artifact selection with a split per-unit Cargo cache."""

import json
from pathlib import Path
import unittest

from cargo_artifacts import CargoArtifacts


class CargoArtifactTests(unittest.TestCase):
    def test_split_build_directories_supply_all_rustc_search_paths(self):
        root = Path(__file__).resolve().parent
        main = root / "artifacts" / "libmain.rlib"
        dep = root / "build" / "lib-dependency-42" / "libdep-42.rlib"
        macro = root / "build" / "macro-81" / "libmacro-81.dylib"
        dependency = artifact(root / "dep", "dep", [dep, dep.with_suffix(".rmeta")])
        messages = [artifact(root, "main", [main]), dependency,
                    artifact(root / "macro", "macro", [macro], "proc-macro"),
                    {"reason": "build-finished", "success": True}]
        build = CargoArtifacts("\n".join(map(json.dumps, messages)))
        self.assertEqual(build.rlib("main", root / "Cargo.toml"), main)
        self.assertCountEqual(build.rustc_dependency_args(), [
            "-L", f"dependency={main.parent}", "-L", f"dependency={dep.parent}",
            "-L", f"dependency={macro.parent}",
        ])

    def test_manifest_distinguishes_same_named_package_and_rejects_duplicates(self):
        root = Path(__file__).resolve().parent
        original = root / "elsewhere" / "libsame.rlib"
        selected = artifact(root, "same", [original])
        other = artifact(root / "other", "same", [root / "libsame.rlib"])
        build = CargoArtifacts("\n".join(map(json.dumps, [other, selected])))
        self.assertEqual(build.rlib("same", root / "Cargo.toml"), original)
        with self.assertRaises(ValueError):
            build.rlib("same", root / "missing" / "Cargo.toml")
        duplicate = CargoArtifacts("\n".join(map(json.dumps, [selected, other, selected])))
        with self.assertRaises(ValueError):
            duplicate.rlib("same", root / "Cargo.toml")

    def test_example_uses_reported_executable_including_platform_suffix(self):
        root = Path(__file__).resolve().parent
        executable = root / "alternative" / "fixture.exe"
        example = artifact(root, "fixture", [executable], "example")
        example["executable"] = str(executable)
        build = CargoArtifacts(json.dumps(example))
        self.assertEqual(build.example("fixture", root / "Cargo.toml"), executable)
        with self.assertRaises(ValueError):
            build.binary("fixture", root / "Cargo.toml")

    def test_binary_requires_matching_package_manifest_and_executable(self):
        root = Path(__file__).resolve().parent
        expected = root / "custom" / "fixture.exe"
        binary = artifact(root, "fixture", [expected], "bin")
        foreign = artifact(root / "foreign", "fixture", [expected], "bin")
        binary["executable"] = str(expected)
        foreign["executable"] = str(root / "other.exe")
        build = CargoArtifacts("\n".join(map(json.dumps, [foreign, binary])))
        self.assertEqual(build.binary("fixture", root / "Cargo.toml"), expected)
        binary["executable"] = None
        with self.assertRaises(ValueError):
            CargoArtifacts(json.dumps(binary)).binary("fixture", root / "Cargo.toml")

    def test_expected_package_rejects_a_conflicting_lib_alongside_the_original(self):
        root = Path(__file__).resolve().parent
        original = artifact(root, "fixture", [root / "libfixture.rlib"])
        original["package_id"] = "expected"
        foreign_manifest = artifact(root / "foreign", "fixture", [root / "foreign.rlib"])
        foreign_manifest["package_id"] = "expected"
        foreign_package = {**original, "package_id": "foreign"}
        for foreign, error in ((foreign_manifest, "library manifest"),
                               (foreign_package, "library package id")):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                build = CargoArtifacts("\n".join(map(json.dumps, [original, foreign])))
                build.rlib("fixture", root / "Cargo.toml", package_id="expected")


def artifact(package, name, files, kind="lib"):
    return {
        "reason": "compiler-artifact", "target": {"name": name, "kind": [kind]},
        "manifest_path": str(package / "Cargo.toml"), "filenames": list(map(str, files)),
    }


if __name__ == "__main__":
    unittest.main(verbosity=2)
