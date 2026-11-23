"""Resolve compiler inputs from a single Cargo build's JSON messages."""

import json
from pathlib import Path


class CargoArtifacts:
    def __init__(self, stdout):
        messages = (json.loads(line) for line in stdout.splitlines() if line.strip())
        self._rows = [row for row in messages if row.get("reason") == "compiler-artifact"]

    def rlib(self, name, manifest, *, package_id=None):
        """Select the rlib for a manifest; an expected package ID forbids conflicts."""
        row = self._select(name, manifest, "lib", package_id)
        paths = [Path(filename) for filename in row.get("filenames", ())
                 if filename.endswith(".rlib")]
        if len(paths) != 1:
            raise ValueError(f"library artifact has missing/ambiguous rlib for {name}: {paths}")
        return paths[0]

    def example(self, name, manifest):
        """Select the named example executable without assuming its filename."""
        return self._executable(name, manifest, "example")

    def binary(self, name, manifest):
        """Select the named package binary without assuming its filename."""
        return self._executable(name, manifest, "bin")

    def _executable(self, name, manifest, kind):
        row = self._select(name, manifest, kind)
        if not row.get("executable"):
            raise ValueError(f"Cargo {kind} {name} did not report an executable")
        return Path(row["executable"])

    def _select(self, name, manifest, kind, package_id=None):
        manifest = Path(manifest).resolve()
        selected = []
        for row in self._rows:
            target = row["target"]
            if target["name"] != name or target["kind"] != [kind]:
                continue
            reported = row.get("manifest_path")
            if not reported or Path(reported).resolve() != manifest:
                if package_id is not None:
                    raise ValueError(f"foreign actual library manifest for {name}: {reported}")
                continue
            if package_id is not None and row.get("package_id") != package_id:
                raise ValueError(f"foreign actual library package id for {name}: {row.get('package_id')}")
            selected.append(row)
        if len(selected) != 1:
            raise ValueError(f"expected one Cargo {kind} artifact for {name} in {manifest}, got {len(selected)}")
        return selected[0]

    def rustc_dependency_args(self):
        """Include Cargo's actual per-unit dependency folders without layout guesses."""
        directories = {Path(filename).parent for row in self._rows
                       for filename in row["filenames"] if self._is_rust_library(row, filename)}
        if not directories:
            raise ValueError("Cargo build reported no Rust library artifacts")
        return [arg for directory in sorted(directories)
                for arg in ("-L", f"dependency={directory}")]

    @staticmethod
    def _is_rust_library(row, filename):
        if filename.endswith((".rlib", ".rmeta")):
            return True
        return (any(kind in ("proc-macro", "dylib") for kind in row["target"]["kind"])
                and filename.endswith((".dll", ".dylib", ".so")))
