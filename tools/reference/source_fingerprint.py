"""Hash source/specification inputs without executing any product or oracle.

The preserved xtask-inputs-v1 input set includes all original source directories
and normative files. Importing this module only defines constants/functions;
callers explicitly choose when the ordinary file reads occur.
"""
import hashlib
import os
from pathlib import Path

SOURCE_DIRS = ("crates", "adapters", "apps", "tools", "tests", ".cargo", ".github")
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "ARCHITECTURE.md", "README.md", "rustfmt.toml")
IGNORED_DIRS = {"target", ".git", "__pycache__"}
FINGERPRINT_ALGORITHM = "xtask-inputs-v1: sorted UTF-8 relative paths; fold SHA256(previous32 || path_length_BE64 || path_UTF8 || data_length_BE64 || data), initial32=zero"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def collect_files(root, directory):
    directory = root / directory
    if not directory.is_dir():
        raise ValueError("missing input directory " + str(directory))
    found = []
    for current, directories, files in os.walk(directory, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in directories + files):
            raise ValueError('source/normative fingerprints refuse symbolic links: ' + str(current))
        directories[:] = sorted(name for name in directories if name not in IGNORED_DIRS)
        found.extend(Path(current) / name for name in files)
    return found


def fingerprint_files(root, files):
    previous = bytes(32)
    rows = []
    for path in sorted(files, key=lambda path: path.relative_to(root).as_posix().encode("utf-8")):
        name, data = path.relative_to(root).as_posix(), path.read_bytes()
        encoded = name.encode("utf-8")
        previous = hashlib.sha256(previous + len(encoded).to_bytes(8, "big") + encoded + len(data).to_bytes(8, "big") + data).digest()
        rows.append({"path": name, "bytes": len(data), "sha256": digest(data)})
    return previous.hex(), rows


def fingerprints(root):
    files = [path for directory in SOURCE_DIRS for path in collect_files(root, directory)]
    files.extend(root / name for name in SOURCE_FILES)
    source, source_rows = fingerprint_files(root, files)
    spec, spec_rows = fingerprint_files(root, collect_files(root, "spec"))
    if not source_rows or not spec_rows:
        raise ValueError("source/specification input set is empty")
    return {"algorithm": FINGERPRINT_ALGORITHM, "source_sha256": source, "spec_sha256": spec,
            "source_files": source_rows, "spec_files": spec_rows}

