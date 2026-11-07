#!/usr/bin/env python3
"""Build the unmodified pinned GNUnet STATISTICS daemon, client and libraries.

This is an external test reference, never a production Rust FFI backend. The
Meson build graph is unchanged; selecting two executable targets builds their
normal upstream library dependencies. Installation staging only copies official
build outputs and generated default configuration files without rewriting them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import time

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
TAG = "v0.29.1"
TARGETS = {
    "client": "src/cli/statistics/gnunet-statistics",
    "service": "src/service/statistics/gnunet-service-statistics",
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def source_state(source):
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    tag = subprocess.check_output(["git", "-C", str(source), "rev-parse", TAG + "^{}"], text=True).strip()
    if revision != REVISION or tag != REVISION:
        raise ValueError("reference HEAD and release tag must resolve to the pinned revision")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "--ignore-submodules=none", "HEAD", "--"], check=True)
    entries = subprocess.check_output(["git", "-C", str(source), "ls-files", "--stage", "-z"]).decode().split("\0")
    paths = {}
    for entry in entries:
        if entry:
            metadata, name = entry.split("\t", 1)
            paths[name] = metadata.split()
    digest = hashlib.sha256()
    files = 0
    gitlinks = []
    for name in sorted(paths):
        path = source / name
        if paths[name][0] == "160000":
            data = ("gitlink:" + paths[name][1]).encode()
            gitlinks.append({"path": name, "commit": paths[name][1]})
        elif path.is_symlink():
            data = os.readlink(path).encode()
        elif path.is_file():
            data = path.read_bytes()
        else:
            raise ValueError("tracked reference input is absent: " + name)
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big") + encoded + len(data).to_bytes(8, "big") + data)
        files += 1
    return {"revision": revision, "tag": TAG, "tracked_files": files,
            "tracked_input_sha256": digest.hexdigest(), "gitlinks": gitlinks, "tracked_sources_clean": True}


def run_logged(output, name, argv, env, timeout=1200):
    log = output / (name + ".log")
    started = time.monotonic()
    with log.open("wb") as stream:
        process = subprocess.run(argv, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, timeout=timeout)
    row = {"name": name, "argv": [str(value) for value in argv], "exit_code": process.returncode,
           "elapsed_seconds": round(time.monotonic() - started, 6), "log": str(log), "log_sha256": sha256(log)}
    return row


def stage_outputs(build, prefix):
    prefix.mkdir(parents=True, exist_ok=False)
    records = {}
    destination = {"client": prefix / "bin/gnunet-statistics",
                   "service": prefix / "lib/gnunet/libexec/gnunet-service-statistics"}
    for name, relative in TARGETS.items():
        original = build / relative
        if not original.is_file() or not os.access(original, os.X_OK):
            raise ValueError("required reference binary missing: " + str(original))
        target = destination[name]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        if sha256(original) != sha256(target):
            raise ValueError("staged executable changed")
        records[name] = {"path": str(target), "built_path": str(original), "sha256": sha256(target)}
    library_files = []
    for directory, stem in ((build / "src/lib/util", "libgnunetutil"),
                            (build / "src/service/statistics", "libgnunetstatistics")):
        for original in sorted(directory.glob(stem + ".*")):
            if not original.is_file() or not (".so" in original.name or original.name.endswith(".dylib")):
                continue
            target = prefix / "lib" / original.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, target, follow_symlinks=False)
            library_files.append({"path": str(target), "symlink": target.is_symlink()})
    for row in library_files:
        row["sha256"] = sha256(row["path"])
    if not any("libgnunetutil" in row["path"] for row in library_files) or not any("libgnunetstatistics" in row["path"] for row in library_files):
        raise ValueError("normal reference shared libraries were not built")
    defaults = prefix / "share/gnunet/config.d"
    defaults.mkdir(parents=True)
    configurations = []
    for relative in ("src/lib/util/util.conf", "src/service/statistics/statistics.conf"):
        original = build / relative
        target = defaults / original.name
        shutil.copy2(original, target)
        configurations.append({"path": str(target), "sha256": sha256(target)})
    return records, library_files, configurations


def build_reference(args):
    source, output, prefix = args.source.resolve(), args.output.resolve(), args.prefix.resolve()
    if output.exists() or prefix.exists():
        raise ValueError("output and staging prefix must both be new directories")
    output.mkdir(parents=True)
    build = output / "build"
    report = {"schema": 1, "kind": "unmodified-official-c-reference-build", "status": "failed",
              "builder_sha256": sha256(__file__),
              "source": str(source), "prefix": str(prefix), "build": str(build), "commands": [],
              "host": {"system": platform.system(), "machine": platform.machine()},
              "scope": "Full upstream STATISTICS executables and normal util/statistics shared libraries; other GNUnet services are not built by this target selection."}
    try:
        report["upstream"] = source_state(source)
        env = dict(os.environ)
        if args.deps_prefix:
            dependencies = args.deps_prefix.resolve()
            pkgconfig = str(dependencies / "lib/pkgconfig")
            env["PKG_CONFIG_PATH"] = pkgconfig + (os.pathsep + env["PKG_CONFIG_PATH"] if env.get("PKG_CONFIG_PATH") else "")
            env["CPPFLAGS"] = "-I" + str(dependencies / "include") + " " + env.get("CPPFLAGS", "")
            env["LDFLAGS"] = "-L" + str(dependencies / "lib") + " " + env.get("LDFLAGS", "")
        report["build_environment"] = {name: env[name] for name in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_PATH") if name in env}
        report["tool_versions"] = []
        for name, command in (("meson-version", [str(args.meson), "--version"]),
                              ("compiler-version", [*shlex.split(env.get("CC", "cc")), "--version"])):
            row = run_logged(output, name, command, env, timeout=30)
            report["tool_versions"].append(row)
            if row["exit_code"]:
                raise ValueError("cannot record actual build tool version: " + name)
        setup = [str(args.meson), "setup", str(build), str(source), "--prefix=" + str(prefix), "--libdir=lib",
                 "--buildtype=debugoptimized", "-Ddisable-autostart=true", "-Dexclude-manpages=true",
                 "-Dinstall-rpath=true", "-Dtestbed=false", "-Dexperimental=false"]
        if args.ninja:
            env["NINJA"] = str(args.ninja.resolve())
        for name, command in (("meson-setup", setup), ("meson-build", [str(args.meson), "compile", "-C", str(build), "-j", str(args.jobs), "gnunet-statistics", "gnunet-service-statistics"])):
            row = run_logged(output, name, command, env)
            report["commands"].append(row)
            if row["exit_code"]:
                raise ValueError("reference command failed: " + name + "; see " + row["log"])
        report["artifacts"], report["libraries"], report["default_configurations"] = stage_outputs(build, prefix)
        report["generated_config"] = {"path": str(build / "gnunet_private_config.h"), "sha256": sha256(build / "gnunet_private_config.h")}
        report["source_unchanged"] = source_state(source) == report["upstream"]
        if not report["source_unchanged"]:
            raise ValueError("reference source changed during build")
        report["runtime_environment"] = {"GNUNET_PREFIX": str(prefix), "LD_LIBRARY_PATH": str(prefix / "lib"), "DYLD_LIBRARY_PATH": str(prefix / "lib")}
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        save(output / "build-result.json", report)
    print(json.dumps({"status": report["status"], "receipt": str(output / "build-result.json"), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--deps-prefix", type=Path)
    parser.add_argument("--meson", default=shutil.which("meson") or "meson", type=Path)
    parser.add_argument("--ninja", type=Path)
    parser.add_argument("--jobs", default=4, type=int)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be 1..64")
    return build_reference(args)


if __name__ == "__main__":
    raise SystemExit(main())
