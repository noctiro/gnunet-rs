#!/usr/bin/env python3
"""Build fixed reference-only C libraries in a private POSIX prefix.

Does not invoke brew install, sudo or a global Python installer. Existing
compiler/system development dependencies remain externally supplied; this
isolates sodium/JSON/HTTP libraries and Meson/Ninja tooling. The development
host is macOS; the same Autoconf recipe is used by the Linux reference CI job.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time

PACKAGES = (
    ("libsodium-1.0.22", "https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz", "adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"),
    ("jansson-2.15.1", "https://github.com/akheron/jansson/releases/download/v2.15.1/jansson-2.15.1.tar.gz", "0c7114dc0b2d22a670724a1f95922029d7077c19dbf79a584cb8084d2f267f2f"),
    ("libmicrohttpd-1.0.10", "https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.10.tar.gz", "04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685"),
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unpack(path, target):
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                raise ValueError("archive path escapes the private build tree")
            if member.issym() or member.islnk():
                if Path(member.linkname).is_absolute() or ".." in Path(member.linkname).parts:
                    raise ValueError("archive link escapes the private build tree")
        archive.extractall(target)


def bootstrap(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prefix, venv = output / "prefix", output / "venv"
    report = {"schema": 1, "kind": "isolated-reference-c-dependencies", "status": "failed", "packages": [], "commands": [],
              "prefix": str(prefix), "meson": str(venv / "bin/meson"), "ninja": str(venv / "bin/ninja"),
              "host": {"system": platform.system(), "machine": platform.machine()}, "global_installation": False}
    def run(name, command, cwd=None):
        log = output / (name + ".log")
        started = time.monotonic()
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=900)
        row = {"name": name, "argv": [str(arg) for arg in command], "cwd": str(cwd) if cwd else None,
               "exit_code": result.returncode, "elapsed_seconds": round(time.monotonic() - started, 6), "log": log.name, "log_sha256": digest(log)}
        report["commands"].append(row)
        if result.returncode:
            raise ValueError("dependency command failed: " + name + "; see " + str(log))
    try:
        if platform.system() not in ("Darwin", "Linux"):
            raise ValueError("the reference bootstrap currently supports macOS and Linux")
        downloads = output / "downloads"
        downloads.mkdir()
        run("python-venv", [sys.executable, "-m", "venv", str(venv)])
        run("build-tools", [str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "meson==1.9.1", "ninja==1.13.0"])
        for package, url, expected in PACKAGES:
            archive = downloads / (package + ".tar.gz")
            run(package + "-download", ["curl", "--fail", "--location", "--retry", "2", "--output", str(archive), url])
            observed = digest(archive)
            if observed != expected:
                raise ValueError("download checksum mismatch: " + package)
            report["packages"].append({"name": package, "url": url, "archive_sha256": observed})
            unpack(archive, output)
            source = output / package
            configure = ["./configure", "--prefix=" + str(prefix), "--enable-shared", "--disable-static"]
            if package.startswith("libmicrohttpd"):
                configure += ["--disable-doc", "--disable-examples"]
            run(package + "-configure", configure, source)
            run(package + "-compile", ["make", "-j", str(args.jobs)], source)
            run(package + "-install", ["make", "install"], source)
        report["pkg_config_files"] = [{"path": str(path), "sha256": digest(path)} for path in sorted((prefix / "lib/pkgconfig").glob("*.pc"))]
        for name in ("libsodium.pc", "jansson.pc", "libmicrohttpd.pc"):
            if not (prefix / "lib/pkgconfig" / name).is_file():
                raise ValueError("installed dependency metadata missing: " + name)
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        (output / "dependency-result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "receipt": str(output / "dependency-result.json"), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new private build directory")
    parser.add_argument("--jobs", default=4, type=int)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be 1..64")
    return bootstrap(args)


if __name__ == "__main__":
    raise SystemExit(main())
