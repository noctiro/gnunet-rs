#!/usr/bin/env python3
"""Compile all seven secret-owner Clone/Debug refusals against one actual rlib.

Requires Python 3.9+, the explicitly selected installed Rust toolchain, and
already cached dependencies. This tool never runs the generated Rust code.
Cargo artifacts go only to --target-dir; UI sources and logs go to a fresh
--output directory. The source manifest and lock are never updated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
OWNERS = (
    "exchange::EcdheSecret",
    "exchange::DhSecret",
    "exchange::KeyMaterial",
    "Prk",
    "session::AeadMaterial",
    "session::TcpMaterial",
    "session::TcpStream",
)
TRAITS = ("Clone", "core::fmt::Debug")
CRATE = "gnunet_session_crypto"
EXPECTED_NEGATIVE_CASES = 14


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def inside(path, root):
    return path == root or root in path.parents


def snapshot(paths):
    return {str(path): sha(path) for path in sorted(set(paths))}


def command(argv, cwd, env, output, name):
    args = [str(value) for value in argv]
    proc = subprocess.run(args, cwd=str(cwd), env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    stdout = output / (name + ".stdout")
    stderr = output / (name + ".stderr")
    stdout.write_text(proc.stdout, encoding="utf-8")
    stderr.write_text(proc.stderr, encoding="utf-8")
    receipt = {
        "argv": args, "cwd": str(cwd), "exit_code": proc.returncode,
        "stdout": str(stdout), "stdout_sha256": sha(stdout),
        "stderr": str(stderr), "stderr_sha256": sha(stderr),
    }
    save(output / (name + ".json"), receipt)
    return proc, receipt


def require_success(proc, name):
    if proc.returncode != 0:
        raise ValueError(name + " failed; see its captured stdout/stderr")


def select_package(metadata, manifest):
    packages = [package for package in metadata["packages"]
                if Path(package["manifest_path"]).resolve() == manifest]
    if len(packages) != 1:
        raise ValueError("metadata did not identify exactly the requested manifest")
    package = packages[0]
    targets = [target for target in package["targets"]
               if target["name"] == CRATE and "lib" in target["kind"]]
    if len(targets) != 1:
        raise ValueError("requested manifest must contain exactly gnunet_session_crypto lib")
    return package, targets[0]


def select_artifact(stdout, package, target, target_dir):
    events = []
    for line in stdout.splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        actual = event.get("target", {})
        if event.get("package_id") != package["id"] or actual.get("name") != CRATE:
            continue
        if ("lib" not in actual.get("kind", []) or
                Path(actual["src_path"]).resolve() != Path(target["src_path"]).resolve()):
            raise ValueError("matching package artifact has an unexpected library target")
        events.append(event)
    if len(events) != 1:
        raise ValueError("build must report exactly one requested library artifact event")
    event = events[0]
    rlibs = [Path(filename).resolve() for filename in event["filenames"]
             if Path(filename).suffix == ".rlib"]
    if len(rlibs) != 1 or not rlibs[0].is_file() or not inside(rlibs[0], target_dir):
        raise ValueError("build did not report one existing rlib inside --target-dir")
    return rlibs[0], event


def expected_error(stderr, path, owner, trait):
    diagnostics = [json.loads(line) for line in stderr.splitlines() if line.strip()]
    errors = [entry for entry in diagnostics if entry.get("level") == "error"]
    coded = [entry for entry in errors if entry.get("code") is not None]
    if len(coded) != 1 or coded[0]["code"].get("code") != "E0277":
        raise ValueError("negative UI must emit exactly one coded error: E0277")
    diagnostic = coded[0]
    if (owner.split("::")[-1] not in diagnostic["message"] or
            trait.split("::")[-1] not in diagnostic["message"]):
        raise ValueError("E0277 does not name the expected owner and trait")
    spans = [span for span in diagnostic["spans"] if span.get("is_primary")]
    if not spans or any(Path(span["file_name"]).resolve() != path for span in spans):
        raise ValueError("E0277 primary span does not identify this UI witness")
    uncoded = [entry for entry in errors if entry.get("code") is None]
    if any(not entry.get("message", "").startswith("aborting due to ") for entry in uncoded):
        raise ValueError("negative UI emitted an unrelated uncoded error")
    return diagnostic


def layout(args, output):
    manifest = args.manifest.resolve(strict=True)
    target_dir = args.target_dir.resolve()
    if not manifest.is_file() or manifest.name != "Cargo.toml":
        raise ValueError("--manifest must identify an existing Cargo.toml")
    if inside(output, manifest.parent) or inside(manifest, output):
        raise ValueError("--output must not overlap the input package")
    if inside(target_dir, output) or inside(output, target_dir):
        raise ValueError("--target-dir and --output must be disjoint")
    if inside(manifest, target_dir):
        raise ValueError("--target-dir cannot contain the input manifest")
    if not args.toolchain or args.toolchain.startswith("-"):
        raise ValueError("--toolchain must name an installed Rust toolchain")
    return manifest, target_dir


def run(args, output):
    manifest, target_dir = layout(args, output)
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env.pop("CARGO_BUILD_TARGET", None)
    # Without --install, rustup run refuses missing toolchains instead of
    # implicitly downloading them as the +toolchain shorthand may do.
    cargo = ["rustup", "run", args.toolchain, "cargo"]
    rustc = ["rustup", "run", args.toolchain, "rustc"]
    cwd = manifest.parent
    manifest_before = sha(manifest)
    proc, version_receipt = command(rustc + ["--version", "--verbose"], cwd, env,
                                    output, "rustc-version")
    require_success(proc, "rustc-version")
    hosts = [line.removeprefix("host: ") for line in proc.stdout.splitlines()
             if line.startswith("host: ")]
    if len(hosts) != 1 or not hosts[0]:
        raise ValueError("rustc did not report one host target")
    host = hosts[0]
    proc, metadata_receipt = command(cargo + ["metadata", "--manifest-path", manifest,
        "--offline", "--locked", "--no-deps", "--format-version", "1"],
        cwd, env, output, "cargo-metadata")
    require_success(proc, "cargo-metadata")
    metadata = json.loads(proc.stdout)
    package, target = select_package(metadata, manifest)
    workspace = Path(metadata["workspace_root"]).resolve()
    verifier = Path(__file__).resolve()
    paths = [manifest, workspace / "Cargo.toml", workspace / "Cargo.lock", verifier]
    paths += sorted(Path(target["src_path"]).resolve().parent.rglob("*.rs"))
    for extra in (workspace / "rust-toolchain.toml", workspace / ".cargo/config.toml"):
        if extra.is_file():
            paths.append(extra)
    if sha(manifest) != manifest_before:
        raise ValueError("input manifest changed during metadata")
    before = snapshot(paths)
    save(output / "inputs-before.json", before)
    proc, build_receipt = command(cargo + ["build", "--manifest-path", manifest,
        "--target-dir", target_dir, "--target", host, "--offline", "--locked",
        "--lib", "--message-format=json"], cwd, env, output, "cargo-build")
    require_success(proc, "cargo-build")
    rlib, event = select_artifact(proc.stdout, package, target, target_dir)
    build_files = set()
    for line in proc.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact":
            for filename in item["filenames"]:
                path = Path(filename).resolve()
                if path.is_file() and inside(path, target_dir):
                    build_files.add(path)
    build_before = snapshot(build_files)
    save(output / "build-artifacts-before.json", build_before)
    search_paths = sorted({path.parent for path in build_files
                           if path.suffix in (".rlib", ".rmeta", ".so", ".dylib", ".dll")})
    if not search_paths:
        raise ValueError("build emitted no dependency library search paths")
    rlib_before = sha(rlib)
    artifact = {
        "path": str(rlib), "sha256_before_ui": rlib_before,
        "bytes": rlib.stat().st_size, "package_id": package["id"],
        "target": event["target"], "profile": event["profile"],
        "cargo_reported_fresh": event["fresh"], "features": event["features"],
        "dependency_search_paths": [str(path) for path in search_paths],
    }
    save(output / "selected-artifact.json", artifact)
    ui = output / "ui"
    generated = output / "artifacts"
    ui.mkdir()
    generated.mkdir()
    common = rustc + ["--edition=2024", "--crate-type=lib", "--emit=metadata",
        "--error-format=json", "--target", host,
        "--extern", CRATE + "=" + str(rlib)]
    for directory in search_paths:
        common += ["-L", "dependency=" + str(directory)]
    cases = []
    for owner in OWNERS:
        for trait in TRAITS:
            name = owner.replace("::", "_") + "_" + trait.split("::")[-1]
            path = (ui / (name + ".rs")).resolve()
            path.write_text("fn needs<T: " + trait + ">() {}\n"
                "pub fn witness() { needs::<" + CRATE + "::" + owner + ">(); }\n",
                encoding="utf-8")
            proc, receipt = command(common + ["--crate-name", "ownership_" + name,
                "-o", generated / (name + ".rmeta"), path], cwd, env, output, name)
            if proc.returncode != 1:
                raise ValueError(name + " must fail type checking with exit code 1")
            diagnostic = expected_error(proc.stderr, path, owner, trait)
            (output / (name + ".rendered")).write_text(diagnostic.get("rendered", ""),
                                                       encoding="utf-8")
            cases.append({"owner": owner, "trait": trait, "source": str(path),
                "source_sha256": sha(path), "diagnostic": "E0277", "passed": True,
                "command_receipt": str(output / (name + ".json")),
                "stderr_sha256": receipt["stderr_sha256"]})
    if (len(cases) != EXPECTED_NEGATIVE_CASES or
            len({(case["owner"], case["trait"]) for case in cases}) != EXPECTED_NEGATIVE_CASES):
        raise ValueError("all fourteen distinct owner/trait refusals must run")
    positive = ui / "positive.rs"
    positive.write_text(
        "pub fn witness() {\n"
        " let secret = gnunet_session_crypto::exchange::EcdheSecret::from_bytes([7; 32]);\n"
        " let public = secret.public_key(); let _copy = public;\n"
        " let _display = format!(\"{public:?}\");\n"
        " let transcript = gnunet_session_crypto::transcript::Hash512State::default();\n"
        " let _checkpoint = transcript.clone();\n"
        "}\n", encoding="utf-8")
    proc, positive_receipt = command(common + ["--crate-name", "ownership_positive",
        "-o", generated / "positive.rmeta", positive], cwd, env, output, "positive")
    require_success(proc, "positive")
    positive_artifact = generated / "positive.rmeta"
    if not positive_artifact.is_file() or positive_artifact.stat().st_size == 0:
        raise ValueError("positive control must produce a nonempty metadata artifact")
    after = snapshot(paths)
    save(output / "inputs-after.json", after)
    if before != after or sha(manifest) != manifest_before:
        raise ValueError("input manifests/lock/source files changed")
    build_after = snapshot(build_files)
    save(output / "build-artifacts-after.json", build_after)
    if build_before != build_after:
        raise ValueError("Cargo-reported build artifacts changed during UI checks")
    rlib_after = sha(rlib)
    if rlib_before != rlib_after:
        raise ValueError("selected rlib changed during UI checks")
    artifact["sha256_after_ui"] = rlib_after
    save(output / "selected-artifact.json", artifact)
    result = {
        "status": "passed", "scope": "public Rust type ownership only; no generated program executed",
        "toolchain": args.toolchain, "host_target": host, "manifest": str(manifest),
        "verifier": {"path": str(verifier), "sha256": sha(verifier)},
        "manifest_sha256_before": manifest_before, "manifest_sha256_after": sha(manifest),
        "inputs_unchanged": True, "selected_rlib": artifact,
        "cargo_reported_artifacts_unchanged": True, "cargo_reported_artifact_count": len(build_files),
        "negative_case_count": len(cases), "negative_cases": cases,
        "positive_control": {"passed": True, "source": str(positive),
            "source_sha256": sha(positive), "artifact": str(positive_artifact),
            "artifact_sha256": sha(positive_artifact),
            "command_receipt": str(output / "positive.json"),
            "stdout_sha256": positive_receipt["stdout_sha256"],
            "stderr_sha256": positive_receipt["stderr_sha256"]},
        "build_receipt": str(output / "cargo-build.json"),
        "metadata_receipt": str(output / "cargo-metadata.json"),
        "compiler_receipt": str(output / "rustc-version.json"),
        "cargo_artifact_selection": "unique exact manifest package_id/lib name/src_path event; no glob",
    }
    save(output / "result.json", result)
    artifact_hashes = {str(path.relative_to(output)): sha(path)
                      for path in sorted(output.rglob("*")) if path.is_file()}
    save(output / "artifacts.json", artifact_hashes)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "target-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    layout(args, output)  # Refuse overlapping inputs before creating any output.
    output.mkdir(parents=True, exist_ok=False)
    try:
        result = run(args, output)
    except Exception as error:
        save(output / "result.json", {"status": "failed", "error_type": type(error).__name__,
                                      "error": str(error)})
        print("ownership verification failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "negative_cases": result["negative_case_count"],
        "positive_control": result["positive_control"]["passed"],
        "result": str(output / "result.json"), "result_sha256": sha(output / "result.json"),
        "artifacts": str(output / "artifacts.json"),
        "artifacts_sha256": sha(output / "artifacts.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
