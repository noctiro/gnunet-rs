#!/usr/bin/env python3
"""Record a native Rust STATISTICS build or assemble a WATCH review candidate."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

import release as gate
import statistics_watch_initial as watch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cargo_artifacts import CargoArtifacts


BUILD_KIND = "statistics-watch-native-rust-build"


def write_new(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def regular_ref(path, root=None):
    path = Path(path).absolute()
    if root is None:
        return {"path": str(path), "sha256": gate.sha(path)}
    base = root if path.is_relative_to(root) else root.resolve()
    name = path.relative_to(base).as_posix()
    bound = gate.regular(root, name)
    return {"path": name, "sha256": gate.sha(bound)}


def compiler_host(data):
    fields = dict(line.split(": ", 1) for line in data.decode("utf-8").splitlines() if ": " in line)
    host = fields.get("host", "")
    watch.require("-linux-" in host and fields.get("release") and fields.get("commit-hash"),
                  "the Rust compiler must report an installed Linux host toolchain")
    return host


def check_elf(path):
    with Path(path).open("rb") as stream:
        watch.require(stream.read(4) == b"\x7fELF", "WATCH actors require native Linux executable files")


def record_build(output):
    watch.require(platform.system() == "Linux", "the WATCH build requires a Linux host")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = gate.implementation_inputs(gate.ROOT)
    toolchain = output / "rustc-info.txt"
    cargo_log = output / "cargo.jsonl"
    cargo_stderr = output / "cargo.stderr"
    env = dict(os.environ)
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        env.pop(key, None)
    rustc = shutil.which("rustc")
    watch.require(rustc is not None, "the installed Rust compiler was not found")
    env.update(RUSTC=rustc, RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    info = subprocess.run([rustc, "-vV"], cwd=gate.ROOT, env=env, capture_output=True, check=True, timeout=15)
    target = compiler_host(info.stdout)
    toolchain.write_bytes(info.stdout)
    target_dir = output / "target"
    cargo_argv = ["cargo", "build", "--locked", "--offline", "--jobs", "1",
                  "--package", "gnunet-service-statistics", "--bin", "gnunet-service-statistics",
                  "--target", target, "--target-dir", str(target_dir), "--message-format=json"]
    with cargo_log.open("wb") as stdout, cargo_stderr.open("wb") as stderr:
        subprocess.run(cargo_argv, cwd=gate.ROOT, env=env, stdin=subprocess.DEVNULL,
                       stdout=stdout, stderr=stderr, check=True)
    binary = CargoArtifacts(cargo_log.read_bytes()).binary(
        "gnunet-service-statistics", gate.ROOT / "apps/gnunet-service-statistics/Cargo.toml")
    check_elf(binary)
    watch.require(source == gate.implementation_inputs(gate.ROOT), "source changed during the Rust build")
    result = {"schema": 1, "kind": BUILD_KIND, "exit_code": 0,
              "host": {"system": platform.system(), "machine": platform.machine()},
              "argv": cargo_argv, "source_inputs": source, "binary": regular_ref(binary),
              "cargo_log": regular_ref(cargo_log), "cargo_stderr": regular_ref(cargo_stderr),
              "compiler": regular_ref(toolchain),
              "lockfile": regular_ref(gate.ROOT / "Cargo.lock")}
    write_new(output / "build-result.json", result)
    return binary


def original_ref(root, ref):
    actual = regular_ref(ref["path"], root)
    watch.require(actual["sha256"] == ref["sha256"], "build artifact changed: " + ref["path"])
    return actual


def run_ref(root, run_root, ref):
    name = gate.relative(ref["path"])
    return {"path": (run_root.relative_to(root) / name).as_posix(), "sha256": ref["sha256"]}


def actor_from_run(root, run_root, row):
    def observation(phase):
        binary = run_ref(root, run_root, row[phase]["binary"])
        loaded = {}
        for path, digest in row[phase]["loaded_files"].items():
            item = run_ref(root, run_root, {"path": path, "sha256": digest})
            loaded[item["path"]] = item["sha256"]
        return binary, loaded

    before, loaded_before = observation("ready_images")
    after, loaded_after = observation("pre_stop_images")
    watch.require(before == after, "actor executable changed between live captures")
    watch.require(type(row["exit_code"]) is int and row["exit_code"] == 0
                  and not any(row.get(key) for key in ("forced_kill", "forced_cleanup", "timed_out", "launch_failure")),
                  "actor lacks a normal exit")
    logs = [run_ref(root, run_root, {"path": row[key], "sha256": row[key + "_sha256"]})
            for key in ("stdout", "stderr")]
    return {
        "role": row["name"], "argv": row["argv"], "binary": before,
        "binary_before": before["sha256"], "binary_after": after["sha256"],
        "exit_code": row["exit_code"], "termination": "exited",
        "loaded_files_before": loaded_before, "loaded_files_after": loaded_after,
    }, logs


def assemble(root, run_path, rust_path, review_path, source, output):
    root = root.absolute()
    run_path = run_path.absolute()
    implementation = gate.implementation_inputs(gate.ROOT)
    _, survey, _, _ = gate.read_requirements()
    reference = gate.tracked_inputs(source)
    watch.require(reference == survey["paths"], "official source checkout does not match the locked survey")
    observation = regular_ref(run_path, root)
    run = watch.decode(gate.pinned_bytes(root, observation)[1])
    watch.require(run["selected_profile"] == "watch-initial-only" and run["status"] == "passed"
                  and run["linux_image_capture"]["status"] == "matched-long-lived-actors",
                  "requires the successful Linux WATCH run with live actor images")
    run_root = root / Path(observation["path"]).parent
    rust_record = regular_ref(rust_path, root)
    rust = watch.decode(gate.pinned_bytes(root, rust_record)[1])
    c_record = run_ref(root, run_root, run["retained_reference_receipt"])
    c = watch.decode(gate.pinned_bytes(root, c_record)[1])
    watch.require(Path(c["source"]).resolve() == source.resolve()
                  and {row["name"] for row in c["commands"]} == {"meson-setup", "meson-build"}
                  and {row["name"] for row in c["tool_versions"]} == {"meson-version", "compiler-version"},
                  "requires the recorded official build and toolchain for this checkout")
    watch.require(type(rust["schema"]) is int and rust["schema"] == 1 and rust["kind"] == BUILD_KIND
                  and type(rust["exit_code"]) is int and rust["exit_code"] == 0
                  and rust["host"] == c["host"] and rust["host"]["system"] == "Linux"
                  and rust["source_inputs"] == implementation,
                  "requires a successful, matching current native Rust build")
    c_client = c["artifacts"]["client"]
    participants = run["participants"]
    for ref, role in ((rust["binary"], "rust_service"), (c_client, "c_client")):
        owner = participants[role]
        watch.require(ref["path"] == owner["original"] and ref["sha256"] == owner["sha256"],
                      "compiled actor differs from the observed participant")
    built = [original_ref(root, ref) for ref in (
        rust["binary"], c_client, {"path": c_client["built_path"], "sha256": c_client["sha256"]},
    )]
    for item in built:
        check_elf(gate.regular(root, item["path"]))
    cargo = original_ref(root, rust["cargo_log"])
    rustc = original_ref(root, rust["compiler"])
    compiler = compiler_host(gate.pinned_bytes(root, rustc)[1])
    watch.require([value for flag, value in zip(rust["argv"], rust["argv"][1:]) if flag == "--target"]
                  == [compiler],
                  "Cargo build target does not match the recorded compiler host")
    lockfile = rust["lockfile"]
    watch.require(lockfile == {"path": str(gate.ROOT / "Cargo.lock"), "sha256": implementation["Cargo.lock"]},
                  "Rust build did not bind the current lockfile")
    # The workspace lockfile can be outside a private run directory. The source
    # map and checked build record retain that digest without inventing a copy.
    inputs = [original_ref(root, c["generated_config"]), rust_record, rustc,
              original_ref(root, rust["cargo_stderr"])]
    for row in c["commands"] + c["tool_versions"]:
        watch.require(type(row["exit_code"]) is int and row["exit_code"] == 0,
                      "reference command did not exit successfully")
        inputs.append(original_ref(root, {"path": row["log"], "sha256": row["log_sha256"]}))
    for row in c["default_configurations"] + c["libraries"]:
        if not row.get("symlink"):
            inputs.append(original_ref(root, row))
    processes = []
    artifacts = [c_record]
    raw_inputs = list(run["configurations"].values()) + run["persistent_dumps"]
    artifacts.extend(run_ref(root, run_root, item) for item in raw_inputs)
    for row in run["commands"]:
        actor, logs = actor_from_run(root, run_root, row)
        processes.append(actor)
        artifacts.extend(logs)
    receipt = {
        "schema": 1, "kind": "external-boundary-receipt", "requirement": watch.CASE,
        "profile": watch.PROFILE, "direction": "C-to-Rust", "adapter": watch.ADAPTER,
        "result": "pass", "implementation_inputs": implementation, "reference_revision": gate.REVISION,
        "reference_inputs": reference, "build": {
            "profile": watch.PROFILE, "argv": rust["argv"], "toolchain": {"rustc": rustc, "host": rust["host"]},
            "binaries": built, "inputs": inputs, "receipt": cargo,
        },
        "processes": processes, "artifacts": artifacts, "observation": observation,
        "review": regular_ref(review_path, root),
    }
    _, references = gate.verify_receipt_artifacts(receipt, root)
    watch.verify(root, receipt)
    for reference in references:
        gate.file_ref(root, reference)
    watch.require(gate.tracked_inputs(source) == receipt["reference_inputs"]
                  and gate.implementation_inputs(gate.ROOT) == implementation,
                  "sources changed during receipt assembly")
    write_new(output, {"schema": 1, "kind": "external-boundary-review-candidate", "review_state": "pending",
                       "receipt": receipt})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    build = modes.add_parser("build-rust")
    build.add_argument("--output", type=Path, required=True)
    candidate = modes.add_parser("assemble")
    for argument in ("evidence-root", "run", "rust-build", "review", "reference-source", "output"):
        candidate.add_argument("--" + argument, type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "build-rust":
        print(record_build(args.output))
    else:
        assemble(args.evidence_root, args.run, args.rust_build, args.review, args.reference_source, args.output)
        print(args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, gate.Invalid, subprocess.SubprocessError) as error:
        raise SystemExit(f"STATISTICS WATCH receipt refused: {error}")
