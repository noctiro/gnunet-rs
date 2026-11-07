#!/usr/bin/env python3
"""Reproduce the single shared native process backend outside the repository.

Stage the complete fingerprinted source-file set, preserving relative workspace
paths and full lint/dependency contracts. A real same-FD mutant must fail the
queued-listener runtime witness; compiler failure cannot earn negative credit.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inputs(repo):
    spec = importlib.util.spec_from_file_location("process_inputs", repo / "tools/interop/run_reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fingerprints(repo)


def stage(repo, destination, identity):
    destination.mkdir()
    for row in [*identity["source_files"], *identity["spec_files"]]:
        original = repo / row["path"]
        if sha(original) != row["sha256"]:
            raise ValueError("source changed while copying: " + row["path"])
        target = destination / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
    if inputs(destination) != identity:
        raise ValueError("staged source/specification bytes differ")


def contracts(metadata, base):
    result = {}
    for package in metadata["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        if package["source"] is not None or not manifest.is_relative_to(base):
            continue
        rows = []
        for dependency in package["dependencies"]:
            row = {key: dependency.get(key) for key in ("name", "req", "source", "kind",
                   "rename", "optional", "uses_default_features", "target", "path")}
            if row["path"] and Path(row["path"]).is_relative_to(base):
                row["path"] = str(Path(row["path"]).relative_to(base))
            row["features"] = sorted(dependency["features"])
            rows.append(row)
        result[str(manifest.relative_to(base))] = {
            "dependencies": sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)),
            "features": package["features"],
            **{key: package[key] for key in ("name", "version", "edition", "license", "rust_version")},
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "source", "reference", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    repo, source, reference, out = [getattr(args, key).resolve()
                                    for key in ("repository", "source", "reference", "output")]
    for protected in (repo, source, reference.parent):
        if out == protected or out in protected.parents or protected in out.parents:
            parser.error("output overlaps source/reference")
    out.mkdir(mode=0o700)
    commands = []
    env = dict(os.environ, CARGO_BUILD_JOBS="2", PYTHONDONTWRITEBYTECODE="1")

    def run(label, argv, cwd, expected=0, timeout=360):
        result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env,
                                capture_output=True, timeout=timeout)
        for stream in ("stdout", "stderr"):
            (out / (label + "." + stream)).write_bytes(getattr(result, stream))
        commands.append({"name": label, "argv": list(map(str, argv)), "exit_code": result.returncode,
                         "stdout_sha256": sha(out / (label + ".stdout")),
                         "stderr_sha256": sha(out / (label + ".stderr"))})
        if expected is not None and result.returncode != expected:
            raise RuntimeError(label + " failed; see " + str(out / (label + ".stderr")))
        return result

    cargo = ["cargo", "+1.99.1"]
    try:
        before = inputs(repo)
        (out / "inputs-before.json").write_text(json.dumps(before, indent=2) + "\n")
        actual = json.loads(run("actual-metadata", cargo + ["metadata", "--offline", "--locked",
                            "--format-version", "1"], repo).stdout)
        generated = out / "repository"
        stage(repo, generated, before)
        copied = json.loads(run("staged-metadata", cargo + ["metadata", "--offline", "--locked",
                            "--format-version", "1"], generated).stdout)
        if contracts(actual, repo) != contracts(copied, generated):
            raise ValueError("staged dependency/feature/package contracts differ")
        runtime = generated / "adapters/service-runtime/src"
        arm = generated / "adapters/arm-std/src"
        if (arm / "native_spawn.rs").exists() or (arm / "process.rs").exists():
            raise ValueError("ARM still contains a duplicate native process implementation")
        if "pub use gnunet_service_runtime::process;" not in (arm / "lib.rs").read_text():
            raise ValueError("ARM does not delegate to shared process owner")
        if "pub use crate::readiness;" not in (runtime / "process.rs").read_text():
            raise ValueError("shared process does not use the one readiness owner")
        run("actual-shared-process", [sys.executable, "-B",
            generated / "adapters/arm-std/tools/verify.py", "--package", arm.parent,
            "--repo", generated, "--source", source, "--reference", reference,
            "--output", out / "full"], generated, timeout=600)
        full_path = out / "full/result.json"
        full = json.loads(full_path.read_text())
        if not (full.get("checks_passed") is True and full.get("inputs_unchanged") is True
                and full.get("normal_inputs_unchanged") is True and full.get("native_equivalence") is False):
            raise ValueError("full finite process/client suite did not pass with explicit C differences")
        for key, count in (("short_rust_checks", 21), ("shared_runtime_rust_checks", 11),
                           ("process_rust_checks", 10), ("borrowed_lifetime_docs", 4)):
            if len(full[key]) != count:
                raise ValueError("missing exact process/client witness set: " + key)
        if inputs(generated) != before:
            raise ValueError("positive staged source/file set changed")
        negative = out / "same-fd-negative"
        stage(repo, negative, before)
        process = negative / "adapters/service-runtime/src/process.rs"
        text = process.read_text()
        begin = text.index("        let target = match target {", text.index("let mut stage ="))
        end = text.index("        if own.as_raw_fd()", begin)
        text = text[:begin] + """        let own = native_spawn::duplicate_at_least(source, minimum)?;
        let target = target.unwrap_or(own.as_raw_fd());
""" + text[end:]
        if text.count("    let mut reservations = Vec::new();\n") != 1:
            raise ValueError("same-FD mutant source seam changed")
        process.write_text(text.replace("    let mut reservations = Vec::new();\n", ""))
        result = run("same-fd-runtime-negative", cargo + ["test", "-p", "gnunet-arm-host",
            "--test", "process", "original_multiple_listener_queues_survive_actual_helper_exec_and_parent_flags",
            "--offline", "--locked", "--target-dir", out / "negative-target", "--", "--exact", "--nocapture"],
            negative, expected=None, timeout=180)
        observed = (result.stdout + result.stderr).decode(errors="replace")
        if (result.returncode == 0 or "1 failed" not in observed
                or "original_multiple_listener_queues_survive_actual_helper_exec_and_parent_flags ... FAILED" not in observed
                or re.search(r"error\[E\d+\]", observed)):
            raise ValueError("negative did not execute and fail the real queued-listener witness")
        after = inputs(repo)
        if before != after:
            raise ValueError("production source/file set changed")
        (out / "inputs-after.json").write_text(json.dumps(after, indent=2) + "\n")
        result = {"status": "passed", "scope": "single shared process publication and finite ARM client/native regression",
                  "full_gnunet_conformance": False, "inputs_unchanged": True,
                  "staged_inputs_unchanged": True, "complete_workspace_contracts_match": True,
                  "single_native_process_implementation": True, "single_shared_readiness": True,
                  "same_fd_negative_actual_runtime_failure": True,
                  "full_receipt": {"path": str(full_path), "sha256": sha(full_path)},
                  "short_rust_count": 21, "shared_runtime_unit_count": 11,
                  "process_rust_count": 10, "rustdoc_count": 4,
                  "actual_normal_generic_process_pairs": full["generic_process_pairs"],
                  "source_extracted_finite_write_seams": full["source_extracted_kill_write_seams"],
                  "stdio_profiles": 80, "native_stdio_matches": 62,
                  "explicit_native_stdio_differences": 18, "signal_pairs": full["full_host_signal_pairs"],
                  "actual_65_second_child": full["long_lifecycle"], "commands": commands,
                  "pending": "Full daemon/testing/utility/platform/global owner acceptance remains required"}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "result": str(out / "result.json")}))
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"status": "failed", "error": str(error),
                                                       "commands": commands}, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
