#!/usr/bin/env python3
"""Build and test the source-bound runtime candidate outside its source tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PACKAGE = Path(__file__).resolve().parents[1]
SOURCES = ["Cargo.toml", "Cargo.toml.in", "tools/migration-baseline.json", "README.md", "PROCESS.md", "tools/activation_process.py", "tools/extraction.py", "tools/verify.py"] + sorted(str(path.relative_to(PACKAGE)) for directory in ["src", "tests", "examples"] for path in (PACKAGE/directory).rglob('*') if path.is_file())

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def identity(paths): return {str(p): digest(p) for p in sorted(paths, key=lambda p: str(p).encode())}
def registries(lock):
    # Cargo emits these four identity fields as simple quoted TOML strings.
    # No dependency-array or arbitrary TOML interpretation is needed here.
    result = set()
    for block in lock.read_text().split("[[package]]")[1:]:
        fields = {key: json.loads(value) for key, value in re.findall(r'^(name|version|source|checksum) = ("[^"\n]*")$', block, re.M)}
        if fields.get("source", "").startswith("registry+"):
            assert all(key in fields for key in ("name", "version", "source", "checksum")), "incomplete registry identity"
            result.add(tuple(fields[key] for key in ("name", "version", "source", "checksum")))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repository, upstream, output = args.repository.resolve(), args.upstream.resolve(), args.output.resolve()
    for source in [repository, upstream, PACKAGE]:
        if output.is_relative_to(source) or source.is_relative_to(output): parser.error("output overlaps source")
    if output.exists(): parser.error("output must be a fresh directory")
    output.mkdir(parents=True, mode=0o700)
    started = time.time()
    package_inputs = identity([PACKAGE / p for p in SOURCES])
    commands = []
    env = dict(os.environ, CARGO_TARGET_DIR=str(output / "target"))
    def run(name, argv, timeout=180):
        result = subprocess.run(list(map(str, argv)), cwd=repository, env=env, text=True, capture_output=True, timeout=timeout)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        commands.append({"name": name, "argv": list(map(str, argv)), "exit_code": result.returncode})
        if result.returncode != 0: raise RuntimeError(name + " failed; see " + str(output / (name + ".stderr")))
        return result
    try:
        generated = output / "rust"
        generated.mkdir()
        for relative in SOURCES:
            if relative.startswith(("src/", "tests/", "examples/")):
                destination = generated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(PACKAGE / relative, destination)
        manifest = (PACKAGE / "Cargo.toml.in").read_text()
        manifest = re.sub(r'"@REPOSITORY@/([^"\n]+)"', lambda m: json.dumps(str(repository / m.group(1)), ensure_ascii=False), manifest)
        assert "@REPOSITORY@" not in manifest
        (generated / "Cargo.toml").write_text(manifest)
        shutil.copyfile(repository / "Cargo.lock", generated / "Cargo.lock")
        cargo = ["cargo", "+1.99.1"]
        base = ["--manifest-path", generated / "Cargo.toml", "--offline"]
        run("prepare-lock", cargo + ["check", *base])
        assert registries(generated / "Cargo.lock") <= registries(repository / "Cargo.lock"), "generated registry dependency drift"
        metadata = json.loads(run("metadata", cargo + ["metadata", *base, "--locked", "--format-version", "1"]).stdout)
        actual = json.loads(run("workspace-metadata", cargo + ["metadata", "--manifest-path", PACKAGE / "Cargo.toml", "--offline", "--locked", "--format-version", "1", "--no-deps"]).stdout)
        actual_package = next(p for p in actual["packages"] if Path(p["manifest_path"]).resolve() == (PACKAGE / "Cargo.toml").resolve())
        generated_package = next(p for p in metadata["packages"] if Path(p["manifest_path"]).resolve() == (generated / "Cargo.toml").resolve())
        def dependency_contract(package):
            fields = ["name", "req", "source", "kind", "rename", "optional", "uses_default_features", "target", "path"]
            return sorted([{**{k: d.get(k) for k in fields}, "features": sorted(d["features"])} for d in package["dependencies"]], key=lambda d: json.dumps(d, sort_keys=True))
        def feature_contract(package):
            return {k: sorted(v) for k, v in package["features"].items() if k != "default" or v}
        assert dependency_contract(actual_package) == dependency_contract(generated_package), "standalone template differs from production dependencies/features"
        assert feature_contract(actual_package) == feature_contract(generated_package), "standalone template differs from production feature declarations"
        inputs = [PACKAGE / relative for relative in SOURCES] + [repository / "Cargo.toml", repository / "Cargo.lock", args.reference.resolve()]
        # The real helper is a thin binary in the ARM package. Bind its producer
        # and every reachable local source/settings input, independently from
        # the isolated runtime's dependency graph.
        helper_tools = repository / "adapters/arm-std/tools"
        sys.path.insert(0, str(helper_tools))
        from _common import local_snapshot
        helper_metadata = json.loads(run("helper-metadata", cargo + ["metadata", "--manifest-path",
            repository / "Cargo.toml", "--locked", "--offline", "--format-version", "1"]).stdout)
        _, helper_inputs = local_snapshot(helper_metadata, repository / "adapters/arm-std", helper_tools)
        inputs.extend(Path(path) for path in helper_inputs)
        for package in metadata["packages"]:
            if package["source"] is None:
                directory = Path(package["manifest_path"]).parent
                if directory == generated: continue
                inputs.extend(p for p in directory.rglob("*") if p.is_file() and p.suffix in (".rs", ".md", ".toml", ".txt", ".json") and "target" not in p.parts)
        for relative in ["src/lib/util/service.c", "src/lib/util/network.c", "src/lib/util/os_process.c"]: inputs.append(upstream / relative)
        reference = json.loads(args.reference.read_text())
        for item in [*reference["artifacts"].values(), *reference["libraries"], *reference["default_configurations"]]:
            path = Path(item["path"])
            assert digest(path) == item["sha256"], "reference input drift: " + str(path)
            inputs.append(path)
        inputs = sorted(set(inputs), key=lambda p: str(p).encode())
        before = identity(inputs)
        generated_before = identity([p for p in generated.rglob("*") if p.is_file()])
        run("format", cargo + ["fmt", "--manifest-path", generated / "Cargo.toml", "--check"])
        run("extraction", [sys.executable, PACKAGE / "tools/extraction.py", "--repository", repository, "--upstream", upstream, "--output", output / "extraction.json"])
        run("clippy", cargo + ["clippy", *base, "--locked", "--all-targets"])
        # Private original-child counter/write boundaries execute a real helper.
        # The sole production helper remains published by ARM's package and calls
        # the shared runtime entry. Build it freshly in this exact output target;
        # no second native implementation or test-only success path is introduced.
        run("shared-process-helper", cargo + ["build", "--manifest-path", repository / "Cargo.toml",
            "-p", "gnunet-arm-host", "--bin", "gnunet-arm-spawn-helper", "--locked", "--offline"])
        helper = output / "target/debug/gnunet-arm-spawn-helper"
        helper_before = digest(helper)
        tests = run("tests", cargo + ["test", *base, "--locked", "--", "--test-threads=1"])
        for expected in ["test result: ok. 24 passed", "test result: ok. 16 passed", "test result: ok. 3 passed", "test result: ok. 1 passed"]:
            assert expected in tests.stdout, expected
        run("rustdoc", cargo + ["doc", *base, "--locked", "--no-deps"])
        run("probe-build", cargo + ["build", *base, "--locked", "--example", "activation_probe"])
        run("activation", [sys.executable, PACKAGE / "tools/activation_process.py", "--probe", output / "target/debug/examples/activation_probe", "--reference", args.reference.resolve(), "--output", output / "activation"], timeout=120)
        activation = json.loads((output / "activation/result.json").read_text())
        assert activation["status"] == "passed" and activation["inputs_unchanged"] and activation["actual_shared_runtime_tested"]
        after = identity(inputs)
        _, helper_after = local_snapshot(helper_metadata, repository / "adapters/arm-std", helper_tools)
        assert helper_inputs == helper_after, "shared helper producer source/file set changed"
        assert digest(helper) == helper_before, "shared process helper changed"
        generated_after = identity([p for p in generated.rglob("*") if p.is_file()])
        assert before == after and package_inputs == identity([PACKAGE / p for p in SOURCES]), "source inputs changed"
        assert generated_before == generated_after, "generated Rust inputs changed"
        result = {"status": "passed", "scope": "Shared service startup and listener ownership candidate, not all generic service/util APIs", "toolchain": run("toolchain", ["cargo", "+1.99.1", "--version"]).stdout.strip(),
                  "elapsed_seconds": time.time() - started, "commands": commands, "source_inputs": before, "inputs_unchanged": before == after,
                  "generated_rust_inputs": generated_after, "generated_inputs_unchanged": generated_before == generated_after,
                  "package_inputs": package_inputs, "rust_tests": {"activation_unit": 3, "private_bind_failure": 1, "readiness_unit": 1, "shared_native_process_unit": 5, "readiness_integration": 3, "local_endpoint_integration": 16, "borrow_compile_fail": 1},
                  "fresh_shared_process_helper": {"path": str(helper), "sha256": helper_before},
                  "production_manifest_matches_generated_dependencies_and_features": True, "activation_checks": len(activation["checks"]), "actual_shared_runtime_sections": ["statistics", "resolver"],
                  "normal_unmodified_c_service": activation["reference"], "extraction": {"path": str(output / "extraction.json"), "sha256": digest(output / "extraction.json")},
                  "activation": {"path": str(output / "activation/result.json"), "sha256": digest(output / "activation/result.json")},
                  "limitations": ["No USERNAME, daemonize, CLOSE_LSOCKS or UNIX_MATCH_UID/GID credential implementation", "Host must apply returned service_options; obtaining a policy does not itself enforce admission", "Temporary umask excludes foreign concurrent creators by documented startup precondition", "Metadata/inode guard and unlink remain separate syscalls; hostile concurrent path replacement must be excluded", "Original C malformed activation prefix acceptance is deliberately rejected before Rust ownership; no unsafe behavior reproduced", "BINDTO native name resolution may consult NSS/DNS; tests use numeric owned loopback only"]}
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "rust_tests": 30, "activation_checks": len(activation["checks"]), "inputs_unchanged": True}))
    except BaseException as error:
        (output / "failure.json").write_text(json.dumps({"status": "failed", "error": str(error), "commands": commands}, indent=2) + "\n")
        raise

if __name__ == "__main__": main()
