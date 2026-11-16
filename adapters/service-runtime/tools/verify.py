#!/usr/bin/env python3
"""Run native runtime and C activation checks from an exact workspace copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from process_verify import contracts, inputs as workspace_inputs, stage

PACKAGE = Path(__file__).resolve().parents[1]
SOURCES = ["Cargo.toml", "README.md", "PROCESS.md", "tools/activation_process.py", "tools/verify.py", "tools/process_verify.py"] + sorted(str(path.relative_to(PACKAGE)) for directory in ["src", "tests", "examples"] for path in (PACKAGE/directory).rglob('*') if path.is_file())
REQUIRED_RUST_TESTS = {
    "accepted::tests::injected_fatal_initialization_closes_only_actual_accepted_owner",
    "configured_access_modes_and_explicit_close_preserve_parent_ownership",
    "inherited_listeners_bypass_addresses_and_never_unlink_paths",
    "readiness_never_consumes_bytes_and_cached_hints_are_rechecked",
    "dropping_pending_wait_retains_the_original_owned_resource",
    "real_hangup_is_classified_without_reading_or_claiming_payload",
    "accepted_tcp_retains_exact_partial_wire_and_original_queue",
    "configured_tcp_binding_uses_actual_port_and_retains_exclusive_ownership",
}

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def identity(paths): return {str(p): digest(p) for p in sorted(paths, key=lambda p: str(p).encode())}
def require_rust_tests(output):
    """Require the selected native targets and their original ownership witnesses."""
    summaries = re.findall(r'^test result: (\w+)\. ([0-9]+) passed; ([0-9]+) failed;', output, re.M)
    if len(summaries) != 4 or any(state != "ok" or int(passed) == 0 or int(failed) != 0
                                  for state, passed, failed in summaries):
        raise ValueError("nonempty runtime library/listener/readiness/TCP targets did not pass")
    completed = set(re.findall(r'^test (\S+) \.\.\. ok$', output, re.M))
    missing = REQUIRED_RUST_TESTS - completed
    if missing:
        raise ValueError("required runtime witnesses missing: " + ", ".join(sorted(missing)))
    return [{"passed": int(passed), "failed": int(failed)} for _, passed, failed in summaries]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error("reference verification requires assertion-enabled Python")
    if os.name != "posix":
        parser.error("the C activation reference requires a Unix host")
    repository, upstream, output = args.repository.resolve(), args.upstream.resolve(), args.output.resolve()
    for source in [repository, upstream, PACKAGE]:
        if output.is_relative_to(source) or source.is_relative_to(output): parser.error("output overlaps source")
    if output.exists(): parser.error("output must be a fresh directory")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    package_inputs = identity([PACKAGE / p for p in SOURCES])
    commands = []
    generated = output / "rust"
    env = dict(os.environ, CARGO_TARGET_DIR=str(output / "target"),
               PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="")
    def run(name, argv, timeout=180):
        result = subprocess.run(list(map(str, argv)), cwd=generated if generated.exists() else repository, env=env, text=True, capture_output=True, timeout=timeout)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        commands.append({"name": name, "argv": list(map(str, argv)), "exit_code": result.returncode})
        if result.returncode != 0: raise RuntimeError(name + " failed; see " + str(output / (name + ".stderr")))
        return result
    try:
        source_snapshot = workspace_inputs(repository)
        stage(repository, generated, source_snapshot)
        cargo = ["cargo", "+1.99.1"]
        manifest = generated / PACKAGE.relative_to(repository) / "Cargo.toml"
        base = ["--manifest-path", manifest, "--offline", "--locked", "-p", "gnunet-service-runtime"]
        metadata = json.loads(run("metadata", cargo + ["metadata", "--manifest-path", manifest, "--offline", "--locked", "--format-version", "1"]).stdout)
        actual = json.loads(run("workspace-metadata", cargo + ["metadata", "--manifest-path", repository / "Cargo.toml", "--offline", "--locked", "--format-version", "1"]).stdout)
        if contracts(actual, repository) != contracts(metadata, generated):
            raise ValueError("staged workspace package/dependency/feature contracts differ")
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
                if directory.is_relative_to(generated): continue
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
        run("format", cargo + ["fmt", "--manifest-path", manifest, "--package", "gnunet-service-runtime", "--check"])
        run("clippy", cargo + ["clippy", *base, "--all-targets", "--", "-D", "warnings"])
        # Private original-child counter/write boundaries execute a real helper.
        # The sole production helper remains published by ARM's package and calls
        # the shared runtime entry. Build it freshly in this exact output target;
        # no second native implementation or test-only success path is introduced.
        run("shared-process-helper", cargo + ["build", "--manifest-path", generated / "Cargo.toml",
            "-p", "gnunet-arm-host", "--bin", "gnunet-arm-spawn-helper", "--locked", "--offline"])
        helper = output / "target/debug/gnunet-arm-spawn-helper"
        helper_before = digest(helper)
        tests = run("tests", cargo + ["test", *base, "--lib", "--test", "listeners", "--test", "readiness", "--test", "tcp", "--", "--test-threads=1"])
        rust_tests = require_rust_tests(tests.stdout)
        run("rustdoc", cargo + ["doc", *base, "--no-deps"])
        run("probe-build", cargo + ["build", *base, "--example", "activation_probe"])
        run("activation", [sys.executable, PACKAGE / "tools/activation_process.py", "--probe", output / "target/debug/examples/activation_probe", "--reference", args.reference.resolve(), "--output", output / "activation"], timeout=120)
        activation = json.loads((output / "activation/result.json").read_text())
        assert activation["status"] == "passed" and activation["inputs_unchanged"] and activation["actual_shared_runtime_tested"]
        after = identity(inputs)
        _, helper_after = local_snapshot(helper_metadata, repository / "adapters/arm-std", helper_tools)
        assert helper_inputs == helper_after, "shared helper producer source/file set changed"
        assert digest(helper) == helper_before, "shared process helper changed"
        generated_after = identity([p for p in generated.rglob("*") if p.is_file()])
        assert before == after and package_inputs == identity([PACKAGE / p for p in SOURCES]), "source inputs changed"
        if workspace_inputs(repository) != source_snapshot or workspace_inputs(generated) != source_snapshot:
            raise ValueError("original or staged workspace source/specification changed")
        assert generated_before == generated_after, "generated Rust inputs changed"
        result = {"status": "passed", "scope": "Shared service startup and listener ownership candidate, not all generic service/util APIs", "toolchain": run("toolchain", ["cargo", "+1.99.1", "--version"]).stdout.strip(),
                  "elapsed_seconds": time.monotonic() - started, "commands": commands, "source_inputs": before, "inputs_unchanged": before == after,
                  "generated_rust_inputs": generated_after, "generated_inputs_unchanged": generated_before == generated_after,
                  "package_inputs": package_inputs,
                  "rust_test_suites": rust_tests,
                  "fresh_shared_process_helper": {"path": str(helper), "sha256": helper_before},
                  "production_manifest_matches_generated_dependencies_and_features": True, "activation_checks": len(activation["checks"]), "actual_shared_runtime_sections": ["statistics", "resolver"],
                  "normal_unmodified_c_service": activation["reference"],
                  "activation": {"path": str(output / "activation/result.json"), "sha256": digest(output / "activation/result.json")},
                  "limitations": ["No USERNAME, daemonize, CLOSE_LSOCKS or UNIX_MATCH_UID/GID credential implementation", "Host must apply returned service_options; obtaining a policy does not itself enforce admission", "Temporary umask excludes foreign concurrent creators by documented startup precondition", "Metadata/inode guard and unlink remain separate syscalls; hostile concurrent path replacement must be excluded", "Original C malformed activation prefix acceptance is deliberately rejected before Rust ownership; no unsafe behavior reproduced", "BINDTO native name resolution may consult NSS/DNS; tests use numeric owned loopback only"]}
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "activation_checks": len(activation["checks"]), "inputs_unchanged": True}))
    except BaseException as error:
        (output / "failure.json").write_text(json.dumps({"status": "failed", "error": str(error), "commands": commands}, indent=2) + "\n")
        raise

if __name__ == "__main__": main()
