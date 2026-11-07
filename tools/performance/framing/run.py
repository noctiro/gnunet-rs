#!/usr/bin/env python3
"""Reproduce a framing-only release workload in a new isolated source snapshot."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FRAMED = "adapters/transport-std/src/framed.rs"
TEST = "framed::performance_probe::unix_batch"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_files(root):
    paths = []
    for directory in (".cargo", "crates", "adapters", "apps", "tools", "tests", "spec"):
        for path in (root / directory).rglob("*"):
            if any(part in ("target", ".git", "__pycache__") for part in path.relative_to(root).parts):
                continue
            if path.is_symlink():
                raise ValueError("source snapshot refuses symlink: " + str(path))
            if path.is_file():
                paths.append(path)
    paths.extend(root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "ARCHITECTURE.md", "README.md", "LICENSE"))
    return sorted(paths)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--admission", choices=("borrowed", "owned"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--toolchain", default="1.99.1")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error("repeats must be 1..20")
    runner_digest = sha(__file__)
    source = args.workspace.resolve()
    output = args.output.resolve()
    if output == source or source in output.parents:
        parser.error("output must be outside the measured source workspace")
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / "workspace"
    facts = {}
    for path in source_files(source):
        name = path.relative_to(source).as_posix()
        facts[name] = sha(path)
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if sha(destination) != facts[name]:
            raise RuntimeError("source changed during snapshot: " + name)
    (output / "source-inputs.json").write_text(json.dumps(facts, sort_keys=True, indent=2) + "\n")
    production = (snapshot / FRAMED).read_bytes()
    template = (HERE / "probe.rs.in").read_text()
    template_digest = hashlib.sha256(template.encode()).hexdigest()
    call = "framed.queue(&bytes)" if args.admission == "borrowed" else "framed.queue_owned(bytes)"
    if template.count("__ADMISSION_CALL__") != 1:
        raise ValueError("benchmark admission adapter placeholder changed")
    probe = template.replace("__ADMISSION_CALL__", call).encode()
    (snapshot / FRAMED).write_bytes(production + probe)
    target = output / "target"
    versions = {}
    for name in ("cargo", "rustc"):
        command = [name, "+" + args.toolchain, "--version", "--verbose"]
        version = subprocess.run(command, cwd=snapshot, capture_output=True, check=True)
        versions[name] = dict(argv=command, stdout=version.stdout.decode(), stderr=version.stderr.decode())
    argv = ["cargo", "+" + args.toolchain, "test", "-p", "gnunet-transport-host", "--lib", "--release", "--no-run", "--offline", "--locked", "--target-dir", str(target), "-j", "2"]
    build_argv = list(argv)
    with (output / "build.log").open("wb") as log:
        built = subprocess.run(argv, cwd=snapshot, stdout=log, stderr=subprocess.STDOUT)
    if built.returncode:
        raise RuntimeError("benchmark build failed; inspect " + str(output / "build.log"))
    match = re.search(r"Executable unittests src/lib.rs \((.+)\)", (output / "build.log").read_text())
    if not match:
        raise RuntimeError("actual built test executable missing")
    binary = Path(match.group(1))
    binary_digest = sha(binary)
    records = []
    for repeat in range(args.repeats):
        for case in range(7):
            metrics = output / ("r%d-c%d.json" % (repeat, case))
            log = output / ("r%d-c%d.log" % (repeat, case))
            env = dict(os.environ)
            env["GNUNET_FRAME_BENCH_CASE"] = str(case)
            env["GNUNET_FRAME_BENCH_OUTPUT"] = str(metrics)
            argv = [str(binary), "--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"]
            if sha(binary) != binary_digest:
                raise RuntimeError("benchmark executable changed before workload")
            started = time.monotonic()
            result = subprocess.run(argv, cwd=snapshot, env=env, capture_output=True, timeout=30)
            elapsed = time.monotonic() - started
            log.write_bytes(result.stdout + result.stderr)
            if sha(binary) != binary_digest:
                raise RuntimeError("benchmark executable changed during workload")
            if result.returncode or not metrics.exists():
                raise RuntimeError("benchmark failed or omitted metrics: " + str(log))
            data = json.loads(metrics.read_text())
            if data["case"] != case or not data["all_bytes_and_order_checked"] or data["rounds"] != 400:
                raise RuntimeError("actual workload or byte validation missing")
            records.append(dict(repeat=repeat, case=case, exit_code=result.returncode,
                                argv=argv, binary_sha256_before=binary_digest, binary_sha256_after=binary_digest,
                                seconds=elapsed, metrics=str(metrics), metrics_sha256=sha(metrics),
                                log=str(log), log_sha256=sha(log)))
    if (snapshot / FRAMED).read_bytes() != production + probe:
        raise RuntimeError("production prefix/probe changed during measurement")
    if sha(HERE / "probe.rs.in") != template_digest:
        raise RuntimeError("probe template changed during measurement")
    if sha(__file__) != runner_digest:
        raise RuntimeError("runner changed during measurement")
    for name, digest in facts.items():
        if name != FRAMED and sha(snapshot / name) != digest:
            raise RuntimeError("snapshot input changed during measurement: " + name)
    report = dict(schema=2, scope="TX framing-only release microbenchmark; raw read_exact peer; no C/domain/crypto/RX-framing or product speedup claim",
                  source=str(source), source_inputs=str(output / "source-inputs.json"), source_inputs_sha256=sha(output / "source-inputs.json"),
                  production_prefix_sha256=hashlib.sha256(production).hexdigest(), appended_probe_sha256=hashlib.sha256(probe).hexdigest(),
                  template_sha256=template_digest, admission_adapter=args.admission,
                  runner_sha256=runner_digest, toolchain=versions, build_argv=build_argv,
                  host=dict(platform=platform.platform(), python=sys.version),
                  binary=str(binary), binary_sha256=binary_digest, build_log_sha256=sha(output / "build.log"),
                  snapshot_inputs_unchanged=True, records=records, validation_after_timed_interval=True,
                  machine_isolated=False, CPU_or_allocator_instrumentation=False, product_speedup_claim=False)
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": str(output / "result.json"), "completed_workloads": len(records), "product_speedup_claim": False}))


if __name__ == "__main__":
    run()
