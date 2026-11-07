#!/usr/bin/env python3
"""Opt-in normal C CLI against normal C/Rust STATISTICS component benchmark.

No participant, socket, resource sample or fingerprint runner is used at import.
The shared original owned-Popen controller is unchanged. This reports complete
CLI lifecycle latency, including process startup/capture, never pure service RPC
latency or whole-node capacity. Execution requires a fresh human-bound approval.
"""
import argparse
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
import tempfile
import time

from conversation_owned import (Blocked, Controller, Deadline, ObservationError,
                                Owner, described, file_hash)

PROFILE = "normal-statistics-c-cli-e2e-benchmark"
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
SUBSYSTEM = "gnunet-normal-benchmark"
NAME = "counter"
PERMISSIONS = {"private-runtime-files", "private-unix",
               "normal-statistics-cli-operations", "owned-normal-process-control",
               "participant-source-artifact-hashing"}
MAX_METADATA = 16 << 20


class BenchmarkInterrupted(BaseException):
    """Handled user stop must cross optional sampler OSError handlers."""


def load_json(path):
    path = Path(path)
    if path.stat().st_size > MAX_METADATA:
        raise Blocked("named JSON exceeds its finite metadata bound")
    return json.loads(path.read_text(encoding="utf-8"))


def checked(row):
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        raise Blocked("actual named path/hash reference is missing")
    path = Path(row["path"])
    if not path.is_absolute() or any(c in str(path) for c in "\0\r\n"):
        raise Blocked("named prerequisite requires an absolute unambiguous path")
    digest, size = file_hash(path)
    if digest != row.get("sha256"):
        raise Blocked("named prerequisite changed: " + str(path))
    return {"path": str(path), "sha256": digest, "bytes": size}


def approval(manifest_path, approval_path, manifest):
    record = load_json(approval_path)
    manifest_sha, _ = file_hash(manifest_path, MAX_METADATA)
    script_sha, _ = file_hash(__file__, MAX_METADATA)
    owner_sha, _ = file_hash(Path(__file__).with_name("conversation_owned.py"), MAX_METADATA)
    permissions = set(PERMISSIONS)
    if manifest.get("resource_profile") == "owned-pid-snapshot":
        permissions.add("owned-pid-resource-observation")
        resource_sha, _ = file_hash(Path(__file__).with_name("statistics_resources.py"), MAX_METADATA)
        if record.get("resource_module_sha256") != resource_sha:
            raise Blocked("approval does not bind this resource collector")
    if record.get("schema") != 1 or record.get("authorized") is not True:
        raise Blocked("new explicit component-benchmark runtime approval is absent")
    if (record.get("profile") != PROFILE or set(record.get("permissions", [])) != permissions
            or record.get("manifest_sha256") != manifest_sha
            or record.get("controller_sha256") != script_sha
            or record.get("owner_module_sha256") != owner_sha):
        raise Blocked("approval does not bind the exact selected scope and tool bytes")
    reference = record.get("human_authorization_reference")
    if not isinstance(reference, str) or not reference.strip():
        raise Blocked("the actual new human authorization reference is required")
    expires = record.get("expires_unix")
    now = time.time()
    if type(expires) not in (float, int) or not now < expires <= now + 86400:
        raise Blocked("approval must have a current finite expiry of at most one day")
    return {"manifest_sha256": manifest_sha, "controller_sha256": script_sha,
            "owner_module_sha256": owner_sha, "record": checked({
                "path": str(Path(approval_path).absolute()),
                "sha256": file_hash(approval_path, MAX_METADATA)[0]}),
            "human_authorization_reference": reference}


class Inputs:
    def __init__(self, manifest):
        if (manifest.get("schema") != 1 or manifest.get("profile") != PROFILE
                or manifest.get("official_revision") != REVISION
                or manifest.get("transport") != "private-unix"
                or manifest.get("storage") != "memory-only-nonpersistent-set"):
            raise Blocked("only the reviewed private Unix/nonpersistent normal profile is implemented")
        self.samples = manifest.get("samples")
        self.warmup = manifest.get("warmup")
        if (type(self.samples) is not int or not 1 <= self.samples <= 25
                or type(self.warmup) is not int or not 0 <= self.warmup <= 4
                or 2 + 4 * (self.samples + self.warmup) > 128):
            raise Blocked("sample/warmup/owned-process bound is invalid")
        self.seconds = manifest.get("total_seconds")
        self.operation_seconds = manifest.get("operation_seconds")
        if (type(self.seconds) is not int or not 30 <= self.seconds <= 600
                or type(self.operation_seconds) is not int or not 1 <= self.operation_seconds <= 20):
            raise Blocked("global/operation deadline is not a finite selected bound")
        self.resources = manifest.get("resource_profile")
        if self.resources not in ("none", "owned-pid-snapshot"):
            raise Blocked("resource profile must be explicitly selected")
        self.bindings = []
        self.receipts = {}
        for implementation in ("c", "rust"):
            reference = checked(manifest["build_receipts"][implementation])
            self.bindings.append(reference)
            receipt = load_json(reference["path"])
            self.receipts[implementation] = receipt
        c, rust = self.receipts["c"], self.receipts["rust"]
        if (c.get("kind") != "unmodified-official-c-reference-build"
                or c.get("status") != "passed" or c.get("source_unchanged") is not True
                or c.get("upstream", {}).get("revision") != REVISION
                or c.get("upstream", {}).get("tracked_sources_clean") is not True
                or c.get("host") != {"system": platform.system(), "machine": platform.machine()}):
            raise Blocked("an actual successful unchanged fixed-C normal build receipt is required")
        if (rust.get("schema") != 1 or rust.get("kind") != "normal-binary-build"
                or rust.get("status") != "passed" or rust.get("implementation") != "rust"
                or rust.get("build_executed") is not True
                or rust.get("native_system") != platform.system()
                or rust.get("native_machine") != platform.machine()):
            raise Blocked("a current actual native normal Rust binary-build index is required")
        for key, maximum in (("underlying_receipts", 64), ("source_bindings", 512)):
            rows = rust.get(key, [])
            if not 1 <= len(rows) <= maximum:
                raise Blocked("Rust compiler/source receipt links are absent or exceed bounds")
            self.bindings.extend(checked(row) for row in rows)
        for key in ("libraries", "default_configurations"):
            rows = c.get(key, [])
            if not 1 <= len(rows) <= 256:
                raise Blocked("fixed C library/default build bindings are missing or too large")
            self.bindings.extend(checked(row) for row in rows)
        extra = manifest.get("source_and_runtime_bindings", [])
        if not 1 <= len(extra) <= 128:
            raise Blocked("reviewed source/runtime dependency bindings are required")
        self.bindings.extend(checked(row) for row in extra)
        self.originals = {}
        for name, producer in (("c_cli", c["artifacts"]["client"]),
                               ("c_service", c["artifacts"]["service"]),
                               ("rust_service", rust.get("artifacts", {}).get("rust.service.statistics"))):
            row = manifest["participants"].get(name)
            if not producer or row != {"path": producer["path"], "sha256": producer["sha256"]}:
                raise Blocked("participant is not the exact normal compiler-produced artifact: " + name)
            self.originals[name] = checked(row)
        self.bindings.extend(self.originals.values())
        self.environment = c.get("runtime_environment", {})
        if not isinstance(self.environment, dict) or set(self.environment) - {
                "GNUNET_PREFIX", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}:
            raise Blocked("unreviewed inherited C runtime environment")
        if any(not isinstance(v, str) or "\0" in v for v in self.environment.values()):
            raise Blocked("invalid selected runtime environment")
        self.snapshots = {}

    def snapshot(self, directory):
        directory.mkdir(mode=0o700)
        for name, row in self.originals.items():
            target = directory / name
            with Path(row["path"]).open("rb") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1 << 16)
            target.chmod(0o555)
            digest, size = file_hash(target)
            if digest != row["sha256"]:
                raise Blocked("participant changed during immutable snapshot")
            self.snapshots[name] = {"path": str(target), "sha256": digest, "bytes": size}

    def recheck(self):
        for row in self.bindings:
            checked(row)
        for row in self.snapshots.values():
            checked(row)


class BenchmarkController(Controller):
    def pump(self, timeout=0.001, cleanup=False):
        # Same owner/pipes/reap implementation; no new thread or process.
        # Record this observer resolution rather than calling the result a
        # pure service latency. Cleanup keeps its original common grace.
        return super().pump(timeout if cleanup else min(timeout, 0.001), cleanup=cleanup)


def configuration(path, endpoint, directory):
    if len(os.fsencode(endpoint)) > 95:
        raise Blocked("private Unix endpoint exceeds the selected portable extent")
    text = ("[PATHS]\nGNUNET_HOME = {root}\nGNUNET_DATA_HOME = {root}\n"
            "GNUNET_CONFIG_HOME = {root}\nGNUNET_RUNTIME_DIR = {root}\n"
            "[statistics]\nUNIXPATH = {endpoint}\nPORT = 0\nHOSTNAME = localhost\n"
            "START_ON_DEMAND = NO\nUNIX_MATCH_UID = YES\nUNIX_MATCH_GID = YES\n"
            "DISABLE_SOCKET_FORWARDING = YES\nACCEPT_FROM = 127.0.0.1;\n"
            "ACCEPT_FROM6 = ::1;\n[arm]\nSTART_SYSTEM_SERVICES = NO\nDEFAULTSERVICES =\n").format(
                root=directory, endpoint=endpoint)
    with path.open("x", encoding="utf-8") as output:
        output.write(text)
    path.chmod(0o600)


def resource_observation(control, owner, label, enabled, rows):
    control.deadline.check()
    if not enabled:
        row = {"label": label, "status": "not-collected", "sample": None,
               "reason": "no owned-PID resource profile selected; no waitpid/rusage inference"}
    else:
        try:
            # Imported only after explicit runtime approval. This collector never
            # polls/waits/reaps and receives the actual still-owned Popen object.
            from statistics_resources import sample
            value = sample(owner.process).as_dict()
            row = {"label": label, "status": value["status"], "sample": value}
        except Exception as error:
            reason = getattr(error, "reason", None)
            row = {"label": label, "status": "unavailable", "sample": None,
                   "error": described(error),
                   "reason": asdict(reason) if is_dataclass(reason) else None}
    # Keep the actual observation/error even when the original hard elapsed
    # during a synchronous OS sample. Never start the next operation afterward.
    rows.append(row)
    control.deadline.check()


def one(control, inputs, implementation, config, value, operation, warmup, rows):
    argv = [inputs.snapshots["c_cli"]["path"], "-c", str(config), "-L", "ERROR",
            "-s", SUBSYSTEM, "-n", NAME]
    if operation == "get":
        argv.append("-q")
    else:
        argv.append(str(value))  # no -p, relative flag or hand-written frame
    row = {"implementation": implementation, "operation": operation,
           "value": value, "warmup": warmup, "status": "started"}
    rows.append(row)
    start = time.perf_counter_ns()
    first = len(control.children)
    try:
        raw = control.command(implementation + "-" + operation + "-" + str(value),
                              argv, inputs.selected_environment,
                              seconds=inputs.operation_seconds)
        if operation == "get" and raw.strip() != str(value).encode("ascii"):
            raise ObservationError("real C GET did not return the exact preceding SET value")
        row["status"] = "completed"
    except BaseException as error:
        row["status"] = "failed"
        row["error"] = described(error)
        raise
    finally:
        row["cli_lifecycle_ns"] = time.perf_counter_ns() - start
        if len(control.children) > first:
            row["owner_id"] = control.children[first].row["id"]


def summarize(rows, resources):
    result = {}
    for implementation in ("c", "rust"):
        result[implementation] = {}
        for operation in ("set", "get"):
            values = sorted(row["cli_lifecycle_ns"] for row in rows
                            if row["implementation"] == implementation
                            and row["operation"] == operation and not row["warmup"]
                            and row["status"] == "completed")
            result[implementation][operation] = {
                "completed": len(values), "minimum_ns": min(values) if values else None,
                "nearest_rank_p50_ns": values[(50 * len(values) + 99) // 100 - 1] if values else None,
                "nearest_rank_p95_ns": values[(95 * len(values) + 99) // 100 - 1] if values else None,
                "maximum_ns": max(values) if values else None,
                "serial_cli_lifecycle_operations_per_second": len(values) * 1e9 / sum(values) if values and sum(values) else None}
        observations = [row["sample"] for row in resources[implementation] if row["sample"]]
        cpu_delta = None
        if len(observations) >= 2:
            a, b = observations[0], observations[-1]
            identity = (a.get("pid"), a.get("process_start_marker"), a.get("process_start_marker_unit"), a.get("platform"), a.get("source"))
            if (identity[1] is not None and identity[2] is not None
                    and identity == (b.get("pid"), b.get("process_start_marker"), b.get("process_start_marker_unit"), b.get("platform"), b.get("source"))
                    and type(a.get("completed_monotonic_ns")) is int
                    and type(b.get("observed_monotonic_ns")) is int
                    and b["observed_monotonic_ns"] >= a["completed_monotonic_ns"]
                    and not a.get("process_exited_observed") and not b.get("process_exited_observed")
                    and all(type(v.get(k)) is int for v in (a, b) for k in ("cpu_user_ns", "cpu_system_ns"))
                    and b["cpu_user_ns"] >= a["cpu_user_ns"] and b["cpu_system_ns"] >= a["cpu_system_ns"]):
                cpu_delta = {"user_ns": b["cpu_user_ns"] - a["cpu_user_ns"],
                             "system_ns": b["cpu_system_ns"] - a["cpu_system_ns"],
                             "scope": "between actual same-owned-process snapshots, not consuming-exit totals"}
        rss = [s["rss_current_bytes"] for s in observations if type(s.get("rss_current_bytes")) is int]
        peak = [s["rss_peak_bytes"] for s in observations if type(s.get("rss_peak_bytes")) is int]
        result[implementation]["resources"] = {
            "cpu_snapshot_delta": cpu_delta,
            "max_observed_sampled_rss_bytes": max(rss) if rss else None,
            "os_reported_lifetime_rss_peak_bytes": max(peak) if peak else None,
            "qualification": "Unsupported/failed fields remain null. Sample maximum is not OS peakRSS; OS lifetime high-water is not benchmark-phase peak. No RUSAGE_CHILDREN or post-waitpid estimate."}
    return result


def stop_service(control, owner):
    deadline = Deadline(10, control.deadline)
    owner.allow_exit = True
    control.signal(owner, signal.SIGTERM)
    control.wait(lambda: owner.process.poll(), deadline, "actual normal service SIGTERM exit")
    while owner.open_readers:
        deadline.check()
        control.pump(min(0.01, deadline.remaining()))
    code = owner.process.wait(timeout=0)
    owner.row.update(exit_code=code, reaped=True, intentional_stop="sigterm")
    control.finalize(owner)
    if code != 0:
        raise ObservationError("normal service did not exit0 on its actual SIGTERM: " + str(code))


def run(args):
    result = {"schema": 1, "profile": PROFILE, "status": "blocked",
              "runtime_verified": False, "whole_goal_complete": False,
              "whole_node_performance_verified": False, "operations": [],
              "resource_observations": {"c": [], "rust": []}, "cleanup": []}
    control, inputs, runtime = None, None, {"path": None, "identity": None}
    evidence = Path(args.output)
    evidence_owned = False
    previous = {}

    def interrupted(signum, _frame):
        if control is not None and not control.active:
            control.cleanup_signal(signum)
            return
        raise BenchmarkInterrupted("normal benchmark interrupted by signal " + str(signum))

    try:
        manifest = load_json(args.manifest)
        result["authorization"] = approval(args.manifest, args.approval, manifest)
        inputs = Inputs(manifest)
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise Blocked("exclusive ordinary consuming wait ownership requires default SIGCHLD; ignore/custom reapers are refused")
        if not evidence.is_absolute() or evidence.exists():
            raise Blocked("output must be a fresh absolute evidence directory")
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        control = BenchmarkController(evidence, inputs.seconds, 65536, 8 << 20, 128)
        # Alias the original bounded list. A late cleanup signal must remain
        # visible through final hashing, handler restoration and classification.
        result["cleanup"] = control.cleanup_errors
        metadata = Owner(0, "private-runtime", "metadata", [])

        def allocate_evidence():
            nonlocal evidence_owned
            evidence.mkdir(mode=0o700)
            evidence_owned = True
        control.acquire(metadata, allocate_evidence)
        inputs.snapshot(evidence / "binaries")
        result["participants"] = inputs.snapshots
        result["input_bindings"] = inputs.bindings

        def allocate_runtime():
            runtime["path"] = Path(tempfile.mkdtemp(prefix="gsb-"))
            runtime["path"].chmod(0o700)
            st = runtime["path"].lstat()
            runtime["identity"] = (st.st_dev, st.st_ino)
        control.acquire(metadata, allocate_runtime)
        root = runtime["path"]
        result["owned_runtime"] = str(root)
        empty_defaults = root / "defaults"
        empty_defaults.mkdir(mode=0o700)
        inputs.selected_environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
            "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_DATA_HOME": str(root),
            "XDG_RUNTIME_DIR": str(root), "GNUNET_BASE_CONFIG": str(empty_defaults),
            **inputs.environment}
        configs, services = {}, {}
        for implementation in ("c", "rust"):
            directory = root / implementation
            directory.mkdir(mode=0o700)
            endpoint = directory / "statistics.sock"
            config = directory / "node.conf"
            configuration(config, endpoint, directory)
            configs[implementation] = config
            shutil.copyfile(config, evidence / (implementation + "-node.conf"))
            executable = inputs.snapshots[implementation + "_service"]["path"]
            startup = Deadline(inputs.operation_seconds, control.deadline)
            service = control.start(implementation + "-service", [executable, "-c", str(config), "-L", "ERROR"],
                                    inputs.selected_environment, role="service", deadline=startup)
            services[implementation] = service
            if implementation == "rust":
                control.observed(service, b"READY statistics wire=0.29.1 persistence=memory-only authentication=kernel-unix",
                                 startup)
            control.wait(lambda: True if endpoint.is_socket() else None,
                         startup, "normal private Unix bind")
        for i in range(inputs.warmup + inputs.samples):
            warmup = i < inputs.warmup
            if i == inputs.warmup:
                for implementation in ("c", "rust"):
                    resource_observation(control, services[implementation], "baseline",
                                         inputs.resources == "owned-pid-snapshot",
                                         result["resource_observations"][implementation])
                result["measured_window_start_monotonic_ns"] = time.monotonic_ns()
            for implementation in (("c", "rust") if i % 2 == 0 else ("rust", "c")):
                for operation in ("set", "get"):
                    one(control, inputs, implementation, configs[implementation], i + 1,
                        operation, warmup, result["operations"])
                if not warmup:
                    resource_observation(control, services[implementation], "after-get-" + str(i + 1),
                                         inputs.resources == "owned-pid-snapshot",
                                         result["resource_observations"][implementation])
        result["measured_window_end_monotonic_ns"] = time.monotonic_ns()
        result["summary"] = summarize(result["operations"], result["resource_observations"])
        result["measurement"] = {"latency": "entire normal C CLI lifecycle: owned launch, IPC, exit, output drain/hash and observer overhead",
            "observer_max_wait_seconds": 0.001, "warmup_per_backend": inputs.warmup,
            "measured_SET_per_backend": inputs.samples, "measured_GET_per_backend": inputs.samples,
            "configuration": "private Unix, same UID/GID, memory-only, nonpersistent absolute SET",
            "service_only_latency": None, "service_capacity_throughput": None,
            "paired_harness_commands_per_second": 4 * inputs.samples * 1e9 / (
                result["measured_window_end_monotonic_ns"] - result["measured_window_start_monotonic_ns"]),
            "qualification": "Interleaved backend order alternates. Includes CLI startup and capture/orchestration/resource observer work. This is a component baseline, not pure service or whole-node performance."}
        for implementation in ("c", "rust"):
            stop_service(control, services[implementation])
        result["status"] = "selected-normal-component-measurements-completed"
    except BaseException as error:
        result["status"] = "blocked" if isinstance(error, Blocked) else "failed"
        result["error"] = described(error)
    finally:
        if control is not None:
            # Same registered handlers record bounded cleanup intent rather
            # than raising out of another owner's actual physical retirement.
            control.active = False
            try:
                control.cleanup(10)
            except BaseException as error:
                control.cleanup_error(None, "controller-cleanup", error)
            result["children"] = control.reports()
            if control.cleanup_overflow:
                result["cleanup"].append({"stage": "cleanup-error-bound", "overflow": True})
        try:
            if inputs is not None:
                inputs.recheck()
                result["named_inputs_unchanged"] = True
        except BaseException as error:
            result["named_inputs_unchanged"] = False
            result["cleanup"].append({"stage": "input-recheck", "error": described(error)})
        children = result.get("children", [])
        drained = all(row.get("reaped") and row.get("capture_drained") and row.get("parent_resources_closed")
                      for row in children if row.get("spawned"))
        result["all_owned_children_reaped_and_captured"] = drained
        result["owned_runtime_removed"] = False
        if runtime["path"] is not None and drained and not result["cleanup"]:
            try:
                st = runtime["path"].lstat()
                if (st.st_dev, st.st_ino) != runtime["identity"] or runtime["path"].is_symlink():
                    raise ObservationError("original owned runtime directory identity changed")
                shutil.rmtree(runtime["path"])
                result["owned_runtime_removed"] = True
            except BaseException as error:
                result["cleanup"].append({"stage": "runtime-remove", "error": described(error)})
        if result["cleanup"] or not drained:
            result["status"] = "failed"
        result["runtime_verified"] = result["status"] == "selected-normal-component-measurements-completed"
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                result["cleanup"].append({"stage": "restore-controller-handler",
                                          "signal": int(signum), "error": described(error)})
                result["status"] = "failed"
                result["runtime_verified"] = False
        # The original handler stays active through all cleanup/hash work.
        # After restoration, signals follow their original semantics rather
        # than appending an unobserved callback after the final success check.
        if result["cleanup"]:
            result["status"] = "failed"
            result["runtime_verified"] = False
        if evidence_owned:
            try:
                with (evidence / "result.json").open("x", encoding="utf-8") as output:
                    json.dump(result, output, indent=2, sort_keys=True)
                    output.write("\n")
            except BaseException as error:
                print(json.dumps({"stage": "benchmark-result-write", "error": described(error),
                                  "original": result.get("error"), "cleanup": result["cleanup"]}), file=sys.stderr)
                return 1
        if not result["runtime_verified"]:
            print(json.dumps({"status": result["status"], "error": result.get("error"), "cleanup": result["cleanup"]}), file=sys.stderr)
    return 0 if result["runtime_verified"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--output", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
