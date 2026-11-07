#!/usr/bin/env python3
"""Run pinned official protocol-component and independent primitive checks.

This suite does not run a complete C daemon or test P2P peer interoperation.
Every run uses a new evidence directory. Fixture generators run in verification
mode; only the wire oracle generates fresh data into the evidence directory.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time
import unittest

REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIRS = ("crates", "adapters", "apps", "tools", "tests", ".cargo", ".github")
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "ARCHITECTURE.md", "README.md", "rustfmt.toml")
IGNORED_DIRS = {"target", ".git", "__pycache__"}
FINGERPRINT_ALGORITHM = "xtask-inputs-v1: sorted UTF-8 relative paths; fold SHA256(previous32 || path_length_BE64 || path_UTF8 || data_length_BE64 || data), initial32=zero"
UPSTREAM_INPUTS = (
    "src/include/gnunet_common.h", "src/include/gnunet_crypto_lib.h",
    "src/include/gnunet_time_lib.h", "src/include/gnunet_dht_service.h",
    "src/service/dht/dht.h", "src/service/dht/gnunet-service-dht_neighbours.c",
    "src/include/gnunet_protocols.h", "src/lib/gnsrecord/gnsrecord_serialization.c",
    "src/lib/util/strings.c", "src/include/gnu_name_system_record_types.h",
    "src/include/gnunet_gnsrecord_lib.h", "src/lib/hello/hello-uri.c",
    "src/include/gnunet_signatures.h", "src/lib/util/crypto_ecc.c",
    "src/service/statistics/statistics.h", "src/service/statistics/gnunet-service-statistics.c",
    "src/include/gnunet_container_lib.h",
)
GNS_NAMES = {"a", "txt", "pkey_first", "edkey", "edkey_second", "empty", "pkey_zone", "edkey_zone"}
HELLO_NAMES = {"hello_block", "hello_dht", "hello_message", "hello_empty", "hello_signed_payload"}
WIRE_NAMES = {"dht-get.bin", "dht-put.bin", "dht-put-tracked.bin", "dht-result-tracked.bin", "signature-purpose.bin", "message-registry.tsv"}
STATISTICS_NAMES = {"get", "set", "get-no-end", "get-truncated", "set-wrong-confirm", "get-deadline"}
REQUIRED_STEPS = {"wire", "gnsrecord", "hello", "crypto", "statistics", "statistics-core"}
SERVICE_TRACE_TEST = "matches_original_c_service_handlers_and_both_c_arithmetic_profiles"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


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


def source_inputs(source):
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=15).strip()
    if revision != REVISION:
        raise ValueError("reference checkout does not match pinned upstream revision")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", *UPSTREAM_INPUTS], check=True, timeout=15)
    return {"revision": revision, "files": [{"path": name, "sha256": digest((source / name).read_bytes())} for name in sorted(UPSTREAM_INPUTS)]}


def compare_vectors(expected, generated):
    def data_files(directory):
        return {path.name: path for path in directory.iterdir() if path.is_file() and path.suffix in {".bin", ".tsv"}}
    left, right = data_files(expected), data_files(generated)
    if not left or left.keys() != right.keys():
        raise ValueError("missing, extra or empty wire data fixture set")
    rows = []
    for name in sorted(left):
        data = left[name].read_bytes()
        if not data or data != right[name].read_bytes():
            raise ValueError("empty or different wire data fixture: " + name)
        rows.append({"path": name, "bytes": len(data), "sha256": digest(data)})
    return rows


def compare_c_rows(output, expected_names, fixture):
    rows = {}
    for line in output.decode("ascii").splitlines():
        name, separator, hexadecimal = line.partition(" ")
        if not separator or name not in expected_names or name in rows or re.fullmatch(r"[0-9a-f]*", hexadecimal) is None:
            raise ValueError("unexpected, duplicate or malformed C fixture row")
        data = bytes.fromhex(hexadecimal)
        if not data and name != "empty":
            raise ValueError("unexpected empty C fixture")
        if (fixture / (name + ".bin")).read_bytes() != data:
            raise ValueError("different C fixture: " + name)
        rows[name] = {"path": name + ".bin", "bytes": len(data), "sha256": digest(data)}
    if rows.keys() != expected_names:
        raise ValueError("actual C oracle emitted no or incomplete fixture checks")
    return [rows[name] for name in sorted(rows)]


def capture_original(script, source, output):
    """Execute the original script while retaining actual check_output results.

    Some scripts print a fixed success count. Capturing their executed C
    oracle's output lets the parent independently count and compare real rows.
    """
    original = subprocess.check_output
    trace = []

    def captured(*args, **kwargs):
        argv = args[0] if args else kwargs["args"]
        row = {"argv": [str(arg) for arg in argv]}
        if row["argv"][:2] == ["openssl", "pkeyutl"] and "-in" in row["argv"]:
            input_path = Path(row["argv"][row["argv"].index("-in") + 1])
            row["input_base64"] = base64.b64encode(input_path.read_bytes()).decode()
        try:
            result = original(*args, **kwargs)
            data = result.encode() if isinstance(result, str) else result
            row.update(exit_code=0, stdout_base64=base64.b64encode(data).decode(), stdout_sha256=digest(data))
            return result
        except subprocess.CalledProcessError as error:
            row["exit_code"] = error.returncode
            raise
        finally:
            trace.append(row)

    subprocess.check_output = captured
    sys.argv = [str(script), "--source", str(source)]
    try:
        runpy.run_path(str(script), run_name="__main__")
    finally:
        subprocess.check_output = original
        save(output, {"schema": 1, "calls": trace})


def run_command(output, name, argv, timeout=180, env=None):
    stdout, stderr = output / (name + ".stdout.txt"), output / (name + ".stderr.txt")
    row = {"name": name, "argv": [str(arg) for arg in argv], "executed_checks": 0, "passed": False,
           "output_path": stdout.name, "stderr_path": stderr.name}
    started = time.monotonic()
    child = None
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            child = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=err, stdin=subprocess.DEVNULL, start_new_session=True, env=env)
            row["exit_code"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the isolated process group, including a compiler/C endpoint.
            import signal
            os.killpg(child.pid, signal.SIGKILL)
            row.update(exit_code=child.wait(timeout=5), timed_out=True)
        except OSError as error:
            row.update(exit_code=None, failure=str(error))
    row.update(elapsed_seconds=round(time.monotonic() - started, 6), output_sha256=digest(stdout.read_bytes()), stderr_sha256=digest(stderr.read_bytes()))
    return row


def require_command(row):
    if row.get("exit_code") != 0 or row.get("timed_out"):
        raise ValueError("subcommand did not succeed: " + row["name"])


def oracle_calls(output, row):
    require_command(row)
    trace = json.loads((output / (row["name"] + ".trace.json")).read_text())
    calls = trace.get("calls", [])
    if trace.get("schema") != 1 or not calls or any(call.get("exit_code") != 0 for call in calls):
        raise ValueError("empty or unsuccessful actual oracle call trace")
    for call in calls:
        data = base64.b64decode(call["stdout_base64"], validate=True)
        if digest(data) != call["stdout_sha256"]:
            raise ValueError("actual oracle output hash differs")
    return calls


def c_oracle_data(calls):
    data = [base64.b64decode(call["stdout_base64"], validate=True) for call in calls
            if len(call["argv"]) == 1 and Path(call["argv"][0]).name == "oracle"]
    if len(data) != 1 or not data[0]:
        raise ValueError("actual C oracle output is missing or empty")
    return data[0]


def c_service_traces(calls):
    data = [base64.b64decode(call["stdout_base64"], validate=True) for call in calls
            if len(call["argv"]) == 1 and Path(call["argv"][0]).name == "oracle"]
    if len(data) != 2 or any(not trace for trace in data):
        raise ValueError("both actual C service compiler-profile traces are required")
    return data


def compare_service_trace(actual, fixture):
    """Count actual action/response rows only after exact C/Rust trace comparison."""
    expected = fixture.read_bytes()
    if not actual or not expected or not actual.endswith(b"\n") or actual != expected:
        raise ValueError("empty, incomplete or different service behavior trace")
    rows, kinds = [], set()
    for number, line in enumerate(actual.decode("ascii").splitlines(), 1):
        fields = line.split(" ")
        kind = fields[0]
        if kind == "set" and len(fields) == 5:
            limits = (1 << 31, 1 << 64, 2, 2)
            valid = all(re.fullmatch(r"[0-9]+", value) and int(value) < limit
                        for value, limit in zip(fields[1:], limits))
        elif kind == "watch" and len(fields) == 3:
            valid = all(re.fullmatch(r"[0-9]+", value) and int(value) < (1 << 32)
                        for value in fields[1:])
        elif kind == "disconnect" and len(fields) == 2:
            valid = re.fullmatch(r"[0-9]+", fields[1]) and int(fields[1]) < (1 << 32)
        elif kind == "message" and len(fields) == 3:
            valid = re.fullmatch(r"[0-9]+", fields[1]) and int(fields[1]) < (1 << 32)
            valid = valid and re.fullmatch(r"(?:[0-9a-f]{2})+", fields[2]) is not None
            if valid:
                frame = bytes.fromhex(fields[2])
                valid = len(frame) >= 4 and len(frame) == int.from_bytes(frame[:2], "big")
                code = int.from_bytes(frame[2:4], "big")
                if code == 170:
                    names = frame[16:].split(b"\0")
                    valid = valid and len(frame) >= 18 and len(names) == 3 and names[-1] == b""
                elif code == 173:
                    valid = valid and len(frame) == 24 and frame[12:16] == bytes(4)
                else:
                    valid = valid and code in {171, 175} and len(frame) == 4
        else:
            valid = False
        if not valid:
            raise ValueError("malformed service behavior trace row " + str(number))
        kinds.add(kind)
        data = line.encode("ascii")
        rows.append({"line": number, "kind": kind, "bytes": len(data), "sha256": digest(data)})
    if kinds != {"set", "watch", "disconnect", "message"}:
        raise ValueError("service behavior trace lacks required executed action/response kinds")
    return rows


def statistics_core_checks(output, row):
    fixture = ROOT / "crates/gnunet-statistics/tests/fixtures/service_trace.txt"
    traces = c_service_traces(oracle_calls(output, row))
    comparisons = []
    for profile, trace in zip(("c-optimized", "c-wrapping"), traces):
        rows = compare_service_trace(trace, fixture)
        path = output / (row["name"] + "." + profile + ".trace.txt")
        path.write_bytes(trace)
        comparisons.append({"implementation": profile, "trace_path": path.name,
                            "trace_sha256": digest(trace), "rows": rows})
    rust_trace = output / (row["name"] + ".rust.trace.txt")
    env = os.environ.copy()
    env["GNUNET_STATISTICS_TRACE"] = str(rust_trace)
    rust = run_command(output, "statistics-core-rust", ["cargo", "test", "--locked", "-p", "gnunet-statistics",
                       "--test", "service", SERVICE_TRACE_TEST, "--", "--exact"], env=env)
    row["rust_comparison"] = rust
    require_command(rust)
    # A filtered-out or skipped test cannot be replaced with an old trace file:
    # the evidence directory is new and the actual test name must have run.
    stdout = (output / rust["output_path"]).read_text()
    if re.search(r"^test " + re.escape(SERVICE_TRACE_TEST) + r" \.\.\. ok$", stdout, re.M) is None:
        raise ValueError("required Rust service trace test did not execute successfully")
    trace = rust_trace.read_bytes()
    rows = compare_service_trace(trace, fixture)
    rust.update(passed=True, executed_checks=len(rows))
    comparisons.append({"implementation": "rust", "trace_path": rust_trace.name,
                        "trace_sha256": digest(trace), "rows": rows})
    row["comparisons"] = comparisons
    row["reference_implementation"] = "Original C service handlers with allocation/scheduler/MQ shim; optimized C, wrapping C and actual Rust state-machine trace"
    return sum(len(comparison["rows"]) for comparison in comparisons)


def crypto_rows(calls, fixture):
    public = [call for call in calls if call["argv"][:2] == ["openssl", "pkey"] and "-pubout" in call["argv"]]
    signed = [call for call in calls if call["argv"][:2] == ["openssl", "pkeyutl"] and "-sign" in call["argv"]]
    verified = [call for call in calls if call["argv"][:2] == ["openssl", "pkeyutl"] and "-verify" in call["argv"]]
    if len(public) != 1 or len(signed) != 1 or len(verified) != 1:
        raise ValueError("actual OpenSSL public/sign/verify operations are incomplete")
    public_der = base64.b64decode(public[0]["stdout_base64"], validate=True)
    if len(public_der) != 44 or public_der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ValueError("unexpected actual OpenSSL public key representation")
    region = base64.b64decode(signed[0]["input_base64"], validate=True)
    if len(region) != 80 or region != base64.b64decode(verified[0]["input_base64"], validate=True):
        raise ValueError("signed and verified purpose regions differ or are empty")
    values = {"peer-public.bin": public_der[12:], "peer-purpose.bin": region,
              "peer-purpose.sig": base64.b64decode(signed[0]["stdout_base64"], validate=True)}
    if len(values["peer-purpose.sig"]) != 64:
        raise ValueError("unexpected actual OpenSSL signature size")
    for name, data in values.items():
        if (fixture / name).read_bytes() != data:
            raise ValueError("actual OpenSSL fixture differs: " + name)
    return [{"path": name, "bytes": len(data), "sha256": digest(data)} for name, data in sorted(values.items())]


def statistics_checks(path, binary_sha256):
    report = json.loads(path.read_text())
    cases = report.get("cases", [])
    if report.get("status") != "passed" or report.get("full_c_daemon") is not False or report.get("p2p_peer_interoperation") is not False:
        raise ValueError("statistics component report failed or has wrong scope")
    if report.get("case_count") != 6 or len(cases) != 6 or {case["case"] for case in cases} != STATISTICS_NAMES:
        raise ValueError("statistics component has no or incomplete executed cases")
    for case in cases:
        expected = 0 if case["case"] in {"get", "set"} else 1
        if case.get("passed") is not True or case.get("c_exit_code") != 0 or case.get("rust_exit_code") != expected or case.get("socket_removed") is not True or case.get("c_reference_validator_checks") != 4:
            raise ValueError("statistics component case lacks actual success/failure/cleanup evidence")
    if report["rust"]["sha256"] != binary_sha256 or report["rust"].get("snapshot_unchanged") is not True or report["upstream"].get("inputs_unchanged") is not True or report["upstream"]["revision"] != REVISION:
        raise ValueError("statistics component inputs changed or are not bound to this run")
    return len(cases)


def run_suite(source, binary, output):
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "kind": "official-reference-components", "status": "failed", "commands": [],
              "full_c_daemon": False, "p2p_peer_interoperation": False,
              "scope": "Official C protocol components and STATISTICS business handlers, actual Rust STATISTICS state-machine traces and independent OpenSSL primitive vectors; no complete C daemon, scheduler, database durability or P2P peer interoperation.",
              "check_unit": "data fixture comparisons, real statistics IPC cases and actual service action/response trace rows per C/Rust implementation; registry assignments and C validator self-checks are reported separately"}
    try:
        before = fingerprints(ROOT)
        report["input_fingerprints"] = before
        report["upstream"] = source_inputs(source)
        binary_data = binary.read_bytes()
        snapshot = output / "gnunet-cli.snapshot"
        snapshot.write_bytes(binary_data)
        snapshot.chmod(0o700)
        report["binary"] = {"path": str(binary), "sha256": digest(binary_data), "snapshot": snapshot.name}
        scripts = {
            "wire": ROOT / "crates/gnunet-wire/tests/official_c_oracle.py",
            "gnsrecord": ROOT / "crates/gnunet-gnsrecord/tests/upstream_oracle.py",
            "hello": ROOT / "crates/gnunet-wire/tests/official_hello_oracle.py",
            "crypto": ROOT / "crates/gnunet-crypto/tests/official_eddsa_oracle.py",
            "statistics": ROOT / "tools/interop/statistics_c_peer.py",
            "statistics-core": ROOT / "crates/gnunet-statistics/tests/upstream_oracle.py",
        }
        for name, script in scripts.items():
            if not script.is_file():
                raise ValueError("required reference script is missing: " + str(script))
            if name == "wire":
                argv = [sys.executable, "-B", str(script), "--upstream", str(source), "--output", str(output / "wire")]
            elif name == "statistics":
                argv = [sys.executable, "-B", str(script), "--source", str(source), "--binary", str(snapshot), "--output", str(output / "statistics")]
            else:
                argv = [sys.executable, "-B", str(Path(__file__).resolve()), "--capture-oracle", str(script), str(source), str(output / (name + ".trace.json"))]
            row = run_command(output, name, argv)
            report["commands"].append(row)
            require_command(row)
            if name == "wire":
                rows = compare_vectors(ROOT / "crates/gnunet-wire/tests/official_vectors", output / "wire")
                if {item["path"] for item in rows} != WIRE_NAMES:
                    raise ValueError("official wire data set differs from the required six vectors")
                registry = (output / "wire/message-registry.tsv").read_text().splitlines()
                if len(registry) != 677 or len(set(registry)) != 677:
                    raise ValueError("official registry has missing or duplicate actual assignments")
                row["registry_assignments"] = len(registry)
                row["comparisons"] = rows
                row["executed_checks"] = len(rows)
            elif name in {"gnsrecord", "hello"}:
                names = GNS_NAMES if name == "gnsrecord" else HELLO_NAMES
                fixture = ROOT / ("crates/gnunet-gnsrecord/tests/fixtures" if name == "gnsrecord" else "crates/gnunet-wire/tests/fixtures")
                row["comparisons"] = compare_c_rows(c_oracle_data(oracle_calls(output, row)), names, fixture)
                row["executed_checks"] = len(row["comparisons"])
            elif name == "crypto":
                row["comparisons"] = crypto_rows(oracle_calls(output, row), ROOT / "crates/gnunet-crypto/tests/fixtures")
                row["executed_checks"] = len(row["comparisons"])
                row["reference_implementation"] = "OpenSSL ordinary Ed25519, not the complete GNUnet C crypto library"
            elif name == "statistics":
                row["executed_checks"] = statistics_checks(output / "statistics/result.json", report["binary"]["sha256"])
                row["c_validator_self_checks"] = 24
                row["evidence_path"] = "statistics/result.json"
            else:
                row["executed_checks"] = statistics_core_checks(output, row)
            if not row["executed_checks"]:
                raise ValueError("reference command performed zero checks")
            row["passed"] = True
        report["source_unchanged"] = fingerprints(ROOT) == before
        report["upstream_unchanged"] = source_inputs(source) == report["upstream"]
        report["binary_unchanged"] = digest(binary.read_bytes()) == digest(snapshot.read_bytes()) == report["binary"]["sha256"]
        report["executed_checks"] = sum(row["executed_checks"] for row in report["commands"])
        if not report["source_unchanged"] or not report["upstream_unchanged"] or not report["binary_unchanged"] or {row["name"] for row in report["commands"]} != REQUIRED_STEPS or len(report["commands"]) != len(REQUIRED_STEPS) or any(not row["executed_checks"] or not row["passed"] for row in report["commands"]):
            raise ValueError("reference inputs changed or required real checks are incomplete")
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        report["executed_checks"] = sum(row["executed_checks"] for row in report["commands"])
        save(output / "result.json", report)
    print(json.dumps({"status": report["status"], "executed_checks": report["executed_checks"], "evidence": str(output / "result.json")}))
    return 0 if report["status"] == "passed" else 1


class BoundaryTests(unittest.TestCase):
    def test_data_comparison_ignores_only_provenance(self):
        with tempfile.TemporaryDirectory() as work:
            left, right = Path(work) / "a", Path(work) / "b"
            left.mkdir(); right.mkdir()
            for directory in (left, right):
                (directory / "x.bin").write_bytes(b"\0\4\0\1")
                (directory / "registry.tsv").write_bytes(b"A\t1\n")
            (left / "provenance.json").write_text("left")
            (right / "provenance.json").write_text("right")
            self.assertEqual(len(compare_vectors(left, right)), 2)

    def test_missing_extra_empty_and_different_vectors_fail(self):
        with tempfile.TemporaryDirectory() as work:
            left, right = Path(work) / "a", Path(work) / "b"
            left.mkdir(); right.mkdir()
            for a, b in ((None, None), (b"a", None), (b"a", b"b"), (b"", b"")):
                for directory, data in ((left, a), (right, b)):
                    path = directory / "x.bin"
                    if path.exists(): path.unlink()
                    if data is not None: path.write_bytes(data)
                with self.assertRaises(ValueError): compare_vectors(left, right)

    def test_actual_c_rows_count_and_empty_record(self):
        with tempfile.TemporaryDirectory() as work:
            fixture = Path(work)
            (fixture / "a.bin").write_bytes(b"\x01")
            (fixture / "empty.bin").write_bytes(b"")
            self.assertEqual(len(compare_c_rows(b"a 01\nempty \n", {"a", "empty"}, fixture)), 2)
            for data in (b"", b"a 01\n", b"a 01\na 01\n", b"a zz\n", b"unknown 01\n"):
                with self.assertRaises(ValueError): compare_c_rows(data, {"a", "empty"}, fixture)

    def test_fixed_success_text_cannot_replace_real_c_output(self):
        for calls in ([], [{"argv": ["oracle"], "stdout_base64": ""}], [{"argv": ["echo"], "stdout_base64": base64.b64encode(b"8 fixtures matched").decode()}]):
            with self.assertRaises(ValueError): c_oracle_data(calls)

    def test_service_trace_requires_real_complete_c_and_rust_rows(self):
        with tempfile.TemporaryDirectory() as work:
            fixture = Path(work) / "trace.txt"
            complete = b"watch 0 0\nset 0 7 1 0\nmessage 0 000400ab\ndisconnect 0\n"
            fixture.write_bytes(complete)
            self.assertEqual(len(compare_service_trace(complete, fixture)), 4)
            for trace in (b"", b"68 checks passed\n", complete[:-1], complete.replace(b"000400ab", b"000500ab")):
                with self.assertRaises(ValueError): compare_service_trace(trace, fixture)
            fixture.write_bytes(b"")
            with self.assertRaises(ValueError): compare_service_trace(b"", fixture)
            for calls in ([], [{"argv": ["oracle"], "stdout_base64": ""}] * 2,
                          [{"argv": ["oracle"], "stdout_base64": base64.b64encode(complete).decode()}]):
                with self.assertRaises(ValueError): c_service_traces(calls)

    def test_fingerprint_matches_documented_fold(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "a").write_bytes(b"abc")
            result, rows = fingerprint_files(root, [root / "a"])
            expected = hashlib.sha256(bytes(32) + (1).to_bytes(8, "big") + b"a" + (3).to_bytes(8, "big") + b"abc").hexdigest()
            self.assertEqual(result, expected)
            self.assertEqual(rows[0]["sha256"], digest(b"abc"))
            (root / "a").write_bytes(b"abd")
            self.assertNotEqual(fingerprint_files(root, [root / "a"])[0], result)

    def test_command_failure_and_timeout_never_claim_checks(self):
        with tempfile.TemporaryDirectory() as work:
            output = Path(work)
            failed = run_command(output, "failed", [sys.executable, "-c", "raise SystemExit(7)"])
            timed_out = run_command(output, "timeout", [sys.executable, "-c", "import time; time.sleep(5)"], .05)
            self.assertEqual(failed["exit_code"], 7)
            self.assertTrue(timed_out["timed_out"])
            for row in (failed, timed_out):
                self.assertEqual(row["executed_checks"], 0)
                with self.assertRaises(ValueError): require_command(row)

    def test_empty_statistics_report_fails(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "result.json"
            save(path, {"status": "passed", "cases": [], "case_count": 0, "full_c_daemon": False, "p2p_peer_interoperation": False})
            with self.assertRaises(ValueError): statistics_checks(path, "0" * 64)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--capture-oracle":
        capture_original(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true", help="run isolated structural regression tests, no C checkout or sockets")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
        print(json.dumps({"status": "passed" if result.wasSuccessful() and result.testsRun else "failed", "executed_checks": result.testsRun}))
        return 0 if result.wasSuccessful() and result.testsRun else 1
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required unless --self-test is used")
    return run_suite(args.source.resolve(), args.binary.resolve(), args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
