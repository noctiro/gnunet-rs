#!/usr/bin/env python3
"""Execute and seal the reviewed HELLO owner proof, rejecting stale adjudication.

Always runs fresh real C/Rust comparisons. A component receipt cannot simply be
relabeled with a new source/requirements digest. Updating the reviewed acceptance
map after a normative change requires a separate operation-by-operation review.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "tools/reference/hello_acceptance.json"
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def local(path):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    relative = path.relative_to(ROOT)
    if ".." in relative.parts:
        raise ValueError("nonlocal proof path")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("proof paths cannot be symbolic links")
    return path


def relative(path):
    return local(path).relative_to(ROOT).as_posix()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def inputs():
    spec = importlib.util.spec_from_file_location("owner_inputs", ROOT / "tools/interop/run_reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fingerprints(ROOT)


def validate_bindings(rows, expected, checks, tests):
    """Every adjudicated obligation must have present, actually passed witnesses."""
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != set(expected):
        raise ValueError("reviewed obligations differ from current required criteria")
    for row in rows:
        if not row.get("obligation") or not row.get("adjudication"):
            raise ValueError("missing feature/ownership adjudication")
        if not row.get("c_rust_checks") or not row.get("rust_tests"):
            raise ValueError("criterion lacks concrete C and Rust witnesses")
        if any(name not in checks for name in row["c_rust_checks"]):
            raise ValueError("unexecuted C/Rust comparison witness")
        if any(name not in tests for name in row["rust_tests"]):
            raise ValueError("unexecuted Rust test witness")


def run(args):
    output = local(args.output)
    output.mkdir(parents=True, exist_ok=False)
    args.created_output = output
    before = inputs()
    save(output / "inputs-before.json", before)
    reviewed = json.loads(MAP.read_text())
    ledger_path = ROOT / "spec/gnunet/conformance.json"
    ledger = json.loads(ledger_path.read_text())
    owner = next(row for row in ledger["foundations"] if row["id"] == "hello")
    preconditions = []

    def execute(name, argv, cwd=ROOT):
        completed = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True, text=True,
                                   timeout=1200)
        log = output / (name + ".log")
        log.write_text(completed.stdout + "\n" + completed.stderr)
        entry = {"argv": list(map(str, argv)), "exit_code": completed.returncode,
                 "output_path": relative(log), "output_sha256": sha(log)}
        preconditions.append(entry)
        if completed.returncode != 0:
            raise ValueError(name + " failed; see " + str(log))
        return completed, entry

    identity, _ = execute("evidence-inputs", ["cargo", "xtask", "evidence-inputs"])
    identity = json.loads(identity.stdout)
    if identity["source_sha256"] != before["source_sha256"] or identity["spec_sha256"] != before["spec_sha256"]:
        raise ValueError("input identities differ")
    requirement = identity["requirements_sha256"]["hello"]
    if reviewed["owner"] != "hello" or reviewed["reviewed_requirements_sha256"] != requirement:
        raise ValueError("normative requirements changed: re-review the acceptance map before sealing")
    inventory, _ = execute("api-inventory", [
        "python3", "-B", "tools/api_inventory/check.py", "--json", "--source", args.source,
        "--build", args.api_build])
    inventory = json.loads(inventory.stdout)
    if not inventory["source_verified"] or not inventory["build_profile_verified"]:
        raise ValueError("official source/profile not validated")
    expected = set(inventory["required_criteria"]["hello"])
    for interface in owner["interfaces"].values():
        if interface["required"]:
            expected.update(row["id"] for row in interface["criteria"])
    if len(expected) != 36:
        raise ValueError("HELLO obligation set changed; explicit review required")
    component_dir = output / "component"
    _, oracle_command = execute("normal-c-oracle", [
        "python3", "-B", "crates/gnunet-hello/tests/normal_c_oracle.py",
        "--source", args.source, "--build", args.build,
        "--deterministic-build", args.deterministic_build,
        "--deps-prefix", args.deps_prefix, "--output", component_dir])
    component_path = component_dir / "result.json"
    component = json.loads(component_path.read_text())
    if (component["status"] != "passed" or component["source_revision"] != REVISION
            or component["production_c_ffi"] is not False
            or component["c_inputs_unchanged"] is not True
            or component["rust_inputs_unchanged"] is not True
            or set(component["profiles"]) != {"normal", "deterministic"}):
        raise ValueError("failed, changed or incomplete C profile proof")
    checks = component["checks"]
    check_ids = {row["id"] for row in checks}
    if (not checks or len(checks) != len(check_ids) or component["check_count"] != len(checks)
            or any(row["passed"] is not True for row in checks)):
        raise ValueError("empty, duplicate or failed component checks")
    for name, digest in component["artifacts"].items():
        if sha(local(component_dir / name)) != digest:
            raise ValueError("changed generated artifact: " + name)
    for path, digest in component["rust_inputs"].items():
        if sha(local(path)) != digest:
            raise ValueError("changed HELLO input: " + path)
    source = Path(args.source).resolve()
    for path, digest in component["source_inputs"].items():
        if sha(source / path) != digest:
            raise ValueError("changed official source")
    for profile in component["profiles"].values():
        for name, digest in profile["generated_configuration"].items():
            if sha(Path(profile["build"]) / name) != digest:
                raise ValueError("changed C configuration")
        for path, digest in profile["libraries"].items():
            if sha(path) != digest:
                raise ValueError("changed actual normal C library")
    macro_runs = [c for c in component["commands"] if "-dM" in c["argv"]]
    if len(macro_runs) != 2 or any(re.search(r"^#define NDEBUG(?:\s|$)", c["stdout"], re.M) for c in macro_runs):
        raise ValueError("C driver assertion profile not established")
    rust_commands = [c for c in component["commands"] if c["argv"][:2] == ["cargo", "test"]]
    if len(rust_commands) != 1 or rust_commands[0]["exit_code"] != 0:
        raise ValueError("actual Rust tests missing")
    rust = rust_commands[0]
    tests = set(re.findall(r"^test (.+?) \.\.\. ok$", rust["stdout"], re.M))
    test_count = sum(map(int, re.findall(r"test result: ok\. (\d+) passed;", rust["stdout"])))
    if not tests or len(tests) != test_count:
        raise ValueError("Rust test output is empty, filtered or ambiguous")
    validate_bindings(reviewed["criteria"], expected, check_ids, tests)
    binaries = re.findall(r"Running tests/c_fixtures\.rs \(([^)]+)\)", rust["stderr"])
    if len(binaries) != 1:
        raise ValueError("actual Rust participant path is ambiguous")
    original_rust = local(binaries[0])
    rust_binary = output / "rust-hello-fixtures"
    shutil.copyfile(original_rust, rust_binary)
    if sha(original_rust) != sha(rust_binary):
        raise ValueError("participant copy changed bytes")
    c_binary = component_dir / "hello-normal"
    if sha(c_binary) != component["profiles"]["normal"]["driver_sha256"]:
        raise ValueError("C participant hash changed")
    rust_log = output / "rust-tests.log"
    rust_log.write_text(rust["stdout"] + "\n" + rust["stderr"])
    oracle_command["executed_checks"] = len(checks)
    commands = [oracle_command, {"argv": rust["argv"], "exit_code": 0,
        "executed_checks": test_count, "output_path": relative(rust_log), "output_sha256": sha(rust_log)}]
    after = inputs()
    save(output / "inputs-after.json", after)
    if before != after:
        raise ValueError("implementation or specification changed during the owner proof")
    report = {
        "schema": 1, "subsystem": "hello", "profile": "gnunet-0.29.1",
        "upstream_commit": REVISION, "source_sha256": before["source_sha256"],
        "source_unchanged": True, "requirements_sha256": requirement, "passed": True,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "implementations": ["gnunet-c", "gnunet-rs"], "kinds": ["official-c-differential"],
        "binary_paths": {"gnunet-c": relative(c_binary), "gnunet-rs": relative(rust_binary)},
        "binary_sha256": {"gnunet-c": sha(c_binary), "gnunet-rs": sha(rust_binary)},
        "spec_inputs": [{"path": row["path"], "sha256": row["sha256"]}
                        for row in before["spec_files"] if row["path"] != "spec/gnunet/conformance.json"],
        "commands": commands,
        "checks": [{**row, "passed": True} for row in reviewed["criteria"]],
        "acceptance_map": {"path": relative(MAP), "sha256": sha(MAP)},
        "scope_adjudications": reviewed["accepted_safe_decompositions"],
        "component_receipt": {"path": relative(component_path), "sha256": sha(component_path)},
        "preconditions": preconditions, "c_profiles": component["profiles"],
        "c_source_inputs": component["source_inputs"], "rust_tests": sorted(tests),
        "production_c_ffi": False, "full_gnunet_conformance_claim": False,
    }
    report_path = output / "conformance.json"
    save(report_path, report)
    if args.update_ledger:
        # Ledger report pointers/status do not enter the requirement projection;
        # source and every other normative byte were already checked unchanged.
        owner["status"] = "verified"
        owner["verification"] = {"path": relative(report_path), "sha256": sha(report_path)}
        owner["progress"]["remaining"] = [
            "Service/communicator admission, PILS identity derivation and routing remain separate owners."
        ]
        pending_ledger = output / "ledger-update.json"
        save(pending_ledger, ledger)
        pending_ledger.replace(ledger_path)
    print(json.dumps({"status": "passed", "owner": "hello", "criteria": len(expected),
        "comparison_checks": len(checks), "rust_tests": test_count,
        "ledger_updated": args.update_ledger, "report": relative(report_path)}))


class BindingTests(unittest.TestCase):
    def row(self):
        return {"id": "criterion", "obligation": "real operation", "adjudication": "reviewed",
                "c_rust_checks": ["comparison"], "rust_tests": ["borrow_test"]}

    def test_dropped_or_duplicate_obligation_is_rejected(self):
        for rows in ([], [self.row(), self.row()]):
            with self.assertRaises(ValueError):
                validate_bindings(rows, {"criterion"}, {"comparison"}, {"borrow_test"})

    def test_nonexecuted_comparison_or_rust_test_cannot_earn_credit(self):
        for checks, tests in ((set(), {"borrow_test"}), ({"comparison"}, set())):
            with self.assertRaises(ValueError):
                validate_bindings([self.row()], {"criterion"}, checks, tests)

    def test_review_text_and_both_witness_classes_are_mandatory(self):
        for key in ("obligation", "adjudication", "c_rust_checks", "rust_tests"):
            row = self.row()
            row[key] = None
            with self.assertRaises(ValueError):
                validate_bindings([row], {"criterion"}, {"comparison"}, {"borrow_test"})


def main():
    if sys.argv[1:] == ["--self-test"]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BindingTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful():
            raise SystemExit(1)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "api-build", "build", "deterministic-build", "deps-prefix", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--update-ledger", action="store_true")
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        if getattr(args, "created_output", None) is not None:
            save(args.created_output / "failure.json", {
                "status": "failed", "passed": False, "error": str(error),
                "full_gnunet_conformance_claim": False,
            })
        raise


if __name__ == "__main__":
    main()
