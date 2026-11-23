#!/usr/bin/env python3
"""Evaluate frozen artifacts for one candidate STATISTICS WATCH initial-value case."""

import argparse
import configparser
import hashlib
import json
from pathlib import Path


CASE = "statistics.watch-initial:case:1"
PROFILE = "statistics-private-unix-watch-initial"
ADAPTER = "statistics-watch-initial-linux"
ROLES = ("rust-service-watch-initial", "c-watch-initial")
REVISION = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
SUBSYSTEM, COUNTER, VALUE = "rust-c-interop", "counter", 55
TEXT_BOUND = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded(path):
    with path.open("rb") as stream:
        data = stream.read(TEXT_BOUND + 1)
    require(len(data) <= TEXT_BOUND, "oversized evidence artifact")
    return data


class Artifacts:
    def __init__(self, root, receipt):
        self.root = root.resolve()
        self.by_path = {ref["path"]: ref["sha256"] for ref in receipt["artifacts"]}
        self.run = Path(receipt["observation"]["path"]).parent

    def read(self, ref):
        value = Path(ref["path"])
        require(not value.is_absolute() and ".." not in value.parts and value.as_posix() == ref["path"],
                "unsafe evidence artifact path")
        path = self.root
        for component in value.parts:
            path = path / component
            require(not path.is_symlink(), "aliased evidence artifact")
        require(path.is_file(), "missing evidence artifact")
        raw = bounded(path)
        require(sha(raw) == ref["sha256"], "wrong evidence artifact hash")
        return raw

    def run_ref(self, reference):
        path = (self.run / reference["path"]).as_posix()
        require(not Path(reference["path"]).is_absolute(), "run artifact must be relative")
        return {"path": path, "sha256": reference["sha256"]}

    def observed(self, ref):
        declared = self.run_ref(ref)
        require(self.by_path.get(declared["path"]) == declared["sha256"],
                "run artifact missing from receipt")
        return self.read(declared)


def check_build(artifacts, receipt, run, participants):
    c = decode(artifacts.observed(run["retained_reference_receipt"]))
    require(c["kind"] == "unmodified-official-c-reference-build" and c["status"] == "passed"
            and c["host"]["system"] == "Linux" and c["source_unchanged"] is True
            and c["upstream"] == run["upstream"] and c["upstream"]["revision"] == REVISION
            and c["upstream"]["tracked_sources_clean"] is True,
            "wrong reference C build")
    require(c["artifacts"]["client"]["sha256"] == participants["c_client"]["sha256"]
            and c["artifacts"]["client"]["path"] == participants["c_client"]["original"],
            "official C watcher is absent from the reference build")
    require(any(row["name"] == "meson-build" and type(row["exit_code"]) is int and row["exit_code"] == 0
                and "gnunet-statistics" in row["argv"] for row in c["commands"]),
            "missing successful official C build command")
    require(c["generated_config"]["sha256"] in {row["sha256"] for row in receipt["build"]["inputs"]},
            "compiled C configuration is absent from the receipt inputs")

    build = receipt["build"]
    argv = build["argv"]
    require(argv and Path(argv[0]).name == "cargo" and "build" in argv
            and "--locked" in argv and "gnunet-service-statistics" in argv,
            "wrong Rust build command")
    events = [decode(line) for line in artifacts.read(build["receipt"]).splitlines()]
    require(events and events[-1].get("reason") == "build-finished" and events[-1].get("success") is True,
            "missing Cargo build completion")
    outputs = [event for event in events if event.get("reason") == "compiler-artifact"
               and event.get("executable") == participants["rust_service"]["original"]]
    require(len(outputs) == 1, "Rust service executable is absent or repeated in Cargo build output")
    target = outputs[0]["target"]
    require(outputs[0]["fresh"] is False
            and target["name"] == "gnunet-service-statistics" and target["kind"] == ["bin"]
            and Path(target["src_path"]).parts[-4:] == ("apps", "gnunet-service-statistics", "src", "main.rs"),
            "wrong Rust service build target")
    return c


def check_actor(artifacts, row, process, participant):
    require(row["argv"] == process["argv"] and row["argv"][0] == participant["snapshot"]
            and row["configuration"] and row.get("owned_process_group") is True
            and row["one_shot"] is False and row["diagnostic"] is False
            and type(row["exit_code"]) is int and row["exit_code"] == 0
            and not any(row.get(flag) for flag in ("forced_kill", "forced_cleanup", "timed_out", "launch_failure")),
            "owned actor did not complete normally")
    epoch = row["ready_images"]
    require(epoch == row["pre_stop_images"], "actor executable mappings changed")
    binary = artifacts.run_ref(epoch["binary"])
    loaded = {artifacts.run_ref({"path": path, "sha256": value})["path"]: value
              for path, value in epoch["loaded_files"].items()}
    require(binary == process["binary"] and binary["sha256"] == participant["sha256"]
            and process["binary_before"] == process["binary_after"] == binary["sha256"]
            and loaded == process["loaded_files_before"] == process["loaded_files_after"],
            "receipt does not match live actor images")
    files = epoch["mapped_files"]
    identities = {(tuple(row["device"]), row["inode"]) for row in files}
    require(files and files[0]["artifact"] == epoch["binary"]
            and files[0]["mapped_path"] == participant["snapshot"] and len(identities) == len(files)
            and all(len(device) == 2 and all(type(number) is int and number >= 0 for number in device)
                    and type(inode) is int and inode > 0 for device, inode in identities)
            and {row["artifact"]["path"]: row["artifact"]["sha256"] for row in files[1:]} == epoch["loaded_files"],
            "incomplete actor map identities")
    return tuple(artifacts.observed({"path": row[name], "sha256": row[name + "_sha256"]})
                 for name in ("stdout", "stderr")), files


def verify(root, receipt):
    require((receipt["requirement"], receipt["profile"], receipt["direction"], receipt["adapter"])
            == (CASE, PROFILE, "C-to-Rust", ADAPTER) and receipt["reference_revision"] == REVISION,
            "wrong candidate case, topology, direction or reference")
    artifacts = Artifacts(root, receipt)
    run = decode(artifacts.read(receipt["observation"]))
    require(run["kind"] == "official-c-statistics-daemon-ipc" and run["schema"] == 1
            and run["selected_profile"] == "watch-initial-only" and run["status"] == "passed"
            and run["cleanup_errors"] == [] and run["owned_processes_reaped"] is True
            and run["owned_runtime_removed"] is True and run["diagnostics"]["commands"] == [],
            "wrong or unclean WATCH run")
    fingerprints = run["input_fingerprints"]
    files = fingerprints["source_files"] + fingerprints["spec_files"]
    inputs = {row["path"]: row["sha256"] for row in files}
    require(len(inputs) == len(files) and receipt["implementation_inputs"]
            and all(inputs.get(path) == digest for path, digest in receipt["implementation_inputs"].items()),
            "WATCH runtime is stale or lacks source bindings")
    require(all(run.get(key) is True for key in ("source_unchanged", "reference_unchanged",
                "reference_receipt_unchanged", "reference_runtime_inputs_unchanged",
                "configurations_unchanged", "participants_unchanged", "persistent_dumps_unchanged")),
            "WATCH runtime inputs changed")
    commands, processes, participants = run["commands"], receipt["processes"], run["participants"]
    require([row["name"] for row in commands] == list(ROLES) and set(participants) == {"rust_service", "c_client"}
            and len(processes) == 2 and {row["role"] for row in processes} == set(ROLES)
            and all(type(row["pid"]) is int and row["pid"] > 0 for row in commands)
            and commands[0]["pid"] != commands[1]["pid"], "wrong process set")
    by_role = {row["role"]: row for row in processes}
    coverage = run["linux_image_capture"]
    require(coverage["status"] == "matched-long-lived-actors"
            and coverage["matched_long_lived"] == [row["stdout"] for row in commands]
            and not any(coverage[key] for key in ("unobserved_one_shot", "excluded_diagnostic", "failures")),
            "incomplete live image coverage")
    c_build = check_build(artifacts, receipt, run, participants)

    service, watcher = commands
    runtime = Path(run["owned_runtime"])
    require(runtime.is_absolute() and ".." not in runtime.parts,
            "invalid private runtime path")
    config_name = str(runtime / "watch.conf")
    common = ["-c", config_name, "-L", "ERROR"]
    require(service["argv"][1:] == common
            and watcher["argv"][1:] == common + ["-q", "-w", "-s", SUBSYSTEM, "-n", COUNTER],
            "incorrect service or WATCH arguments")
    configuration = service["configuration"]
    require(configuration == watcher["configuration"] and run["configurations"] == {config_name: configuration},
            "actors did not use the same retained configuration")
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(artifacts.observed(configuration).decode("utf-8"))
    settings = config["statistics"]
    require(settings["unixpath"] == str(runtime / "watch.sock")
            and settings["database"] == str(runtime / "watch.dat") and settings["port"] == "0"
            and settings["hostname"] == "localhost" and settings["unix_match_uid"] == "YES"
            and settings["start_on_demand"] == "NO" and settings["disable_socket_forwarding"] == "YES",
            "WATCH configuration is not the selected private Unix profile")
    (fixture,) = run["persistent_dumps"]
    names = SUBSYSTEM.encode() + b"\0" + COUNTER.encode() + b"\0"
    require(artifacts.observed(fixture) == ((16 + len(names)).to_bytes(2, "big") + b"\x00\xa8"
            + (2).to_bytes(4, "big") + VALUE.to_bytes(8, "big") + names),
            "invalid preloaded public SET fixture")

    (service_out, _), _ = check_actor(artifacts, service, by_role[ROLES[0]], participants["rust_service"])
    (watch_out, _), maps = check_actor(artifacts, watcher, by_role[ROLES[1]], participants["c_client"])
    for library in ("libgnunetutil", "libgnunetstatistics"):
        official = {row["sha256"] for row in c_build["libraries"] if Path(row["path"]).name.startswith(library + ".")}
        require(any(Path(row["mapped_path"]).name.startswith(library + ".")
                    and row["artifact"]["sha256"] in official for row in maps[1:]),
                "official C WATCH library not seen in the actor")
    require(b"READY statistics persistence=official-set-snapshot" in service_out.splitlines()
            and watch_out.splitlines() == [str(VALUE).encode()],
            "expected one WATCH value from the starting Rust service")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    raw = bounded(args.receipt)
    verify(args.evidence_root, decode(raw))
    print(json.dumps({"receipt_sha256": sha(raw), "semantic_verdict": "pass"}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, configparser.Error) as error:
        raise SystemExit(f"STATISTICS WATCH evidence rejected: {error}")
