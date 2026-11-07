#!/usr/bin/env python3
"""Verify actual ARM registry/listener ownership, not complete daemon conformance."""
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

from reactor_verify import REQUIRED as REACTOR_REQUIRED

sys.dont_write_bytecode = True
PACKAGE = Path(__file__).resolve().parents[1]
PACKAGES = ("gnunet-arm-service-host", "gnunet-service-runtime", "gnunet-native")
REQUIRED = {
    "all_services_remain_registered_and_head_insertion_order_is_preserved",
    "category_absence_yes_no_and_invalid_follow_source_selection",
    "immediate_noarmbind_and_ondemand_branching_retains_nonlisteners",
    "simple_filename_argv0_options_and_global_substitution_are_source_exact",
    "caller_capacity_rejects_complete_registry_and_recursive_substitutions",
    "malformed_port_is_zero_but_range_and_boolean_are_fatal",
    "native_numeric_input_has_exact_family_protocol_and_source_order",
    "no_endpoint_and_zero_port_do_not_invent_ephemeral_listener",
    "unix_only_does_not_resolve_an_irrelevant_bindto",
    "queued_unix_connection_survives_readiness_cancel_disarm_and_actual_child_inheritance",
    "actual_tcp_child_receives_queued_data_and_v6_is_v6only",
    "sibling_disarm_and_every_actual_close_precede_term_admission",
    "adopted_parent_listener_and_replaced_owned_path_are_never_unlinked",
    "stale_socket_only_precheck_regular_and_live_entries_are_preserved",
    "registry_cross_section_binding_and_permission_precedence_follow_source",
    "partial_attachment_capacity_retains_native_owners_until_explicit_drop",
    "foreign_owner_is_rejected_before_leasing_or_retiring_original_readiness",
    "actual_native_ipv4_uses_exact_arm_hints_and_null_service_port",
    "actual_native_family_refusal_does_not_resolve_unspecified_then_filter",
    "raw_invalid_bytes_and_nul_are_classified_without_unicode_rewrite",
    "readiness_never_consumes_bytes_and_cached_hints_are_rechecked",
    "dropping_pending_wait_retains_the_original_owned_resource",
    "real_hangup_is_classified_without_reading_or_claiming_payload",
    "readiness::tests::errors_hangup_invalid_and_empty_are_distinct",
    "activation::tests::inactive_outer_predicate_matches_c_and_avoids_overflow",
    "activation::tests::official_numeric_names_are_not_systemd_names_or_sequential_guesses",
    "activation::tests::no_prefix_success_duplicate_owner_or_invalid_descriptor_number",
    "activation::private_backlog_tests::actual_bound_path_is_cleaned_when_first_listen_fails",
    "native_spawn::tests::positive_posix_errno_is_never_success",
    "process::boundaries::helper_check_observes_xok_then_uid_then_nonroot_stat_without_file_type_policy",
    "process::boundaries::exhausted_admission_generation_cannot_block_original_signal_and_reap",
    "process::boundaries::interrupted_and_zero_write_seams_execute_real_kill_without_false_pipe_success",
    "process::boundaries::unrelated_child_notification_cannot_suspend_the_next_owned_death",
    "process::boundaries::child_identity_uses_arc_address_and_token_keeps_old_identity_alive",
}

REQUIRED |= REACTOR_REQUIRED
REQUIRED |= {
    "network::tests::cloexec_and_nodelay_failure_are_nonfatal_with_bounded_ordered_diagnostics",
    "network::tests::darwin_nosigpipe_failure_is_fatal_before_nodelay",
    "network::tests::earlier_nonfatal_diagnostic_survives_later_fatal_error",
    "network::tests::exact_source_order_preserves_flags_and_skips_redundant_cloexec_set",
    "network::tests::invalid_or_fdsetsize_boundary_mints_no_native_attempt",
    "network::tests::nonblocking_failure_is_fatal_and_does_not_attempt_later_options",
    "network::tests::real_wrong_kind_setter_failure_keeps_owned_socket_usable",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(directory):
    return {p.resolve() for p in directory.rglob("*") if p.is_file()
            and not {"target", ".git", "__pycache__"}.intersection(p.relative_to(directory).parts)}


def snapshot(paths):
    return {str(p): sha(p) for p in sorted(paths, key=lambda p: os.fsencode(str(p)))}


def lint_sections(text, prefix):
    result = {}
    for section in ("rust", "clippy", "rustdoc"):
        found = re.search(r"(?ms)^\[" + re.escape(prefix + section)
                          + r"\]\s*\n(.*?)(?=^\[|\Z)", text)
        if not found:
            raise ValueError("missing complete lint section: " + section)
        result[section] = "\n".join(line.strip() for line in found.group(1).splitlines()
                                    if line.strip() and not line.strip().startswith("#"))
    return result


def package_contract(package):
    fields = ("name", "req", "source", "kind", "rename", "optional",
              "uses_default_features", "target", "path")
    dependencies = [{**{key: row.get(key) for key in fields},
                     "features": sorted(row["features"])} for row in package["dependencies"]]
    return {"dependencies": sorted(dependencies, key=lambda row: json.dumps(row, sort_keys=True)),
            "features": {key: sorted(value) for key, value in package["features"].items()
                         if key != "default" or value},
            **{key: package[key] for key in ("name", "version", "edition", "license", "rust_version")}}


def select(metadata, directory):
    return next(row for row in metadata["packages"]
                if Path(row["manifest_path"]).resolve() == directory / "Cargo.toml")


def test_names(text, expected, required):
    names = re.findall(r"^test (.+?) \.\.\. ok$", text, re.M)
    docs = [name for name in names if ".rs - " in name]
    runtime = [name for name in names if name not in docs]
    if len(runtime) != expected or len(runtime) != len(set(runtime)) or not required <= set(runtime):
        raise ValueError("runtime witnesses missing, duplicated or unexpected: " + repr(runtime))
    return runtime, docs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "source", "reference", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    repo, source, reference, out = [getattr(args, key).resolve()
                                    for key in ("repository", "source", "reference", "output")]
    for protected in (PACKAGE, repo, source):
        if out == protected or out in protected.parents or protected in out.parents:
            parser.error("output overlaps an input tree")
    out.mkdir(mode=0o700)
    commands = []
    env = dict(os.environ, CARGO_TARGET_DIR=str(out / "target"), CARGO_BUILD_JOBS="2")
    started = time.monotonic()

    def run(label, argv, timeout=300, extra=None):
        current = env.copy()
        current.update(extra or {})
        result = subprocess.run(list(map(str, argv)), cwd=repo, env=current,
                                capture_output=True, timeout=timeout)
        for stream in ("stdout", "stderr"):
            (out / (label + "." + stream)).write_bytes(getattr(result, stream))
        commands.append({"name": label, "argv": list(map(str, argv)), "exit_code": result.returncode,
                         "stdout_sha256": sha(out / (label + ".stdout")),
                         "stderr_sha256": sha(out / (label + ".stderr"))})
        if result.returncode:
            raise RuntimeError(label + " failed; see " + str(out / (label + ".stderr")))
        return result.stdout.decode(errors="replace")

    cargo = ["cargo", "+1.99.1"]
    metadata = lambda path, locked=True: json.loads(run(
        "metadata-" + str(len(commands)), cargo + ["metadata", "--manifest-path", path,
        "--offline", "--format-version", "1"] + (["--locked"] if locked else [])))
    try:
        actual = metadata(repo / "Cargo.toml")
        root_lints = lint_sections((repo / "Cargo.toml").read_text(), "workspace.lints.")
        for name in PACKAGES:
            package = next(row for row in actual["packages"] if row["name"] == name)
            text = Path(package["manifest_path"]).read_text()
            if not re.search(r"(?ms)^\[lints\]\s*\n\s*workspace\s*=\s*true\s*(?:\n|$)", text):
                raise ValueError("production package lost root lint inheritance: " + name)
        template = (PACKAGE / "Cargo.toml.in").read_text()
        if lint_sections(template, "lints.") != root_lints:
            raise ValueError("portable manifest does not retain the complete root lint contract")
        generated = out / "rust"
        generated.mkdir()
        for name in ("src", "tests", "examples"):
            shutil.copytree(PACKAGE / name, generated / name)
        rendered = re.sub(r'"@REPOSITORY@/([^"\n]+)"',
                          lambda match: json.dumps(str(repo / match.group(1))), template)
        if "@REPOSITORY@" in rendered:
            raise ValueError("unresolved portable manifest placeholder")
        (generated / "Cargo.toml").write_text(rendered)
        shutil.copy2(repo / "Cargo.lock", generated / "Cargo.lock")
        isolated = metadata(generated / "Cargo.toml", False)
        if package_contract(select(actual, PACKAGE)) != package_contract(select(isolated, generated)):
            raise ValueError("generated dependencies/features differ from production")
        sys.path.insert(0, str(repo / "tools/reference"))
        import build_reference
        normal = json.loads(reference.read_text())
        if normal.get("kind") != "unmodified-official-c-arm-reference-build" or normal.get("status") != "passed":
            raise ValueError("expected successful unchanged normal C ARM receipt")
        if build_reference.source_state(source) != normal["upstream"]:
            raise ValueError("normal C tracked source/gitlink state changed")
        inventory = json.loads((repo / "crates/gnunet-arm-service-core/source-inventory.json").read_text())
        if len(inventory["sources"]) != 22 or len(inventory["requirements"]) != 121:
            raise ValueError("complete ARM source obligation inventory was removed")

        def discover():
            paths = files(PACKAGE) | {reference, repo / "Cargo.toml", repo / "Cargo.lock",
                    repo / "rust-toolchain.toml", repo / "rustfmt.toml",
                    repo / "tools/reference/build_reference.py",
                    repo / "crates/gnunet-arm-service-core/source-inventory.json"}
            for package in [*isolated["packages"], *actual["packages"]]:
                directory = Path(package["manifest_path"]).parent.resolve()
                if package["source"] is None and directory != generated:
                    paths |= files(directory)
            for name, item in inventory["sources"].items():
                path = source / name
                if sha(path) != item["sha256"]:
                    raise ValueError("official source anchor changed: " + name)
                paths.add(path)
            values = [*normal["artifacts"].values(), *normal["libraries"],
                      *normal["default_configurations"], normal["generated_config"]]
            for item in values:
                path = Path(item["path"]).resolve()
                if sha(path) != item["sha256"]:
                    raise ValueError("normal C artifact changed: " + str(path))
                paths.add(path)
            return snapshot(paths)

        before = discover()
        generated_before = snapshot(files(generated))
        (out / "inputs-before.json").write_text(json.dumps(before, indent=2) + "\n")
        selection = sum((["-p", name] for name in PACKAGES), [])
        common = ["--locked", "--offline"]
        run("production-format", cargo + ["fmt", "--all", "--check"])
        run("shared-process-helper", cargo + ["build", "-p", "gnunet-arm-host",
            "--bin", "gnunet-arm-spawn-helper", *common])
        text = run("production-tests", cargo + ["test", *selection, *common, "--", "--test-threads=1"])
        names, docs = test_names(text, 78, REQUIRED)
        expected_doc = "adapters/service-runtime/src/listeners.rs - listeners::BoundListeners (line 34) - compile fail"
        if (expected_doc not in docs or len(docs) != 3
                or sum("framed::FramedConnection::poll_receive" in name for name in docs) != 2
                or sum("compile fail" in name for name in docs) != 2):
            raise ValueError("unexpected actual borrowed-lifetime rustdocs: " + repr(docs))
        run("production-clippy", cargo + ["clippy", *selection, "--all-targets", *common, "--", "-D", "warnings"])
        run("production-rustdoc", cargo + ["doc", *selection, "--no-deps", *common],
            extra={"RUSTDOCFLAGS": "-D warnings"})
        isolated_text = run("portable-tests", cargo + ["test", "--manifest-path", generated / "Cargo.toml",
                                                     *common, "--", "--test-threads=1"])
        shared_names = {name for name in REQUIRED if name.startswith(("activation::", "readiness::", "native_spawn::", "process::", "network::"))} | {
            "actual_native_ipv4_uses_exact_arm_hints_and_null_service_port",
            "actual_native_family_refusal_does_not_resolve_unspecified_then_filter",
            "raw_invalid_bytes_and_nul_are_classified_without_unicode_rewrite",
            "readiness_never_consumes_bytes_and_cached_hints_are_rechecked",
            "dropping_pending_wait_retains_the_original_owned_resource",
            "real_hangup_is_classified_without_reading_or_claiming_payload"}
        portable_names, portable_docs = test_names(isolated_text, 36, REQUIRED - shared_names)
        if (len(portable_docs) != 2 or sum("compile fail" in name for name in portable_docs) != 1
                or any("framed::FramedConnection::poll_receive" not in name for name in portable_docs)):
            raise ValueError("unexpected portable docs: " + repr(portable_docs))
        run("normal-c-listeners", [sys.executable, "-B", PACKAGE / "tools/normal_listeners.py",
            "--repository", repo, "--source", source, "--reference", reference,
            "--manifest", generated / "Cargo.toml", "--output", out / "normal-c"])
        paired = json.loads((out / "normal-c/result.json").read_text())
        if paired["status"] != "passed" or paired["case_count"] != 3 or not paired["inputs_unchanged"]:
            raise ValueError("normal C listener observation incomplete")
        after = discover()
        if before != after or generated_before != snapshot(files(generated)):
            raise ValueError("input file set/content changed during verification")
        if build_reference.source_state(source) != normal["upstream"]:
            raise ValueError("official tracked/gitlink state changed")
        result = {"status": "passed", "scope": "ARM registry/native-address/managed-listener foundation only",
                  "full_arm_daemon_conformance": False, "inputs_unchanged": True,
                  "generated_inputs_unchanged": True, "source_obligations_retained": 121,
                  "upstream_anchors": 22, "production_rust_count": len(names),
                  "production_rustdoc_count": len(docs), "production_rust_names": names,
                  "portable_host_count": len(portable_names), "normal_c_case_count": 3,
                  "complete_root_lints": True, "production_portable_contract_match": True,
                  "normal_c": {"path": str(out / "normal-c/result.json"), "sha256": sha(out / "normal-c/result.json")},
                  "commands": commands, "elapsed_seconds": time.monotonic() - started,
                  "inputs": before, "pending": "Full IPC/process/timer/reactor/startup/CLI/testing/platform obligations remain required"}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ("status", "production_rust_count",
                         "production_rustdoc_count", "portable_host_count", "normal_c_case_count")}))
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"status": "failed", "error": str(error),
                                                       "commands": commands}, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
