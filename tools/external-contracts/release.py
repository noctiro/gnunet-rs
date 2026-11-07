#!/usr/bin/env python3
"""External release migration gate. Unknown contracts block release, not C helpers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import copy

from semantic import validate_inventory

from scan import FOUNDATIONS, REVISION, SUBSYSTEMS
from verify import DATA, ROOT, Invalid, LOCK_SHA256, indexed, need, read_data, validate

# Review pin, not a regeneratable implementation-status cache. New semantics
# require an explicit additive delta review and pin change, preserving the floor.
STAGE1_LOCK_SHA256 = "4383f92e780fe2cbeece121429691bde7957d61ee7181b0a03adc156d2b46f4a"
RELEASE_LOCK_SHA256 = "674f858d8827495ec9723df65c998fe96dd72570e537aef3192f872cf8e76014"
DIRECTIONS = {"C-to-Rust", "Rust-to-C", "mixed", "negative", "recovery", "artifact", "oracle"}
INPUT_DIRS = ("crates", "adapters", "apps", "tools", "tests", ".cargo", ".github", "spec")
INPUT_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "ARCHITECTURE.md", "README.md", "rustfmt.toml")
# Legacy C helper audit data is retained but is not external release authority.
# Mutable evidence indices cannot be inputs to receipts containing their own
# digest. Normative owner flags are checked separately by the preserved draft.
LEGACY_AUDIT_PREFIX = "spec/gnunet/api/"
RESULT_INDICES = {"spec/gnunet/external/release-evidence.json", "spec/gnunet/conformance.json"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def shape(value, keys, label):
    need(isinstance(value, dict) and set(value) == set(keys), "invalid fields: " + label)


def string(value, label):
    need(isinstance(value, str) and value.strip() == value and bool(value), "invalid string: " + label)


def digest(value):
    need(isinstance(value, str) and len(value) == 64 and all(x in "0123456789abcdef" for x in value), "invalid digest")


def relative(value):
    string(value, "path")
    p = Path(value)
    need(not p.is_absolute() and ".." not in p.parts and p.as_posix() == value and value != ".", "unsafe input path")
    return p


def regular(root, name):
    """No symlink (including directory aliases), escape or missing file."""
    root = Path(root).resolve()
    p = relative(name)
    current = root
    for part in p.parts:
        current = current / part
        need(not current.is_symlink(), "aliased file: " + name)
    need(current.is_file() and current.resolve().is_relative_to(root), "missing/nonregular file: " + name)
    return current


def file_ref(root, ref):
    shape(ref, ("path", "sha256"), "file reference")
    digest(ref["sha256"])
    p = regular(root, ref["path"])
    need(sha(p) == ref["sha256"], "artifact/source digest mismatch: " + ref["path"])
    return p


def decode_json(text):
    # json.loads silently overwrites duplicate keys by default. Authority and
    # digest fields must never be replaced by a second spelling in the same file.
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs)


def load_json(path):
    return decode_json(Path(path).read_text())


def implementation_inputs(root):
    root = Path(root)
    names = set(INPUT_FILES)
    for directory in INPUT_DIRS:
        base = root / directory
        need(base.is_dir() and not base.is_symlink(), "missing/aliased implementation directory: " + directory)
        for current, dirs, files in os.walk(base):
            dirs[:] = sorted(x for x in dirs if x not in ("target", ".git", "__pycache__"))
            for name in dirs:
                need(not (Path(current) / name).is_symlink(), "aliased implementation directory")
            for name in files:
                names.add((Path(current) / name).relative_to(root).as_posix())
    return {name: sha(regular(root, name)) for name in sorted(names - RESULT_INDICES) if not name.startswith(LEGACY_AUDIT_PREFIX)}


def tracked_inputs(source):
    """Whole tracked path/type/content survey, not compiled-active inference."""
    source = Path(source).resolve()
    def git(*args):
        return subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True).stdout
    need(git("rev-parse", "HEAD").decode().strip() == REVISION, "reference revision mismatch")
    git("diff", "--exit-code", "--ignore-submodules=none", "HEAD", "--")
    result = {}
    for item in git("ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not item:
            continue
        fields, raw_name = item.split(b"\t", 1)
        mode, _kind, obj = fields.decode().split()
        name = raw_name.decode()
        relative(name)
        p = source / name
        if mode == "160000":
            result[name] = {"kind": "gitlink", "object": obj}
        elif mode == "120000":
            need(p.is_symlink(), "reference alias replaced")
            target = p.readlink().as_posix()
            result[name] = {"kind": "symlink", "target": target, "sha256": hashlib.sha256(target.encode()).hexdigest()}
        else:
            result[name] = {"kind": "file", "sha256": sha(regular(source, name))}
    return result


def read_requirements(data=DATA, historical=False):
    """Canonical stage2 or explicitly selected immutable stage1 history."""
    lock_path = data / "release-lock.json"
    expected = STAGE1_LOCK_SHA256 if historical else RELEASE_LOCK_SHA256
    need(sha(lock_path) == expected, "external release lock changed/downgraded; review an additive old/new delta, never regenerate reduced scope")
    lock = load_json(lock_path)
    common = ("schema", "kind", "reference_revision", "legacy_draft_lock_sha256", "requirements_sha256", "source_index_sha256", "evidence_schema_sha256", "review")
    extra = () if historical else ("predecessor", "semantic_inventories", "semantic_inventory_schema_sha256")
    shape(lock, common + extra, "release lock")
    version = 1 if historical else 2
    need(type(lock["schema"]) is int and lock["schema"] == version and lock["kind"] == "reviewed-external-release-stage" + str(version) + "-lock" and lock["reference_revision"] == REVISION and lock["legacy_draft_lock_sha256"] == LOCK_SHA256, "unknown release lock target")
    result = []
    for name, key in [("release-requirements.json", "requirements_sha256"), ("release-source-index.json", "source_index_sha256"), ("release-evidence.schema.json", "evidence_schema_sha256")]:
        need(sha(data / name) == lock[key], "unreviewed external requirement/schema/source-index change: " + name)
        result.append(load_json(data / name))
    need(result[0]["source_index_sha256"] == lock["source_index_sha256"], "requirements bind a different reference source index")
    need(result[2]["properties"]["requirements_sha256"]["const"] == lock["requirements_sha256"], "evidence schema binds a different requirement revision")
    if not historical:
        need(lock["predecessor"] == {"path": "history/stage1/release-lock.json", "sha256": STAGE1_LOCK_SHA256}, "stage1 predecessor omitted/changed")
        file_ref(data, lock["predecessor"])
        need(sha(data / "semantic-inventory.schema.json") == lock["semantic_inventory_schema_sha256"], "unreviewed semantic inventory schema")
        need(result[0]["semantic_inventories"] == lock["semantic_inventories"], "semantic inventory extension omitted/changed")
        for row in lock["semantic_inventories"]:
            shape(row, ("id", "path", "sha256"), "semantic inventory reference")
            file_ref(data, {"path": row["path"], "sha256": row["sha256"]})
    return (*result, lock)


def semantic_summaries(requirements, survey, data=DATA, reference_source=None):
    if requirements["schema"] == 1:
        return []
    references = indexed(requirements["semantic_inventories"], "semantic inventory reference")
    need(references, "semantic inventory extension omitted")
    result = []
    for row in references.values():
        shape(row, ("id", "path", "sha256"), "semantic inventory reference")
        path = file_ref(data, {"path": row["path"], "sha256": row["sha256"]})
        inventory = load_json(path)
        need(inventory.get("owner") == row["id"], "semantic inventory owner/reference mismatch")
        result.append(validate_inventory(inventory, requirements["registry_assignments"], survey["paths"], REVISION, DIRECTIONS, reference_source))
    return result


def validate_requirements(requirements, survey, schema, legacy, data=DATA, reference_source=None):
    """Preserve the original floor; draft additions never resolve its unknowns."""
    if requirements.get("schema") == 1:
        return validate_stage1_requirements(requirements, survey, schema, legacy)
    need(type(requirements.get("schema")) is int and requirements["schema"] == 2 and requirements.get("kind") == "external-release-requirements-stage2", "unknown release requirement stage")
    past, past_survey, _past_schema, _past_lock = read_requirements(data / "history/stage1", historical=True)
    floor = copy.deepcopy(requirements)
    need(floor.pop("predecessor_requirements_sha256", None) == sha(data / "history/stage1/release-requirements.json"), "stage1 requirement predecessor omitted/changed")
    extensions = floor.pop("semantic_inventories", None)
    lock = load_json(data / "release-lock.json")
    need(sha(data / "release-lock.json") == RELEASE_LOCK_SHA256 and extensions == lock["semantic_inventories"], "unreviewed/omitted semantic inventory extension")
    floor["schema"] = 1
    floor["kind"] = "external-release-requirements-stage1"
    need(floor == past and survey == past_survey, "stage2 changed/dropped the retained stage1 external floor")
    cases = validate_stage1_requirements(floor, survey, schema, legacy)
    summaries = semantic_summaries(requirements, survey, data, reference_source)
    new_cases = [name for row in summaries for name in row["draft_cases"]]
    need(len(new_cases) == len(set(new_cases)) and not set(new_cases) & set(cases), "duplicate legacy/semantic case identity")
    return cases


def validate_stage1_requirements(requirements, survey, schema, legacy):
    discovery, node, coverage, _lock = legacy
    shape(requirements, ("schema", "kind", "reference_revision", "legacy_draft_lock_sha256", "required_subsystems", "required_foundations", "C_helper_mapping_required", "complete_semantic_inventory", "registry_assignments", "reviewed_partial_messages", "reviewed_partial_operations", "reviewed_partial_profiles", "nonregistry_obligations", "unknowns", "case_obligations", "evidence_adapters", "source_index_sha256", "coverage_policy"), "release requirements")
    need(requirements["schema"] == 1 and requirements["kind"] == "external-release-requirements-stage1" and requirements["reference_revision"] == REVISION and requirements["legacy_draft_lock_sha256"] == LOCK_SHA256, "unknown release requirements")
    need(requirements["required_subsystems"] == list(SUBSYSTEMS) and requirements["required_foundations"] == list(FOUNDATIONS) and requirements["C_helper_mapping_required"] is False, "required34+8 scope or Rust-native policy changed")
    need(requirements["registry_assignments"] == [{"id": row["id"], "number": row["number"]} for row in discovery["registry"]], "registry identity or numeric alias omitted")
    for field, rows in [("reviewed_partial_messages", node["messages"]), ("reviewed_partial_operations", node["operations"]), ("reviewed_partial_profiles", node["profiles"]), ("nonregistry_obligations", coverage["nonregistry_obligations"])]:
        need(requirements[field] == rows, "reviewed external requirement lost/rewritten: " + field)
    need(requirements["coverage_policy"] == {"lexical_candidates_are_semantics": False, "numeric_alias_deduplication_allowed": False, "unknowns_may_be_waived_by_evidence": False, "implementation_status_changes_requirements": False, "legacy_helper_catalog_is_release_prerequisite": False}, "unsafe release policy")
    unknown = indexed(requirements["unknowns"], "unknown review task")
    floor = {"owner:" + x for x in SUBSYSTEMS + FOUNDATIONS}
    floor.update("registry:" + x["id"] for x in discovery["registry"])
    floor.update("nonregistry:" + x["id"] for x in coverage["nonregistry_obligations"])
    floor.update("survey:" + x for x in ("generated-non-C", "build-platform-variants", "third-party-negotiation", "artifact-domains", "profile-case-directions", "submodules-docs", "evidence-adapters"))
    need(set(unknown) == floor and requirements["complete_semantic_inventory"] is False, "unreviewed completeness or missing unknown capability")
    for row in unknown.values():
        shape(row, ("id", "status", "reason"), "unknown")
        need(row["status"] == "unknown", "unknown semantic inventory cannot be marked complete by result data")
        string(row["reason"], "unknown reason")
    cases = indexed(requirements["case_obligations"], "external case")
    expected = []
    for op in node["operations"]:
        for i, case in enumerate(op["required_cases"], 1):
            expected.append({"id": op["id"] + ":case:" + str(i), "operation": op["id"], "contract": case, "profile_direction_review": "pending", "evidence_slots": []})
    need(requirements["case_obligations"] == expected, "external state/failure case/profile obligation changed without review")
    # Stage1 intentionally registers no semantic verifier. A future reviewed
    # requirement delta can register source-pinned adapters, not unchecked JSON
    # status labels or old receipt hashes relabeled to a new implementation.
    need(requirements["evidence_adapters"] == [], "unreviewed evidence adapter")
    shape(survey, ("schema", "kind", "reference_revision", "paths", "compiled_active", "external_semantics_complete", "submodule_contents_reviewed"), "source survey")
    need(survey["schema"] == 1 and survey["kind"] == "reference-tracked-survey-inputs" and survey["reference_revision"] == REVISION and survey["compiled_active"] is False and survey["external_semantics_complete"] is False and survey["submodule_contents_reviewed"] is False, "source survey falsely claims semantic/build activation")
    need(len(survey["paths"]) == 2193 and all(name in survey["paths"] and survey["paths"][name].get("sha256") == value for name, value in discovery["input_files"].items()), "source survey omitted legacy source bytes")
    need(schema["properties"]["records"]["type"] == "array", "unsupported evidence schema")
    return cases


def verify_receipt(receipt, receipt_path, requirements, implementation, source_index, evidence_root, adapters):
    """Integrity layer only; a pinned semantic adapter must also verify raw facts."""
    receipt_before = sha(receipt_path)
    shape(receipt, ("schema", "kind", "requirement", "profile", "direction", "adapter", "result", "implementation_inputs", "reference_revision", "reference_inputs", "build", "processes", "artifacts", "observation", "review"), "external receipt")
    need(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["kind"] == "external-boundary-receipt" and receipt["result"] == "pass", "failed/unknown receipt is not passing evidence")
    cases = indexed(requirements["case_obligations"], "case")
    need(receipt["requirement"] in cases and receipt["direction"] in DIRECTIONS, "unknown case/direction")
    profiles = indexed(requirements["reviewed_partial_profiles"], "profile")
    need(receipt["profile"] in profiles and cases[receipt["requirement"]]["operation"] in profiles[receipt["profile"]]["required_operations"], "case not covered by receipt topology profile")
    need(receipt["reference_revision"] == REVISION and receipt["reference_inputs"] == source_index, "reference inputs/version omitted or drifted")
    need(receipt["implementation_inputs"] == implementation, "stale or partial implementation input binding")
    adapter = adapters.get(receipt["adapter"])
    need(adapter is not None, "unreviewed semantic evidence adapter; raw JSON cannot award interoperability credit")
    shape(adapter, ("id", "script", "sha256", "review"), "adapter")
    string(adapter["review"], "semantic verifier review")
    adapter_path = file_ref(ROOT, {"path": adapter["script"], "sha256": adapter["sha256"]})
    shape(receipt["build"], ("profile", "argv", "toolchain", "binaries", "inputs", "receipt"), "build provenance")
    string(receipt["build"]["profile"], "build profile")
    need(isinstance(receipt["build"]["argv"], list) and receipt["build"]["argv"] and all(isinstance(x, str) for x in receipt["build"]["argv"]), "missing build argv")
    need(isinstance(receipt["build"]["toolchain"], dict) and receipt["build"]["toolchain"], "missing actual compiler/toolchain")
    need(isinstance(receipt["build"]["binaries"], list), "invalid build binaries")
    for x in receipt["build"]["binaries"]:
        file_ref(evidence_root, x)
    need(receipt["build"]["binaries"], "missing actual built binaries")
    need(isinstance(receipt["build"]["inputs"], list) and receipt["build"]["inputs"], "missing configured/generated/dependency build inputs")
    for build_input in receipt["build"]["inputs"]:
        file_ref(evidence_root, build_input)
    file_ref(evidence_root, receipt["build"]["receipt"])
    artifacts = receipt["artifacts"]
    need(isinstance(artifacts, list) and artifacts and len({x["path"] for x in artifacts}) == len(artifacts), "duplicate/missing raw artifacts")
    for artifact in artifacts:
        file_ref(evidence_root, artifact)
    file_ref(evidence_root, receipt["observation"])
    file_ref(evidence_root, receipt["review"])
    roles = []
    need(isinstance(receipt["processes"], list) and receipt["processes"], "missing process lifecycle observations")
    for process in receipt["processes"]:
        shape(process, ("role", "argv", "binary", "binary_before", "binary_after", "exit_code", "termination", "loaded_files_before", "loaded_files_after"), "process")
        string(process["role"], "process role")
        p = file_ref(evidence_root, process["binary"])
        need(process["binary_before"] == process["binary_after"] == sha(p), "binary changed during process epoch")
        need(type(process["exit_code"]) is int and process["exit_code"] == 0 and process["termination"] == "exited", "owned process failed/forced/still live")
        need(isinstance(process["argv"], list) and process["argv"] and all(isinstance(x, str) for x in process["argv"]), "missing process argv")
        need(isinstance(process["loaded_files_before"], dict) and process["loaded_files_before"] == process["loaded_files_after"], "loaded dependency drift")
        # File-backed images must be actual retained bytes, never UUID-only
        # cache identities relabeled as file content verification.
        for name, value in process["loaded_files_before"].items():
            file_ref(evidence_root, {"path": name, "sha256": value})
        roles.append(process["role"])
    need(len(roles) == len(set(roles)), "duplicate topology process role")
    profile = profiles[receipt["profile"]]
    need(set(profile["required_components"]) <= set(roles), "required production role absent")
    need(not set(profile["forbidden_data_plane_substitutions"]) & set(roles), "C/backend/mock replaces Rust production data plane")
    # No shell, no new network/profile run: only a reviewed local observation
    # verifier on frozen artifacts. This migration registers no adapter.
    command = ["python3", "-B", str(adapter_path), "--receipt", str(receipt_path), "--evidence-root", str(evidence_root)]
    verified = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    verdict = decode_json(verified.stdout)
    need(verdict == {"receipt_sha256": receipt_before, "semantic_verdict": "pass"} and sha(receipt_path) == receipt_before, "semantic adapter did not verify this exact unchanged receipt")
    for artifact in artifacts + receipt["build"]["binaries"] + receipt["build"]["inputs"] + [receipt["build"]["receipt"], receipt["observation"], receipt["review"]]:
        file_ref(evidence_root, artifact)
    for process in receipt["processes"]:
        file_ref(evidence_root, process["binary"])
        for name, value in process["loaded_files_before"].items():
            file_ref(evidence_root, {"path": name, "sha256": value})
    return (receipt["requirement"], receipt["profile"], receipt["direction"])


def evaluate(requirements, evidence, requirements_sha, implementation, survey, evidence_root, data=DATA, reference_source_checked=False):
    shape(evidence, ("schema", "kind", "requirements_sha256", "records"), "evidence index")
    need(type(evidence["schema"]) is int and evidence["schema"] == 1 and evidence["kind"] == "external-release-evidence-index" and evidence["requirements_sha256"] == requirements_sha, "evidence for different requirements/version")
    need(isinstance(evidence["records"], list), "invalid evidence records")
    keys = set()
    paths = set()
    adapters = indexed(requirements["evidence_adapters"], "semantic adapter")
    for ref in evidence["records"]:
        path = file_ref(evidence_root, ref)
        need(ref["path"] not in paths, "duplicate evidence receipt")
        paths.add(ref["path"])
        key = verify_receipt(load_json(path), path, requirements, implementation, survey["paths"], evidence_root, adapters)
        need(key not in keys, "duplicate case/profile/direction cannot inflate coverage")
        keys.add(key)
    unknowns = [x["id"] for x in requirements["unknowns"]]
    pending_cases = [x["id"] for x in requirements["case_obligations"] if x["profile_direction_review"] != "reviewed" or not x["evidence_slots"] or any((x["id"], slot["profile"], slot["direction"]) not in keys for slot in x["evidence_slots"])]
    inventories = semantic_summaries(requirements, survey, data)
    draft_cases = [name for row in inventories for name in row["draft_cases"]]
    pending_review = [name for row in inventories for name in row["pending_inventory_review"]]
    pending_review += [name for row in inventories for name in row["draft_operations"] + row["draft_profiles"] + row["draft_registry_classifications"]]
    pending_cases += draft_cases
    complete, ready = release_state(unknowns, pending_cases, pending_review, reference_source_checked)
    return {"status": "external-release-ready" if ready else "external-release-pending", "requirement_stage": requirements["schema"], "required_subsystems": len(SUBSYSTEMS), "required_foundations": len(FOUNDATIONS), "registry_assignments": len(requirements["registry_assignments"]), "reviewed_partial_messages": len(requirements["reviewed_partial_messages"]), "reviewed_partial_operations": len(requirements["reviewed_partial_operations"]), "reviewed_partial_profiles": len(requirements["reviewed_partial_profiles"]), "retained_state_failure_cases": len(requirements["case_obligations"]), "semantic_inventories": len(inventories), "draft_semantic_operations": sum(len(x["draft_operations"]) for x in inventories), "draft_semantic_cases": len(draft_cases), "draft_semantic_profiles": sum(len(x["draft_profiles"]) for x in inventories), "conditional_draft_operations": [name for row in inventories for name in row["conditional_draft_operations"]], "conditional_draft_cases": [name for row in inventories for name in row["conditional_draft_cases"]], "pending_semantic_review": pending_review, "unknown_contracts": unknowns, "pending_cases": pending_cases, "integrity_checked_receipts": len(keys), "complete_semantic_inventory": complete, "full_GNUnet_conformance_verified": ready, "C_helper_mapping_required": False, "reference_source_checked": reference_source_checked, "release_ready": ready}


def release_state(unknowns, pending_cases, pending_semantic_review, reference_source_checked):
    """Readiness is derived from unresolved requirements, never a result label.

    Callers must first validate the pinned normative floor and every receipt.
    This function cannot approve or resolve a semantic review obligation.
    """
    complete = not unknowns and not pending_semantic_review
    return complete, complete and not pending_cases and reference_source_checked is True


def require_release(report):
    need(report["release_ready"] is True and report["complete_semantic_inventory"] is True and report.get("reference_source_checked") is True and not report["unknown_contracts"] and not report["pending_cases"], "external release blocked: unknown/pending external contracts or current source-bound semantic evidence; C internal helper mappings are not required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--historical-stage1", action="store_true", help="Read the immutable stage1 pending requirement format; never silently downgrade the canonical stage2 gate")
    parser.add_argument("--reference-source", type=Path, default=os.environ.get("GNUNET_REFERENCE_SOURCE"))
    parser.add_argument("--evidence-index", type=Path, default=DATA / "release-evidence.json")
    parser.add_argument("--evidence-root", type=Path, default=ROOT)
    args = parser.parse_args()
    before = implementation_inputs(ROOT)
    legacy = read_data()
    validate(*legacy, source=args.reference_source)
    data = DATA / "history/stage1" if args.historical_stage1 else DATA
    requirements, survey, schema, lock = read_requirements(data, historical=args.historical_stage1)
    validate_requirements(requirements, survey, schema, legacy, data, args.reference_source)
    if args.reference_source:
        need(tracked_inputs(args.reference_source) == survey["paths"], "whole reference survey path/type/source drift")
    index_path = data / "release-evidence.json" if args.historical_stage1 and args.evidence_index == DATA / "release-evidence.json" else args.evidence_index
    evidence_before = sha(index_path)
    report = evaluate(requirements, load_json(index_path), lock["requirements_sha256"], before, survey, args.evidence_root, data, args.reference_source is not None)
    need(implementation_inputs(ROOT) == before and sha(index_path) == evidence_before, "inputs changed during release verification")
    if args.reference_source:
        need(tracked_inputs(args.reference_source) == survey["paths"], "reference inputs changed during release verification")
    report["reference_source_checked"] = args.reference_source is not None
    report["implementation_input_count"] = len(before)
    # The full pending identities make omissions independently inspectable.
    print(json.dumps(report, sort_keys=True), flush=True)
    if args.strict:
        require_release(report)


if __name__ == "__main__":
    try:
        main()
    except (Invalid, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("external-release: " + str(error)) from error
