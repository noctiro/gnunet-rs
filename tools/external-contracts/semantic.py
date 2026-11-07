"""Pending semantic requirements, separate from implementation evidence.

This migration admits draft inventories only. A future reviewed authority model
may resolve reviews, but a status string, source hash or passing receipt cannot.
"""
import hashlib
from pathlib import Path

from verify import indexed, need


def shape(value, keys, label):
    need(isinstance(value, dict) and set(value) == set(keys), "invalid fields: " + label)


def string(value, label):
    need(isinstance(value, str) and value.strip() == value and bool(value), "invalid string: " + label)


def unique_strings(value, label):
    need(isinstance(value, list) and value, "empty/non-list: " + label)
    for item in value:
        string(item, label)
    need(len(value) == len(set(value)), "duplicate: " + label)
    return set(value)


def source_ref(row, source_index, reference_source=None):
    shape(row, ("path", "sha256", "start_line", "end_line", "anchor"), "semantic source reference")
    string(row["path"], "semantic source path")
    path = Path(row["path"])
    need(not path.is_absolute() and ".." not in path.parts and path.as_posix() == row["path"], "unsafe semantic source path")
    original = source_index.get(row["path"])
    need(isinstance(original, dict) and original.get("kind") == "file" and original.get("sha256") == row["sha256"], "semantic source absent or hash differs from pinned original survey")
    need(type(row["start_line"]) is int and type(row["end_line"]) is int and 0 < row["start_line"] <= row["end_line"], "invalid semantic source line range")
    string(row["anchor"], "semantic source anchor")
    if reference_source is not None:
        root = Path(reference_source).resolve()
        current = root
        for part in path.parts:
            current = current / part
            need(not current.is_symlink(), "aliased semantic source")
        need(current.is_file() and current.resolve().is_relative_to(root), "missing semantic source")
        raw = current.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == row["sha256"], "actual semantic source drift")
        lines = raw.decode().splitlines()
        need(row["end_line"] <= len(lines) and row["anchor"] in lines[row["start_line"] - 1], "semantic source anchor/range mismatch")


def validate_inventory(value, registry, source_index, revision, directions, reference_source=None):
    shape(value, ("schema", "kind", "owner", "reference_revision", "review_state", "owner_review_complete", "operations", "cases", "profiles", "registry_classifications", "pending_surveys", "scope"), "semantic inventory")
    need(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "external-semantic-inventory-draft", "unsupported semantic inventory")
    # This reviewed migration selects one pending FS inventory. It does not
    # authorize classifying other owners by prefix/token matching.
    need(value["owner"] == "fs" and value["reference_revision"] == revision, "unsupported semantic owner/reference")
    need(value["review_state"] == "draft" and value["owner_review_complete"] is False, "draft inventory cannot self-award semantic review")
    string(value["scope"], "semantic scope")
    unique_strings(value["pending_surveys"], "pending semantic surveys")
    operations = indexed(value["operations"], "semantic operation")
    cases = indexed(value["cases"], "semantic case")
    profiles = indexed(value["profiles"], "semantic profile")
    need(operations and cases and profiles, "empty semantic inventory")
    # Validate cross-reference targets before following them. Malformed draft
    # rows are input errors rather than Python membership/key exceptions.
    for case in cases.values():
        shape(case, ("id", "operation", "contract", "review_state", "profile_direction_review", "profile_candidates", "evidence_slots"), "semantic case")
        string(case["operation"], "semantic case operation")
        unique_strings(case["profile_candidates"], "semantic profile candidates")
    for profile in profiles.values():
        shape(profile, ("id", "scope", "review_state", "candidate_directions", "required_operations"), "semantic profile")
        unique_strings(profile["required_operations"], "semantic profile operations")
    declared_cases = set()
    for operation in operations.values():
        shape(operation, ("id", "owner", "title", "contract", "review_state", "necessity", "condition", "source_refs", "case_ids"), "semantic operation")
        need(operation["id"].startswith("fs:") and operation["owner"] == "fs" and operation["review_state"] == "draft", "invalid/unreviewed semantic operation authority")
        string(operation["title"], "semantic title")
        string(operation["contract"], "semantic contract")
        need(operation["necessity"] in ("always", "selected-external-boundary"), "invalid semantic necessity")
        if operation["necessity"] == "always":
            need(operation["condition"] == "", "unreviewed condition on required capability")
        else:
            string(operation["condition"], "selected boundary condition")
        need(isinstance(operation["source_refs"], list) and operation["source_refs"], "semantic operation lacks original sources")
        for row in operation["source_refs"]:
            source_ref(row, source_index, reference_source)
        names = unique_strings(operation["case_ids"], "operation case identities")
        need(not declared_cases & names, "semantic case shared by distinct operations")
        declared_cases.update(names)
        for name in names:
            need(name in cases and cases[name]["operation"] == operation["id"], "missing/foreign semantic case")
    need(declared_cases == set(cases), "orphan or omitted semantic cases")
    for case in cases.values():
        shape(case, ("id", "operation", "contract", "review_state", "profile_direction_review", "profile_candidates", "evidence_slots"), "semantic case")
        need(case["operation"] in operations and case["id"].startswith(case["operation"] + ":case:"), "invalid semantic case identity")
        string(case["contract"], "semantic case contract")
        need(case["review_state"] == "draft" and case["profile_direction_review"] == "pending" and case["evidence_slots"] == [], "draft case cannot acquire reviewed evidence slots")
        candidates = unique_strings(case["profile_candidates"], "semantic profile candidates")
        need(candidates <= set(profiles), "unknown semantic profile candidate")
        for name in candidates:
            need(case["operation"] in profiles[name]["required_operations"], "semantic profile omits candidate operation")
    for profile in profiles.values():
        shape(profile, ("id", "scope", "review_state", "candidate_directions", "required_operations"), "semantic profile")
        need(profile["id"].startswith("fs-") and profile["review_state"] == "draft", "draft profile cannot self-award review")
        string(profile["scope"], "semantic profile scope")
        need(unique_strings(profile["candidate_directions"], "semantic candidate directions") <= directions, "unsupported semantic candidate direction")
        names = unique_strings(profile["required_operations"], "semantic profile operations")
        need(names <= set(operations), "foreign semantic profile operation")
        for name in names:
            need(any(profile["id"] in case["profile_candidates"] for case in cases.values() if case["operation"] == name), "semantic profile operation has no candidate case")
    classifications = indexed(value["registry_classifications"], "semantic registry classification")
    # All selected FS identities remain present, including optional helper IPC.
    expected = {row["id"]: row["number"] for row in registry if row["id"].startswith("FS_")}
    need(set(classifications) == set(expected), "FS registry identity omitted/added")
    for row in classifications.values():
        shape(row, ("id", "number", "review_state", "proposed_boundary", "operations", "unknown_obligation"), "semantic registry classification")
        need(type(row["number"]) is int and row["number"] == expected[row["id"]], "semantic registry assignment changed")
        need(row["review_state"] == "draft" and row["unknown_obligation"] == "registry:" + row["id"], "draft classification cannot resolve original unknown")
        string(row["proposed_boundary"], "proposed registry boundary")
        need(unique_strings(row["operations"], "registry operations") <= set(operations), "registry mapped to foreign semantic operation")
    conditional = [name for name, row in operations.items() if row["necessity"] == "selected-external-boundary"]
    conditional_cases = [name for name, row in cases.items() if row["operation"] in conditional]
    return {"owner": value["owner"], "draft_operations": list(operations), "draft_cases": list(cases), "draft_profiles": list(profiles), "draft_registry_classifications": list(classifications), "pending_inventory_review": ["owner:" + value["owner"]], "conditional_draft_operations": conditional, "conditional_draft_cases": conditional_cases}
