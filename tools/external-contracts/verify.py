#!/usr/bin/env python3
"""Check reviewed inventory integrity. This draft never grants conformance credit."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from scan import FOUNDATIONS, REVISION, SUBSYSTEMS, discover

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "spec/gnunet/external"
# Reviewed requirement lock, not an auto-update cache. A protocol-target or
# semantic requirement change must review the old/new delta and this pin.
LOCK_SHA256 = "27b765155fc9f77bf58b13dae7f46108d402dae599cb053cc2c33210cbb9a50a"


class Invalid(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Invalid(message)


def indexed(rows, label):
    need(isinstance(rows, list), "invalid " + label)
    result = {}
    for row in rows:
        need(isinstance(row, dict) and isinstance(row.get("id"), str), "invalid " + label + " identity")
        need(row["id"] not in result, "duplicate " + label + ": " + row["id"])
        result[row["id"]] = row
    return result


def safe_paths(paths):
    for name, value in paths.items():
        path = Path(name)
        need(not path.is_absolute() and ".." not in path.parts and path.as_posix() == name,
             "unsafe reference input path")
        need(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value),
             "invalid reference input digest")


def read_data(data=DATA):
    raw = (data / "requirements-lock.json").read_bytes()
    need(hashlib.sha256(raw).hexdigest() == LOCK_SHA256,
         "reviewed external requirement lock changed; review the delta, do not regenerate reduced scope")
    return (json.loads((data / "discovery.json").read_text()),
            json.loads((data / "node-path.json").read_text()),
            json.loads((data / "coverage.json").read_text()), json.loads(raw))


def validate(discovery, node, coverage, lock, source=None, ledger=None):
    need(set(lock) == {"schema", "kind", "discovery_sha256", "node_path_sha256", "coverage_sha256", "scope", "reference_revision"},
         "unknown requirement-lock field")
    need(lock["schema"] == 1 and lock["kind"] == "reviewed-external-discovery-draft-lock", "unsupported lock")
    need(lock["reference_revision"] == REVISION, "unknown reference revision")
    scope = lock["scope"]
    need(scope == {"subsystems": list(SUBSYSTEMS), "foundations": list(FOUNDATIONS),
                   "complete_semantic_inventory": False, "quality_gate_separate": True,
                   "C_helper_mapping_required": False}, "whole-project scope or Rust policy changed")
    ledger = ledger if ledger is not None else json.loads((ROOT / "spec/gnunet/conformance.json").read_text())
    for field, expected in [("required_subsystems", SUBSYSTEMS), ("foundations", FOUNDATIONS)]:
        actual = [row["id"] for row in ledger[field]]
        need(actual == list(expected), "whole-project owner removed/changed")
        need(all(row.get("required") is True for row in ledger[field]), "whole-project required owner downgraded")
    need(canonical_digest(discovery) == lock["discovery_sha256"], "source/registry discovery changed without review")
    need(canonical_digest(node) == lock["node_path_sha256"], "external message/operation/profile requirement changed without review")
    need(canonical_digest(coverage) == lock["coverage_sha256"], "whole-owner/nonregistry requirement changed without review")
    need(set(discovery) == {"schema", "kind", "reference_revision", "scan_policy", "input_files", "source_aliases", "C_files", "registry", "unregistered_source_tokens"}, "unreviewed discovery field or credit")
    need(discovery["schema"] == 1 and discovery["kind"] == "official-message-discovery-candidates" and discovery["reference_revision"] == REVISION,
         "unknown discovery version")
    need(all(discovery["scan_policy"].get(key) is False for key in
             ["preprocessor_conditions_evaluated", "build_activation_inferred", "operation_or_semantic_completeness_inferred", "unframed_or_nonregistry_protocols_complete"]),
         "lexical discovery cannot certify active or complete external protocols")
    safe_paths(discovery["input_files"])
    for name, target in discovery["source_aliases"].items():
        need(name in ("meson.options", "meson_options.txt") and target in discovery["input_files"],
             "unknown or unbound Meson option alias")
    names = indexed(discovery["registry"], "registry message")
    need(len(names) == 677, "pinned complete registry assignment scope changed")
    for row in names.values():
        need(set(row) == {"id", "number", "source_references"} and type(row["number"]) is int and 0 <= row["number"] <= 65535,
             "invalid registry assignment")
        for fact in row["source_references"]:
            need(set(fact) == {"path", "line", "source_area_hint"} and fact["path"] in discovery["C_files"] and type(fact["line"]) is int and fact["line"] > 0,
                 "invalid discovery reference")
    need(len(discovery["C_files"]) == len(set(discovery["C_files"])) and set(discovery["C_files"]) <= set(discovery["input_files"]),
         "discovery source inventory incomplete")
    need(set(node) == {"schema", "kind", "awards_implementation_or_verification_credit", "reference_revision", "scope", "input_files", "owners", "messages", "operations", "profiles", "known_discrepancies"},
         "unreviewed external status/credit field")
    need(node["schema"] == 1 and node["kind"] == "external-node-path-contract-draft" and node["reference_revision"] == REVISION and node["awards_implementation_or_verification_credit"] is False,
         "node path draft cannot award conformance credit")
    safe_paths(node["input_files"])
    need(all(discovery["input_files"].get(path) == value for path, value in node["input_files"].items()),
         "node path source identity missing from discovery")
    messages = indexed(node["messages"], "node message")
    operations = indexed(node["operations"], "external operation")
    profiles = indexed(node["profiles"], "external profile")
    need((len(messages), len(operations), len(profiles)) == (99, 34, 3), "reviewed partial node-path scope changed")
    need(set(node["owners"]) == {row["owner"] for row in list(messages.values()) + list(operations.values())},
         "node-path owner missing")
    for key, row in messages.items():
        need(key in names and row["number"] == names[key]["number"], "message number/alias missing from full registry")
        if row["required"]:
            need(row["owner"] != "UNRESOLVED" and row["boundary"] in ("network-wire", "service-ipc") and row["source_references"],
                 "required external message unresolved")
            discovered = {(fact["path"], fact["line"]) for fact in names[key]["source_references"]}
            need(all((fact["path"], fact["line"]) in discovered for fact in row["source_references"]),
                 "required source reference absent from whole-source discovery")
    for row in operations.values():
        need(row["required"] is True and row["owner"] != "UNRESOLVED" and set(row["messages"]) <= set(messages) and row["contract"] and row["required_cases"],
             "external operation/state requirement unresolved")
    for row in profiles.values():
        need(set(row["required_operations"]) <= set(operations) and row["node_credit"] is False,
             "unknown profile operation or false node credit")
    need(set(coverage) == {"schema", "kind", "reference_revision", "owners", "nonregistry_obligations", "complete_semantic_inventory"}
         and coverage["schema"] == 1 and coverage["kind"] == "external-owner-coverage-draft"
         and coverage["reference_revision"] == REVISION and coverage["complete_semantic_inventory"] is False,
         "unknown coverage field or false completeness")
    owners = indexed(coverage["owners"], "whole-project owner")
    need(set(owners) == set(SUBSYSTEMS + FOUNDATIONS), "whole-project owner omitted")
    for key, row in owners.items():
        need(set(row) == {"id", "kind", "required", "semantic_inventory", "node_path_operations"}
             and row["required"] is True
             and row["kind"] == ("subsystem" if key in SUBSYSTEMS else "foundation")
             and row["semantic_inventory"] in ("pending", "partial-node-path")
             and set(row["node_path_operations"]) <= set(operations), "owner scope/semantic status changed")
    need(set(operations) == {key for row in owners.values() for key in row["node_path_operations"]},
         "external node operation has no whole-project owner")
    for row in indexed(coverage["nonregistry_obligations"], "nonregistry obligation").values():
        need(set(row) == {"id", "owners", "boundary", "required", "contract", "required_cases", "source_examples", "semantic_review"}
             and row["required"] is True and row["semantic_review"] == "pending"
             and set(row["owners"]) <= set(owners) and row["owners"]
             and row["contract"] and row["required_cases"] and row["source_examples"]
             and set(row["source_examples"]) <= set(discovery["input_files"]),
             "nonregistry/zero-token external capability lost or falsely completed")
    if source is not None:
        source = Path(source).resolve()
        revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        need(revision == REVISION, "reference checkout is not the pinned target")
        # Recompute the entire path set, tokens and bytes, not just the input
        # rows supplied by a potentially narrowed discovery document.
        actual = discover(source, node["input_files"])
        need(actual == discovery, "current official sources/paths/tokens differ; review protocol delta")
    return {
        "status": "consistent-external-inventory-draft",
        "full_required_subsystems": len(SUBSYSTEMS), "full_required_foundations": len(FOUNDATIONS),
        "registry_assignments": len(names), "lexical_C_files": len(discovery["C_files"]),
        "registry_names_with_candidates": sum(bool(row["source_references"]) for row in names.values()),
        "unregistered_candidate_names": len(discovery["unregistered_source_tokens"]),
        "reviewed_node_path_messages": len(messages), "reviewed_node_path_operations": len(operations),
        "nonregistry_obligation_groups_pending": len(coverage["nonregistry_obligations"]),
        "complete_semantic_inventory": False, "reference_source_checked": source is not None,
        "full_GNUnet_conformance_verified": False, "awards_implementation_or_verification_credit": False,
    }


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def topology(plan, node):
    need(set(plan) == {"profile", "components", "claims_complete_GNUnet"}, "unknown topology field")
    profiles = indexed(node["profiles"], "profile")
    need(plan["profile"] in profiles and plan["claims_complete_GNUnet"] is False, "unknown profile or false full-node claim")
    row = profiles[plan["profile"]]
    components = plan["components"]
    need(isinstance(components, list) and all(isinstance(x, str) for x in components), "invalid component identities")
    need(len(components) == len(set(components)), "duplicate topology role")
    need(set(row["required_components"]) <= set(components), "production component missing")
    need(not set(row["forbidden_data_plane_substitutions"]) & set(components), "C/mock/relay replaces Rust production data plane")
    return {"status": "consistent-topology-shape-only", "awards_implementation_or_verification_credit": False}


def require_complete(_report):
    # No discovery count, local test or topology plan can stand in for the
    # semantic operations/profiles and real C evidence of all 42 owners.
    raise Invalid("external release gate pending: complete semantic operation/profile inventory and source-bound interoperability evidence for all 34 subsystems + 8 foundations remain required; C helper mapping is not a substitute")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-source", type=Path, default=os.environ.get("GNUNET_REFERENCE_SOURCE"))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--topology", type=Path)
    args = parser.parse_args()
    discovery, node, coverage, lock = read_data()
    report = validate(discovery, node, coverage, lock, args.reference_source)
    if args.topology:
        report["topology"] = topology(json.loads(args.topology.read_text()), node)
    print(json.dumps(report, sort_keys=True), flush=True)
    if args.strict:
        require_complete(report)


if __name__ == "__main__":
    try:
        main()
    except (Invalid, ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("external-contracts: " + str(error)) from error
