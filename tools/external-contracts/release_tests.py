#!/usr/bin/env python3
"""Local controls for gate integrity, not GNUnet interoperability evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release as gate


class ReleaseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = gate.read_data()
        cls.req, cls.survey, cls.schema, cls.lock = gate.read_requirements()
        cls.index = gate.load_json(gate.DATA / "release-evidence.json")

    def invalid_requirement(self, mutate):
        r = copy.deepcopy(self.req)
        mutate(r)
        with self.assertRaises(gate.Invalid):
            gate.validate_requirements(r, self.survey, self.schema, self.legacy)

    def test_full_external_floor_and_partial_cases_retained(self):
        cases = gate.validate_requirements(self.req, self.survey, self.schema, self.legacy)
        self.assertEqual((len(self.req["required_subsystems"]), len(self.req["required_foundations"])), (34, 8))
        self.assertEqual(len(self.req["registry_assignments"]), 677)
        self.assertEqual(len(self.req["unknowns"]), 734)
        self.assertEqual(len(cases), 156)
        self.assertEqual(len(self.survey["paths"]), 2193)
        self.assertFalse(self.req["C_helper_mapping_required"])

    def test_pending_inventory_blocks_even_empty_consistent_evidence(self):
        report = gate.evaluate(self.req, self.index, self.lock["requirements_sha256"], {}, self.survey, gate.ROOT)
        self.assertFalse(report["release_ready"])
        self.assertEqual(len(report["unknown_contracts"]), 734)
        self.assertEqual(len(report["pending_cases"]) - report["draft_semantic_cases"], 156)
        self.assertEqual(report["draft_semantic_cases"], 147)
        self.assertEqual(len(report["pending_cases"]), 303)
        with self.assertRaises(gate.Invalid):
            gate.require_release(report)

    def test_no_helper_symbol_catalog_is_read_by_release_gate(self):
        # This test denies every attempted API-catalog read. The externally
        # complete owner projection remains a separate draft integrity input.
        original = gate.load_json
        def no_api(path):
            self.assertNotIn("spec/gnunet/api/", str(path))
            return original(path)
        with patch.object(gate, "load_json", no_api):
            req, survey, schema, _ = gate.read_requirements()
            gate.validate_requirements(req, survey, schema, self.legacy)

    def test_legacy_catalog_changes_do_not_invalidate_external_actor_bindings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for directory in gate.INPUT_DIRS:
                (root / directory).mkdir(parents=True, exist_ok=True)
            for name in gate.INPUT_FILES:
                (root / name).write_text("actual production/build input")
            source = root / "crates/actor.rs"
            source.write_text("fn actor() {}")
            legacy = root / "spec/gnunet/api/catalog.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{"internal_helper":"pending"}')
            original = gate.implementation_inputs(root)
            legacy.write_text('{"internal_helper":"unmapped"}')
            self.assertEqual(gate.implementation_inputs(root), original)
            legacy.unlink()
            self.assertEqual(gate.implementation_inputs(root), original)
            source.write_text("fn actor() { changed(); }")
            self.assertNotEqual(gate.implementation_inputs(root), original)

    def test_owner_cannot_be_dropped_or_downgraded(self):
        self.invalid_requirement(lambda x: x["required_subsystems"].pop())
        self.invalid_requirement(lambda x: x["required_foundations"].pop())
        self.invalid_requirement(lambda x: x.update(C_helper_mapping_required=True))

    def test_all_numeric_aliases_and_zero_reference_identities_retained(self):
        self.invalid_requirement(lambda x: x["registry_assignments"].pop())
        def dedup(x):
            seen = set()
            x["registry_assignments"] = [r for r in x["registry_assignments"] if r["number"] not in seen and not seen.add(r["number"])]
        self.invalid_requirement(dedup)
        self.assertIn("PSYC_MESSAGE_HEADER", {x["id"] for x in self.req["registry_assignments"]})

    def test_nonregistry_and_zero_token_capabilities_cannot_disappear(self):
        self.invalid_requirement(lambda x: x["nonregistry_obligations"].pop())
        self.invalid_requirement(lambda x: x["unknowns"].__setitem__(slice(None), [r for r in x["unknowns"] if not r["id"].startswith("nonregistry:")]))
        for name in ["src/service/rest/identity_plugin.c", "src/service/transport/gnunet-communicator-http3.c"]:
            self.assertIn(name, self.survey["paths"])

    def test_unknowns_cannot_be_deleted_completed_or_waived(self):
        self.invalid_requirement(lambda x: x["unknowns"].pop())
        self.invalid_requirement(lambda x: x["unknowns"][0].update(status="complete"))
        self.invalid_requirement(lambda x: x.update(complete_semantic_inventory=True))
        self.invalid_requirement(lambda x: x["coverage_policy"].update(unknowns_may_be_waived_by_evidence=True))

    def test_generated_macro_non_C_and_supported_variant_review_remain_blocking(self):
        for suffix in ["generated-non-C", "build-platform-variants", "third-party-negotiation", "submodules-docs"]:
            self.invalid_requirement(lambda x, suffix=suffix: x["unknowns"].__setitem__(slice(None), [r for r in x["unknowns"] if r["id"] != "survey:" + suffix]))

    def test_contract_state_failure_profile_cases_cannot_shrink(self):
        self.invalid_requirement(lambda x: x["case_obligations"].pop())
        self.invalid_requirement(lambda x: x["reviewed_partial_operations"][0]["required_cases"].pop())
        self.invalid_requirement(lambda x: x["reviewed_partial_profiles"][-1]["required_operations"].pop())
        self.invalid_requirement(lambda x: x["case_obligations"][0].update(profile_direction_review="reviewed", evidence_slots=[]))

    def test_false_credit_and_unknown_extra_fields_rejected(self):
        self.invalid_requirement(lambda x: x.update(full_GNUnet_conformance_verified=True))
        r = copy.deepcopy(self.index)
        r["release_ready"] = True
        with self.assertRaises(gate.Invalid):
            gate.evaluate(self.req, r, self.lock["requirements_sha256"], {}, self.survey, gate.ROOT)

    def test_source_survey_is_not_active_or_semantically_complete(self):
        for field in ["compiled_active", "external_semantics_complete", "submodule_contents_reviewed"]:
            s = copy.deepcopy(self.survey)
            s[field] = True
            with self.assertRaises(gate.Invalid):
                gate.validate_requirements(self.req, s, self.schema, self.legacy)

    def test_new_implementation_status_cannot_rewrite_review_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / "release-lock.json").write_text(json.dumps({"schema": 1, "complete": True}))
            with self.assertRaises(gate.Invalid):
                gate.read_requirements(p)

    def test_duplicate_JSON_authority_fields_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "x.json"
            p.write_text('{"result":"fail","result":"pass"}')
            with self.assertRaises(gate.Invalid):
                gate.load_json(p)

    def test_path_escape_absolute_and_directory_aliases_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "file").write_text("raw")
            (root / "alias").symlink_to(root, target_is_directory=True)
            for name in ["../file", "/file", "alias/file", "a//file", "."]:
                with self.assertRaises(gate.Invalid):
                    gate.regular(root, name)

    def test_missing_reference_schema_or_requirement_bytes_are_not_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ["release-lock.json", "release-requirements.json", "release-source-index.json", "release-evidence.schema.json"]:
                (root / name).write_bytes((gate.DATA / name).read_bytes())
            (root / "release-requirements.json").write_text("{}")
            with self.assertRaises(gate.Invalid):
                gate.read_requirements(root)


class ReceiptControls(unittest.TestCase):
    """Synthetic frozen-file fixtures only. No service, network or C proof."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gnunet-external-receipt-")
        self.root = Path(self.tmp.name)
        self.req = copy.deepcopy(ReleaseControls.req)
        self.survey = {"ref.c": {"kind": "file", "sha256": "1" * 64}}
        self.inputs = {"src.rs": "2" * 64}
        for name in ["binary", "loaded", "raw", "observation", "review", "build-config", "build-receipt"]:
            (self.root / name).write_text("synthetic " + name)
        self.script = self.root / "adapter.py"
        self.script.write_text('import sys,json,hashlib\np=sys.argv[sys.argv.index("--receipt")+1]\nprint(json.dumps({"receipt_sha256":hashlib.sha256(open(p,"rb").read()).hexdigest(),"semantic_verdict":"pass"}))\n')
        self.adapter = {"id": "synthetic-test-only", "script": "adapter.py", "sha256": gate.sha(self.script), "review": "synthetic control, no protocol credit"}
        self.receipt = {"schema": 1, "kind": "external-boundary-receipt", "requirement": "core.init-loopback:case:1", "profile": "core-host-selfloop", "direction": "C-to-Rust", "adapter": self.adapter["id"], "result": "pass", "implementation_inputs": self.inputs, "reference_revision": gate.REVISION, "reference_inputs": self.survey, "build": {"profile": "synthetic", "argv": ["test-only"], "toolchain": {"python": "test"}, "binaries": [self.ref("binary")], "inputs": [self.ref("build-config")], "receipt": self.ref("build-receipt")}, "processes": [], "artifacts": [self.ref("raw")], "observation": self.ref("observation"), "review": self.ref("review")}
        profile = next(x for x in self.req["reviewed_partial_profiles"] if x["id"] == "core-host-selfloop")
        for role in profile["required_components"]:
            self.receipt["processes"].append({"role": role, "argv": ["synthetic-test"], "binary": self.ref("binary"), "binary_before": gate.sha(self.root / "binary"), "binary_after": gate.sha(self.root / "binary"), "exit_code": 0, "termination": "exited", "loaded_files_before": {"loaded": gate.sha(self.root / "loaded")}, "loaded_files_after": {"loaded": gate.sha(self.root / "loaded")}})
        self.path = self.root / "receipt.json"

    def tearDown(self):
        self.tmp.cleanup()

    def ref(self, name):
        return {"path": name, "sha256": gate.sha(self.root / name)}

    def verify(self, adapters=True):
        self.path.write_text(json.dumps(self.receipt))
        with patch.object(gate, "ROOT", self.root):
            return gate.verify_receipt(self.receipt, self.path, self.req, self.inputs, self.survey, self.root, {self.adapter["id"]: self.adapter} if adapters else {})

    def rejected(self, mutate):
        mutate(self.receipt)
        with self.assertRaises(gate.Invalid):
            self.verify()

    def test_synthetic_integrity_fixture_checks_exact_frozen_receipt(self):
        self.assertEqual(self.verify(), ("core.init-loopback:case:1", "core-host-selfloop", "C-to-Rust"))

    def test_draft_FS_receipt_cannot_impersonate_reviewed_case_or_profile(self):
        self.rejected(lambda x: x.update(requirement="fs:uri-chk:case:1", profile="fs-artifact-uri"))

    def test_raw_pass_without_reviewed_adapter_never_awards_credit(self):
        with self.assertRaises(gate.Invalid):
            self.verify(adapters=False)

    def test_current_gate_registers_no_historical_receipt_as_current(self):
        self.assertEqual(self.req["evidence_adapters"], [])
        self.assertEqual(ReleaseControls.index["records"], [])

    def test_old_or_partial_implementation_source_map_rejected(self):
        self.rejected(lambda x: x.update(implementation_inputs={}))

    def test_reference_revision_and_full_reference_map_are_required(self):
        self.rejected(lambda x: x.update(reference_revision="old"))
        self.receipt["reference_revision"] = gate.REVISION
        self.rejected(lambda x: x.update(reference_inputs={}))

    def test_actual_binary_drift_cannot_be_relabelled_as_same_actor(self):
        self.rejected(lambda x: x["processes"][0].update(binary_after="0" * 64))

    def test_loaded_file_drift_is_not_success(self):
        self.rejected(lambda x: x["processes"][0].update(loaded_files_after={}))

    def test_failure_force_or_live_actor_invalidates_passing_receipt(self):
        self.rejected(lambda x: x["processes"][0].update(exit_code=-11))
        self.receipt["processes"][0]["exit_code"] = 0
        self.rejected(lambda x: x["processes"][0].update(termination="forced"))

    def test_duplicate_or_missing_roles_and_C_substitution_rejected(self):
        self.rejected(lambda x: x["processes"].append(copy.deepcopy(x["processes"][0])))
        self.receipt["processes"].pop()
        self.rejected(lambda x: x["processes"].pop())

    def test_forbidden_data_plane_substitution_rejected(self):
        p = copy.deepcopy(self.receipt["processes"][0]);p["role"] = "mock-core-service"
        self.rejected(lambda x: x["processes"].append(p))

    def test_artifact_tamper_missing_review_and_empty_build_rejected(self):
        (self.root / "raw").write_text("changed")
        with self.assertRaises(gate.Invalid):
            self.verify()
        self.receipt["artifacts"] = [self.ref("raw")]
        (self.root / "review").unlink()
        with self.assertRaises(gate.Invalid):
            self.verify()

    def test_unbound_adapter_source_rejected(self):
        self.script.write_text("print('pass')")
        with self.assertRaises(gate.Invalid):
            self.verify()

    def test_wrong_profile_unknown_direction_and_case_rejected(self):
        self.rejected(lambda x: x.update(direction="C-ABI-helper"))
        self.receipt["direction"] = "C-to-Rust"
        self.rejected(lambda x: x.update(requirement="new-private-capability"))

    def test_boolean_schema_cannot_impersonate_numeric_version(self):
        self.rejected(lambda x: x.update(schema=True))

    def test_duplicate_case_direction_does_not_inflate_coverage(self):
        self.verify()
        self.req["evidence_adapters"] = [self.adapter]
        index = {"schema": 1, "kind": "external-release-evidence-index", "requirements_sha256": "a" * 64,
                 "records": [self.ref("receipt.json"), self.ref("receipt.json")]}
        with patch.object(gate, "ROOT", self.root):
            with self.assertRaises(gate.Invalid):
                gate.evaluate(self.req, index, "a" * 64, self.inputs, {"paths": self.survey}, self.root)

    def test_empty_build_provenance_does_not_pass(self):
        self.rejected(lambda x: x["build"].update(argv=[]))

    def test_evidence_cannot_bind_to_another_requirement_version(self):
        index = copy.deepcopy(ReleaseControls.index)
        index["requirements_sha256"] = "0" * 64
        with self.assertRaises(gate.Invalid):
            gate.evaluate(self.req, index, ReleaseControls.lock["requirements_sha256"], self.inputs, {"paths": self.survey}, self.root)

    def test_generated_configuration_or_dependency_drift_rejected(self):
        (self.root / "build-config").write_text("new configuration")
        with self.assertRaises(gate.Invalid):
            self.verify()

    def test_missing_actual_build_receipt_rejected(self):
        (self.root / "build-receipt").unlink()
        with self.assertRaises(gate.Invalid):
            self.verify()

    def test_empty_generated_build_input_map_rejected(self):
        self.rejected(lambda x: x["build"].update(inputs=[]))

    def test_duplicate_semantic_verdict_fields_rejected(self):
        with self.assertRaises(gate.Invalid):
            gate.decode_json('{"semantic_verdict":"fail","semantic_verdict":"pass"}')

    def test_unknown_receipt_credit_fields_rejected(self):
        self.rejected(lambda x: x.update(full_GNUnet_conformance_verified=True))



class SemanticDraftControls(unittest.TestCase):
    """Actual pending catalog mutations; no protocol/runtime completion proof."""
    @classmethod
    def setUpClass(cls):
        cls.req, cls.survey, cls.schema, cls.lock = gate.read_requirements()
        cls.legacy = gate.read_data()
        cls.path = gate.DATA / cls.req["semantic_inventories"][0]["path"]
        cls.inventory = gate.load_json(cls.path)

    def invalid_inventory(self, mutate):
        row = copy.deepcopy(self.inventory)
        mutate(row)
        with self.assertRaises(gate.Invalid):
            gate.validate_inventory(row, self.req["registry_assignments"], self.survey["paths"], gate.REVISION, gate.DIRECTIONS)

    def test_canonical_draft_counts_and_original_floor_are_distinct(self):
        gate.validate_requirements(self.req, self.survey, self.schema, self.legacy)
        rows = gate.semantic_summaries(self.req, self.survey)
        self.assertEqual(len(rows), 1)
        self.assertEqual((len(rows[0]["draft_operations"]), len(rows[0]["draft_cases"]), len(rows[0]["draft_profiles"]), len(rows[0]["draft_registry_classifications"])), (38, 147, 18, 23))
        self.assertEqual(len(self.req["unknowns"]), 734)
        self.assertEqual(len(self.req["case_obligations"]), 156)
        self.assertEqual(self.req["evidence_adapters"], [])

    def test_draft_review_and_owner_complete_claims_are_rejected(self):
        self.invalid_inventory(lambda x: x.update(review_state="reviewed"))
        self.invalid_inventory(lambda x: x.update(owner_review_complete=True))
        self.invalid_inventory(lambda x: x.update(full_GNUnet_conformance_verified=True))

    def test_case_operation_profile_and_registry_cannot_self_review(self):
        for key in ["operations", "cases", "profiles", "registry_classifications"]:
            self.invalid_inventory(lambda x, key=key: x[key][0].update(review_state="reviewed"))
        self.invalid_inventory(lambda x: x["cases"][0].update(profile_direction_review="reviewed"))
        self.invalid_inventory(lambda x: x["cases"][0].update(evidence_slots=[{"profile": "fs-artifact-uri", "direction": "artifact"}]))

    def test_missing_sources_wrong_hash_unknown_path_and_invalid_line_are_rejected(self):
        self.invalid_inventory(lambda x: x["operations"][0].update(source_refs=[]))
        self.invalid_inventory(lambda x: x["operations"][0]["source_refs"][0].update(sha256="0" * 64))
        self.invalid_inventory(lambda x: x["operations"][0]["source_refs"][0].update(path="src/unknown.c"))
        self.invalid_inventory(lambda x: x["operations"][0]["source_refs"][0].update(start_line=True))
        self.invalid_inventory(lambda x: x["operations"][0]["source_refs"][0].update(start_line=100, end_line=1))

    def test_actual_missing_or_changed_original_source_is_rejected(self):
        from semantic import source_ref
        row = copy.deepcopy(self.inventory["operations"][0]["source_refs"][0])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(gate.Invalid):
                source_ref(row, self.survey["paths"], root)
            target = root / row["path"]
            target.parent.mkdir(parents=True)
            target.write_text("changed original source")
            with self.assertRaises(gate.Invalid):
                source_ref(row, self.survey["paths"], root)

    def test_actual_source_anchor_and_alias_are_checked(self):
        from semantic import source_ref
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "src.c"
            target.write_text("first\nactual-anchor\n")
            row = {"path": "src.c", "sha256": gate.sha(target), "start_line": 2, "end_line": 2, "anchor": "actual-anchor"}
            survey = {"src.c": {"kind": "file", "sha256": gate.sha(target)}}
            source_ref(row, survey, root)
            row["anchor"] = "invented-anchor"
            with self.assertRaises(gate.Invalid):
                source_ref(row, survey, root)
            row["anchor"] = "actual-anchor"
            target.rename(root / "real.c")
            target.symlink_to(root / "real.c")
            with self.assertRaises(gate.Invalid):
                source_ref(row, survey, root)

    def test_omitted_registry_case_operation_and_profile_are_rejected(self):
        for key in ["registry_classifications", "cases", "operations", "profiles"]:
            self.invalid_inventory(lambda x, key=key: x[key].pop())

    def test_duplicate_identity_and_numeric_assignment_tamper_are_rejected(self):
        self.invalid_inventory(lambda x: x["cases"].append(copy.deepcopy(x["cases"][0])))
        self.invalid_inventory(lambda x: x["registry_classifications"][0].update(number=True))
        self.invalid_inventory(lambda x: x["registry_classifications"][0].update(number=65535))
        self.invalid_inventory(lambda x: x["registry_classifications"][0].update(unknown_obligation="owner:fs"))

    def test_wrong_profile_direction_and_case_membership_are_rejected(self):
        self.invalid_inventory(lambda x: x["cases"][0].update(profile_candidates=["fs-invented"]))
        self.invalid_inventory(lambda x: x["profiles"][0].update(candidate_directions=["C-ABI-helper"]))
        self.invalid_inventory(lambda x: x["profiles"][0]["required_operations"].pop())
        self.invalid_inventory(lambda x: x["operations"][0]["case_ids"].pop())
        self.invalid_inventory(lambda x: x["cases"][0].update(operation="fs:foreign"))

    def test_normative_inventory_file_tamper_missing_and_requirement_omission_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            row = self.req["semantic_inventories"][0]
            target = root / row["path"]
            target.parent.mkdir(parents=True)
            target.write_text("{}")
            with self.assertRaises(gate.Invalid):
                gate.semantic_summaries(self.req, self.survey, root)
            target.unlink()
            with self.assertRaises(gate.Invalid):
                gate.semantic_summaries(self.req, self.survey, root)
        changed = copy.deepcopy(self.req)
        changed["semantic_inventories"] = []
        with self.assertRaises(gate.Invalid):
            gate.validate_requirements(changed, self.survey, self.schema, self.legacy)

    def test_rehashed_catalog_cannot_change_trusted_requirement_reference(self):
        changed = copy.deepcopy(self.req)
        changed["semantic_inventories"][0]["sha256"] = "0" * 64
        with self.assertRaises(gate.Invalid):
            gate.validate_requirements(changed, self.survey, self.schema, self.legacy)

    def test_historical_stage1_is_readable_but_not_a_canonical_downgrade(self):
        history = gate.DATA / "history/stage1"
        req, survey, schema, lock = gate.read_requirements(history, historical=True)
        self.assertEqual(req["schema"], 1)
        self.assertEqual(len(gate.validate_requirements(req, survey, schema, self.legacy, history)), 156)
        with self.assertRaises(gate.Invalid):
            gate.read_requirements(history)
        report = gate.evaluate(req, gate.load_json(history / "release-evidence.json"), lock["requirements_sha256"], {}, survey, gate.ROOT, history)
        self.assertEqual((len(report["unknown_contracts"]), len(report["pending_cases"]), report["semantic_inventories"]), (734, 156, 0))
        with self.assertRaises(gate.Invalid):
            gate.require_release(report)

    def test_unknowns_and_pending_slots_derive_readiness_instead_of_status_credit(self):
        self.assertEqual(gate.release_state(["owner:fs"], [], [], True), (False, False))
        self.assertEqual(gate.release_state([], ["case"], [], True), (True, False))
        self.assertEqual(gate.release_state([], [], ["draft-profile"], True), (False, False))
        self.assertEqual(gate.release_state([], [], [], False), (True, False))
        # Predicate control only: production first validates the preserved floor,
        # review authority and every actual receipt. This is no protocol proof.
        self.assertEqual(gate.release_state([], [], [], True), (True, True))

    def test_optional_helper_does_not_erase_required_extraction_or_unknowns(self):
        operations = {x["id"]: x for x in self.inventory["operations"]}
        self.assertEqual(operations["fs:optional-helper-ipc"]["necessity"], "selected-external-boundary")
        self.assertEqual(operations["fs:scan-extract"]["necessity"], "always")
        self.assertEqual(len([x for x in self.inventory["registry_classifications"] if x["id"].startswith("FS_PUBLISH_HELPER_")]), 7)
        self.assertEqual(len([x for x in self.req["unknowns"] if x["id"].startswith("registry:FS_PUBLISH_HELPER_")]), 7)

    def test_conditional_helper_nonselection_cannot_self_waive_review(self):
        row = next(x for x in self.inventory["profiles"] if x["id"] == "fs-optional-official-helper")
        self.assertEqual(row["review_state"], "draft")
        def claim_nonselection(value):
            profile = next(x for x in value["profiles"] if x["id"] == "fs-optional-official-helper")
            profile["selection_state"] = "not-selected"
        self.invalid_inventory(claim_nonselection)
        def erase_condition(value):
            operation = next(x for x in value["operations"] if x["id"] == "fs:optional-helper-ipc")
            operation["condition"] = ""
        self.invalid_inventory(erase_condition)
        report = gate.evaluate(self.req, gate.load_json(gate.DATA / "release-evidence.json"), self.lock["requirements_sha256"], {}, self.survey, gate.ROOT)
        self.assertEqual(report["conditional_draft_operations"], ["fs:optional-helper-ipc"])
        self.assertEqual(len(report["conditional_draft_cases"]), 4)
        self.assertTrue(set(report["conditional_draft_cases"]) <= set(report["pending_cases"]))
        self.assertEqual(len(report["unknown_contracts"]), 734)
        self.assertFalse(report["release_ready"])

    def test_malformed_cross_reference_targets_are_refused_before_following(self):
        self.invalid_inventory(lambda x: x["profiles"][0].update(required_operations=None))
        self.invalid_inventory(lambda x: x["cases"][0].update(operation=[]))
        self.invalid_inventory(lambda x: x["cases"][0].pop("operation"))
        self.invalid_inventory(lambda x: x["cases"][0].update(profile_candidates="fs-artifact-uri"))

    def test_boolean_inventory_schema_is_not_numeric_version(self):
        self.invalid_inventory(lambda x: x.update(schema=True))


if __name__ == "__main__":
    # Load shared baseline even when unittest sorts ReceiptControls first.
    ReleaseControls.setUpClass()
    unittest.main()
