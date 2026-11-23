#!/usr/bin/env python3
"""Local controls for gate integrity, not GNUnet interoperability evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release as gate
import statistics_watch_initial as watch
import statistics_watch_receipt as watch_receipt


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


class ReceiptFixture(unittest.TestCase):
    """Synthetic frozen-file fixtures for receipt controls."""
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
        self.case = next(x for x in self.req["case_obligations"] if x["id"] == self.receipt["requirement"])
        self.case["profile_direction_review"] = "reviewed"
        self.case["evidence_slots"] = [{key: self.receipt[key] for key in ("profile", "direction", "adapter")}]
        profile = next(x for x in self.req["reviewed_partial_profiles"] if x["id"] == "core-host-selfloop")
        for role in profile["required_components"]:
            self.receipt["processes"].append({"role": role, "argv": ["synthetic-test"], "binary": self.ref("binary"), "binary_before": gate.sha(self.root / "binary"), "binary_after": gate.sha(self.root / "binary"), "exit_code": 0, "termination": "exited", "loaded_files_before": {"loaded": gate.sha(self.root / "loaded")}, "loaded_files_after": {"loaded": gate.sha(self.root / "loaded")}})
        self.path = self.root / "receipt.json"

    def tearDown(self):
        self.tmp.cleanup()

    def ref(self, name):
        return {"path": name, "sha256": gate.sha(self.root / name)}


class ReceiptControls(ReceiptFixture):
    def verify(self, adapters=True):
        raw = json.dumps(self.receipt).encode()
        self.path.write_bytes(raw)
        with patch.object(gate, "ROOT", self.root):
            return gate.verify_receipt(raw, self.path, self.req, self.inputs, self.survey, self.root, {self.adapter["id"]: self.adapter} if adapters else {})

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

    def test_process_image_must_match_a_built_binary(self):
        image = self.ref("observation")
        self.receipt["processes"][0].update(binary=image, binary_before=image["sha256"],
                                            binary_after=image["sha256"])
        with self.assertRaisesRegex(gate.Invalid, "absent from the build provenance"):
            self.verify()

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

    def test_pending_case_cannot_receive_evidence(self):
        self.case["profile_direction_review"] = "pending"
        with self.assertRaisesRegex(gate.Invalid, "no reviewed evidence slot"):
            self.verify()

    def test_reviewed_slot_does_not_allow_another_valid_direction_or_adapter(self):
        self.receipt["direction"] = "Rust-to-C"
        with self.assertRaisesRegex(gate.Invalid, "no reviewed evidence slot"):
            self.verify()
        self.receipt["direction"] = "C-to-Rust"
        # Even a registered and pinned adapter can only verify its reviewed slot.
        self.adapter["id"] = self.receipt["adapter"] = "another-adapter"
        with self.assertRaisesRegex(gate.Invalid, "no reviewed evidence slot"):
            self.verify()

    def test_boolean_schema_cannot_impersonate_numeric_version(self):
        self.rejected(lambda x: x.update(schema=True))

    def test_duplicate_case_direction_does_not_inflate_coverage(self):
        self.survey = ReleaseControls.survey["paths"]
        self.receipt["reference_inputs"] = self.survey
        self.verify()
        self.req["evidence_adapters"] = [self.adapter]
        index = {"schema": 1, "kind": "external-release-evidence-index", "requirements_sha256": "a" * 64,
                 "records": [self.ref("receipt.json"), self.ref("receipt.json")]}
        with patch.object(gate, "ROOT", self.root):
            with self.assertRaisesRegex(gate.Invalid, "duplicate evidence receipt"):
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


class ReviewedCatalogControls(ReceiptFixture):
    """Synthetic catalog fixtures, isolated from canonical approval."""

    def setUp(self):
        super().setUp()
        operation_id = "statistics.synthetic-observation"
        profile_id = "synthetic-profile"
        self.case_id = operation_id + ":case:1"
        self.baseline = copy.deepcopy(ReleaseControls.req)
        self.catalog_survey = copy.deepcopy(ReleaseControls.survey)
        self.catalog_survey["paths"].update(self.survey)
        self.catalog = {
            "schema": 1, "kind": "external-release-review-catalog",
            "stage2_lock_sha256": gate.RELEASE_LOCK_SHA256, "reference_revision": gate.REVISION,
            "operations": [{
                "id": operation_id, "owner": "statistics", "contract": "Synthetic operation",
                "source_refs": [{"path": "ref.c", "sha256": self.survey["ref.c"]["sha256"],
                                 "start_line": 1, "end_line": 1, "anchor": "fixture"}],
            }],
            "profiles": [{
                "id": profile_id, "required_operations": [operation_id],
                "required_components": [row["role"] for row in self.receipt["processes"]],
                "forbidden_data_plane_substitutions": ["synthetic-forbidden-role"],
            }],
            "cases": [{
                "id": self.case_id, "operation": operation_id, "contract": "Synthetic case",
                "evidence_slots": [{"profile": profile_id, "direction": self.receipt["direction"],
                                    "adapter": self.adapter["id"]}],
            }],
            "adapters": [self.adapter],
        }
        self.receipt.update(requirement=self.case_id, profile=profile_id,
                            reference_inputs=self.catalog_survey["paths"])
        for row in self.baseline["semantic_inventories"]:
            destination = self.root / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((gate.DATA / row["path"]).read_bytes())
        self.catalog_path = self.root / gate.REVIEW_CATALOG_NAME

    def evaluate_catalog(self, records=(), pinned=True, expected_digest=None):
        self.catalog_path.write_text(json.dumps(self.catalog))
        pin = (expected_digest or gate.sha(self.catalog_path)) if pinned else None
        evidence = dict(ReleaseControls.index, records=list(records))
        with patch.object(gate, "ROOT", self.root), patch.object(gate, "REVIEW_CATALOG_SHA256", pin):
            return gate.evaluate(self.baseline, evidence, ReleaseControls.lock["requirements_sha256"],
                                 self.inputs, self.catalog_survey, self.root, self.root)

    def test_review_catalog_cannot_self_pin_even_if_its_evidence_is_provided(self):
        report = self.evaluate_catalog(pinned=False)
        self.assertNotIn("reviewed_additions", report)
        self.assertNotIn(self.case_id, report["pending_cases"])
        self.path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(gate.Invalid, "unknown case/direction"):
            self.evaluate_catalog([self.ref(self.path.name)], pinned=False)

    def test_pinned_catalog_authorizes_exact_evidence_without_displacing_the_floor(self):
        pending = self.evaluate_catalog()
        self.assertIn(self.case_id, pending["pending_cases"])
        self.assertEqual(pending["reviewed_additions"]["cases"], [self.case_id])
        self.path.write_text(json.dumps(self.receipt))
        report = self.evaluate_catalog([self.ref(self.path.name)])
        self.assertEqual(report["integrity_checked_receipts"], 1)
        self.assertEqual(report["pending_cases"], [x for x in pending["pending_cases"] if x != self.case_id])
        self.assertEqual(report["unknown_contracts"], [x["id"] for x in self.baseline["unknowns"]])
        self.assertEqual(report["retained_state_failure_cases"], len(self.baseline["case_obligations"]))
        self.assertEqual(self.baseline, ReleaseControls.req)
        self.assertFalse(report["release_ready"])
        self.receipt["direction"] = "Rust-to-C"
        self.path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(gate.Invalid, "no reviewed evidence slot"):
            self.evaluate_catalog([self.ref(self.path.name)])

    def test_catalog_rejects_wrong_pin_wrong_baseline_and_waiver(self):
        with self.assertRaisesRegex(gate.Invalid, "digest mismatch"):
            self.evaluate_catalog(expected_digest="1" * 64)
        self.catalog["stage2_lock_sha256"] = "1" * 64
        with self.assertRaisesRegex(gate.Invalid, "different release baseline"):
            self.evaluate_catalog()
        self.catalog["stage2_lock_sha256"] = gate.RELEASE_LOCK_SHA256
        self.catalog["unknowns"] = []
        with self.assertRaisesRegex(gate.Invalid, "invalid fields: review catalog"):
            self.evaluate_catalog()

    def test_catalog_rejects_legacy_and_draft_identity_collisions(self):
        operation = self.catalog["operations"][0]
        operation["id"] = self.baseline["reviewed_partial_operations"][0]["id"]
        with self.assertRaisesRegex(gate.Invalid, "reuses an existing identity"):
            self.evaluate_catalog()
        operation["id"] = gate.semantic_summaries(self.baseline, self.catalog_survey)[0]["draft_operations"][0]
        with self.assertRaisesRegex(gate.Invalid, "reuses an existing identity"):
            self.evaluate_catalog()

    def test_catalog_requires_compatible_reachable_profiles_slots_and_adapters(self):
        slot = self.catalog["cases"][0]["evidence_slots"][0]
        profile = self.catalog["profiles"][0]
        self.catalog["profiles"].append(dict(profile, id="unused-profile"))
        with self.assertRaisesRegex(gate.Invalid, "unreachable authority"):
            self.evaluate_catalog()
        self.catalog["profiles"].pop()
        self.catalog["cases"][0]["evidence_slots"].append(dict(slot))
        with self.assertRaisesRegex(gate.Invalid, "duplicate reviewed evidence slot"):
            self.evaluate_catalog()
        self.catalog["cases"][0]["evidence_slots"].pop()
        slot["adapter"] = "absent"
        with self.assertRaisesRegex(gate.Invalid, "unrelated profile, direction or adapter"):
            self.evaluate_catalog()

    def test_catalog_checks_original_source_and_adapter_pins_before_any_receipt(self):
        ref = self.catalog["operations"][0]["source_refs"][0]
        original = ref["sha256"]
        ref["sha256"] = "0" * 64
        with self.assertRaisesRegex(gate.Invalid, "absent or hash differs"):
            self.evaluate_catalog()
        ref["sha256"] = original
        self.script.write_text("print('changed adapter')")
        with self.assertRaisesRegex(gate.Invalid, "digest mismatch"):
            self.evaluate_catalog()



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
        with patch.object(gate, "REVIEW_CATALOG_SHA256", "a" * 64):
            report = gate.evaluate(req, gate.load_json(history / "release-evidence.json"),
                                   lock["requirements_sha256"], {}, survey, gate.ROOT, history)
        self.assertNotIn("reviewed_additions", report)
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


class StatisticsWatchControls(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.directory = self.root / "run"
        self.directory.mkdir()
        self.artifacts = []
        self.configuration = self.retain("watch-initial.conf", b"""[statistics]
UNIXPATH = /private/run/watch.sock
DATABASE = /private/run/watch.dat
HOSTNAME = localhost
PORT = 0
START_ON_DEMAND = NO
UNIX_MATCH_UID = YES
DISABLE_SOCKET_FORWARDING = YES
""")
        self.fixture = self.retain("watch-initial-input.dat",
                                   b"\x00\x27\x00\xa8\x00\x00\x00\x02" + (55).to_bytes(8, "big")
                                   + b"rust-c-interop\x00counter\x00")
        common = ["-c", "/private/run/watch.conf", "-L", "ERROR"]
        self.rust = self.actor(watch.ROLES[0], "rust_service", common,
                               b"READY statistics persistence=official-set-snapshot\n", [])
        libs = [("libgnunetutil.so.1", "3" * 64), ("libgnunetstatistics.so.1", "4" * 64)]
        watcher_argv = common + ["-q", "-w", "-s", "rust-c-interop", "-n", "counter"]
        self.client = self.actor(watch.ROLES[1], "c_client", watcher_argv, b"55\r\n", libs)
        rows, processes, participants = zip(self.rust, self.client)
        participants = dict(zip(("rust_service", "c_client"), participants))
        upstream = {"revision": gate.REVISION, "tracked_sources_clean": True}
        c = {"kind": "unmodified-official-c-reference-build", "status": "passed", "source_unchanged": True,
             "host": {"system": "Linux"}, "upstream": upstream, "artifacts": {"client": {
                 "sha256": participants["c_client"]["sha256"], "path": participants["c_client"]["original"]}},
             "commands": [{"name": "meson-build", "argv": ["meson", "compile", "gnunet-statistics"], "exit_code": 0}],
             "generated_config": {"sha256": "5" * 64}, "libraries": [
                 {"path": "/c/lib/" + path, "sha256": digest} for path, digest in libs]}
        frozen_build = self.retain("reference-build.json", json.dumps(c).encode())
        compiled = [
            {"reason": "compiler-artifact", "fresh": False, "executable": "/original/rust_service",
             "target": {"name": "gnunet-service-statistics", "kind": ["bin"],
                        "src_path": "/repo/apps/gnunet-service-statistics/src/main.rs"}},
            {"reason": "build-finished", "success": True},
        ]
        cargo = self.retain("cargo.jsonl", b"\n".join(json.dumps(row).encode() for row in compiled))
        self.run = {"schema": 1, "kind": "official-c-statistics-daemon-ipc", "selected_profile": "watch-initial-only",
                    "status": "passed", "cleanup_errors": [], "owned_processes_reaped": True, "owned_runtime_removed": True,
                    "diagnostics": {"commands": []}, "owned_runtime": "/private/run", "upstream": upstream,
                    "input_fingerprints": {"source_files": [{"path": "source.rs", "sha256": "1" * 64}], "spec_files": []},
                    "commands": list(rows), "participants": participants, "persistent_dumps": [self.fixture],
                    "retained_reference_receipt": frozen_build,
                    "configurations": {"/private/run/watch.conf": self.configuration},
                    "linux_image_capture": {"status": "matched-long-lived-actors",
                                            "matched_long_lived": [row["stdout"] for row in rows],
                                            "unobserved_one_shot": [], "excluded_diagnostic": [], "failures": []}}
        self.run.update(dict.fromkeys(("source_unchanged", "reference_unchanged", "reference_receipt_unchanged",
            "reference_runtime_inputs_unchanged", "configurations_unchanged", "participants_unchanged",
            "persistent_dumps_unchanged"), True))
        self.receipt = {"requirement": watch.CASE, "profile": watch.PROFILE, "adapter": watch.ADAPTER,
                        "direction": "C-to-Rust", "reference_revision": gate.REVISION,
                        "implementation_inputs": {"source.rs": "1" * 64},
                        "artifacts": self.artifacts, "processes": processes,
                        "build": {"argv": ["cargo", "build", "--locked", "-p", "gnunet-service-statistics"],
                                  "inputs": [{"sha256": "5" * 64}], "receipt": self.prefixed(cargo)}}

    def prefixed(self, ref):
        return {**ref, "path": "run/" + ref["path"]}

    def retain(self, name, data):
        (self.directory / name).write_bytes(data)
        reference = {"path": name, "sha256": watch.sha(data)}
        self.artifacts.append(self.prefixed(reference))
        return reference

    def actor(self, role, key, argv, stdout, libraries):
        start = "/snapshot/" + key
        binary = {"path": key + ".image", "sha256": watch.sha(key.encode())}
        maps = [{"device": [0, 1], "inode": i, "mapped_path": path, "artifact": ref}
                for i, (path, ref) in enumerate([(start, binary)] + [
                    ("/lib/" + path, {"path": path + ".image", "sha256": digest})
                    for path, digest in libraries], 2)]
        dependencies = {entry["artifact"]["path"]: entry["artifact"]["sha256"] for entry in maps[1:]}
        phase = {"binary": binary, "mapped_files": maps, "loaded_files": dependencies}
        out, err = self.retain(key + ".out", stdout), self.retain(key + ".err", b"")
        row = {"name": role, "argv": [start, *argv], "pid": 1 + len(self.artifacts),
               "configuration": self.configuration, "owned_process_group": True, "one_shot": False,
               "diagnostic": False, "exit_code": 0, "ready_images": phase, "pre_stop_images": copy.deepcopy(phase),
               "stdout": out["path"], "stderr": err["path"], "stdout_sha256": out["sha256"], "stderr_sha256": err["sha256"]}
        receipt_deps = {"run/" + path: digest for path, digest in dependencies.items()}
        process = {"role": role, "argv": row["argv"], "binary": self.prefixed(binary),
                   "binary_before": binary["sha256"], "binary_after": binary["sha256"],
                   "loaded_files_before": receipt_deps, "loaded_files_after": receipt_deps}
        participant = {"original": "/original/" + key, "snapshot": start, "sha256": binary["sha256"]}
        return row, process, participant

    def evaluate(self):
        run = self.retain("result.json", json.dumps(self.run).encode())
        self.receipt["observation"] = self.prefixed(run)
        watch.verify(self.root, self.receipt)

    def test_synthetic_frozen_profile_validates_the_join(self):
        self.evaluate()

    def test_pass_labels_do_not_cover_missing_or_drifted_actor_images(self):
        self.client[0]["pre_stop_images"] = {"unavailable": "owner exited early"}
        with self.assertRaisesRegex(ValueError, "mappings changed"):
            self.evaluate()

    def test_pass_labels_do_not_cover_incorrect_watch_output(self):
        different = self.retain("different-value.out", b"56\r\n")
        self.client[0].update(stdout=different["path"], stdout_sha256=different["sha256"])
        self.run["linux_image_capture"]["matched_long_lived"][1] = different["path"]
        with self.assertRaisesRegex(ValueError, "expected one WATCH value"):
            self.evaluate()

    def assembly_inputs(self):
        directory = self.root / "build"
        directory.mkdir()

        def bind(name, raw):
            path = directory / name
            path.write_bytes(raw)
            return watch_receipt.regular_ref(path)

        host = {"system": "Linux", "machine": "x86_64"}
        input_map = {"source.rs": "1" * 64, "Cargo.lock": "6" * 64}
        self.run["input_fingerprints"]["source_files"].append({"path": "Cargo.lock", "sha256": "6" * 64})
        c = watch.decode((self.directory / self.run["retained_reference_receipt"]["path"]).read_bytes())
        c["host"] = host
        c["source"] = str(self.root / "official-source")
        for row, _, participant in (self.rust, self.client):
            tag = row["name"]
            image = b"\x7fELF synthetic " + tag.encode()
            artifact = bind(tag, image)
            participant.update(original=artifact["path"], sha256=artifact["sha256"])
            epoch = row["ready_images"]
            binary = epoch["binary"]
            binary.update(self.retain(binary["path"], image))
            row["pre_stop_images"] = copy.deepcopy(epoch)
        # Each frozen dependency must have a real retained file at its declared digest.
        for epoch in (self.client[0]["ready_images"], self.client[0]["pre_stop_images"]):
            for entry, library in zip(epoch["mapped_files"][1:], c["libraries"]):
                path = entry["artifact"]["path"]
                ref = self.retain(path, path.encode())
                entry["artifact"] = ref
                epoch["loaded_files"][path] = library["sha256"] = ref["sha256"]
        c_bin = self.client[2]
        c["artifacts"]["client"] = {
            "path": c_bin["original"], "sha256": c_bin["sha256"],
            "built_path": bind("meson-built-cli", Path(c_bin["original"]).read_bytes())["path"],
        }
        c["generated_config"] = bind("gnunet_private_config.h", b"synthetic generated header")
        (command,) = c["commands"]
        log = bind("meson.log", b"synthetic compiler log")
        command.update(log=log["path"], log_sha256=log["sha256"])
        c["commands"].append(dict(command, name="meson-setup"))
        c["tool_versions"] = [dict(command, name=name) for name in ("meson-version", "compiler-version")]
        c["default_configurations"] = []
        for library in c["libraries"]:
            library["symlink"] = True
        self.run["retained_reference_receipt"] = self.retain("reference-build.json", json.dumps(c).encode())
        target = "x86_64-unknown-linux-gnu"
        rust_bin = self.rust[2]
        cargo_log = bind("cargo.jsonl", b"\n".join(json.dumps(row).encode() for row in [
            {"reason": "compiler-artifact", "fresh": False, "executable": rust_bin["original"],
             "target": {"name": "gnunet-service-statistics", "kind": ["bin"],
                        "src_path": "/repo/apps/gnunet-service-statistics/src/main.rs"}},
            {"reason": "build-finished", "success": True},
        ]))
        rust = {
            "schema": 1, "kind": watch_receipt.BUILD_KIND, "host": host, "exit_code": 0, "source_inputs": input_map,
            "argv": ["cargo", "build", "--locked", "-p", "gnunet-service-statistics", "--target", target],
            "binary": {"path": rust_bin["original"], "sha256": rust_bin["sha256"]},
            "lockfile": {"path": str(gate.ROOT / "Cargo.lock"), "sha256": "6" * 64},
            "cargo_log": cargo_log, "cargo_stderr": bind("cargo.err", b""),
            "compiler": bind("rustc.txt", f"host: {target}\nrelease: synthetic\ncommit-hash: synthetic\n".encode()),
        }
        rust_path = Path(bind("rust-build.json", json.dumps(rust).encode())["path"])
        review = Path(bind("review.txt", b"Review pending")["path"])
        self.retain("result.json", json.dumps(self.run).encode())
        return input_map, rust_path, review

    def assemble_candidate(self, source, build, review, output):
        reference = {"tracked.c": {"kind": "file", "sha256": "1" * 64}}
        with patch.object(gate, "implementation_inputs", return_value=source), \
                patch.object(gate, "tracked_inputs", return_value=reference), \
                patch.object(gate, "read_requirements", return_value=(None, {"paths": reference}, None, None)):
            watch_receipt.assemble(self.root, self.directory / "result.json", build, review,
                                   self.root / "official-source", output)

    def test_assembly_keeps_validated_bytes_under_a_pending_review_wrapper(self):
        source, build, review = self.assembly_inputs()
        output = self.root / "candidate.json"
        self.assemble_candidate(source, build, review, output)
        candidate = json.loads(output.read_bytes())
        self.assertEqual((candidate["kind"], candidate["review_state"]),
                         ("external-boundary-review-candidate", "pending"))
        self.assertEqual(candidate["receipt"]["requirement"], watch.CASE)
        self.assertEqual({row["role"] for row in candidate["receipt"]["processes"]}, set(watch.ROLES))
        with self.assertRaises(FileExistsError):
            self.assemble_candidate(source, build, review, output)

    def test_assembly_refuses_a_changed_live_dependency_without_output(self):
        source, build, review = self.assembly_inputs()
        ready = self.client[0]["ready_images"]
        path = next(iter(ready["loaded_files"]))
        (self.directory / path).write_bytes(b"mutated mapped file")
        output = self.root / "candidate.json"
        with self.assertRaisesRegex(gate.Invalid, "digest mismatch"):
            self.assemble_candidate(source, build, review, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    # Load shared baseline even when unittest sorts ReceiptControls first.
    ReleaseControls.setUpClass()
    unittest.main()
