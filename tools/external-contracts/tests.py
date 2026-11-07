#!/usr/bin/env python3
"""Omission, false-credit and real source-discovery controls for the draft gate."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scan import discover, registry
from verify import Invalid, ROOT, read_data, require_complete, topology, validate


class InventoryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = read_data()
        cls.ledger = json.loads((ROOT / "spec/gnunet/conformance.json").read_text())

    def rejected(self, part, change):
        values = copy.deepcopy(self.base)
        change(values[part])
        with self.assertRaises(Invalid):
            validate(*values, ledger=self.ledger)

    def test_consistent_draft_keeps_full_scope_but_awards_no_credit(self):
        report = validate(*self.base, ledger=self.ledger)
        self.assertEqual((report["full_required_subsystems"], report["full_required_foundations"]), (34, 8))
        self.assertEqual(report["registry_assignments"], 677)
        self.assertFalse(report["complete_semantic_inventory"])
        self.assertFalse(report["full_GNUnet_conformance_verified"])
        self.assertFalse(report["awards_implementation_or_verification_credit"])
        self.assertFalse(report["reference_source_checked"])

    def test_fragment_and_validation_requirements_cannot_disappear(self):
        for key in ("TRANSPORT_FRAGMENT", "TRANSPORT_FLOW_CONTROL"):
            self.rejected(1, lambda value: value.update(messages=[row for row in value["messages"] if row["id"] != key]))
        self.rejected(1, lambda value: value.update(operations=[row for row in value["operations"] if row["id"] != "transport.address-validation"]))

    def test_registry_continued_definition_and_numeric_aliases_cannot_be_dropped(self):
        self.rejected(0, lambda value: value.update(registry=[row for row in value["registry"] if row["id"] != "PSYC_MESSAGE_HEADER"]))
        def deduplicate(value):
            seen = set()
            value["registry"] = [row for row in value["registry"] if row["number"] not in seen and not seen.add(row["number"])]
        self.rejected(0, deduplicate)

    def test_node_profile_cannot_drop_an_operation_or_boundary_case(self):
        self.rejected(1, lambda value: value["profiles"][-1]["required_operations"].pop())
        self.rejected(1, lambda value: value["operations"][0]["required_cases"].pop())
        self.rejected(1, lambda value: value["messages"][0].update(number=12345))

    def test_top_level_or_operation_verified_fields_do_not_create_credit(self):
        self.rejected(1, lambda value: value.update(awards_implementation_or_verification_credit=True))
        self.rejected(1, lambda value: value["operations"][0].update(status="verified"))
        self.rejected(0, lambda value: value.update(verified=True))
        self.rejected(2, lambda value: value.update(complete_semantic_inventory=True))

    def test_nonregistry_semantics_and_zero_token_sources_remain_required(self):
        self.rejected(2, lambda value: value.update(nonregistry_obligations=[]))
        for path in ("src/service/rest/identity_plugin.c", "src/service/transport/gnunet-communicator-http3.c"):
            self.assertIn(path, self.base[0]["C_files"])
            self.assertFalse(any(fact["path"] == path for row in self.base[0]["registry"] for fact in row["source_references"]))
            self.rejected(0, lambda value: value["C_files"].remove(path))

    def test_hard_owner_scope_cannot_be_downgraded_with_the_same_ids(self):
        for field in ("required_subsystems", "foundations"):
            ledger = copy.deepcopy(self.ledger)
            ledger[field][-1]["required"] = False
            with self.assertRaises(Invalid):
                validate(*self.base, ledger=ledger)
        self.rejected(2, lambda value: value["owners"].pop())

    def test_source_identity_and_activation_uncertainty_cannot_be_deleted(self):
        self.rejected(0, lambda value: value["input_files"].pop(next(iter(value["input_files"]))))
        self.rejected(0, lambda value: value["scan_policy"].update(build_activation_inferred=True))
        self.rejected(0, lambda value: value["source_aliases"].clear())

    def test_editing_both_documents_and_lock_requires_reviewing_the_code_pin(self):
        with tempfile.TemporaryDirectory(prefix="gnunet-contract-lock-") as temporary:
            path = Path(temporary)
            lock = copy.deepcopy(self.base[-1])
            lock["node_path_sha256"] = "0" * 64
            (path / "requirements-lock.json").write_text(json.dumps(lock))
            with self.assertRaises(Invalid):
                read_data(path)

    def test_topology_requires_actual_roles_and_cannot_be_full_node_proof(self):
        node = self.base[1]
        profile = node["profiles"][-1]
        plan = dict(profile=profile["id"], components=profile["required_components"][:], claims_complete_GNUnet=False)
        self.assertFalse(topology(plan, node)["awards_implementation_or_verification_credit"])
        for role in ("opaque-Python-relay", "normal-C-TRANSPORT-at-Rust-node"):
            bad = copy.deepcopy(plan)
            bad["components"].append(role)
            with self.assertRaises(Invalid):
                topology(bad, node)
        for action in (lambda p: p["components"].remove("Rust-TRANSPORT-service"),
                       lambda p: p.update(claims_complete_GNUnet=True)):
            bad = copy.deepcopy(plan)
            action(bad)
            with self.assertRaises(Invalid):
                topology(bad, node)

    def test_strict_mode_rejects_even_a_tampered_passing_report(self):
        report = validate(*self.base, ledger=self.ledger)
        report.update(complete_semantic_inventory=True, full_GNUnet_conformance_verified=True)
        with self.assertRaisesRegex(Invalid, "34 subsystems.*8 foundations"):
            require_complete(report)


class SourceDiscoveryControls(unittest.TestCase):
    def fixture(self, root):
        (root / "src/include").mkdir(parents=True)
        (root / "src/service/core").mkdir(parents=True)
        (root / "src/service/rest").mkdir(parents=True)
        (root / "meson.build").write_text("project('fixture', 'c')\n")
        (root / "meson.options").write_text("option('conditional', type: 'boolean')\n")
        (root / "meson_options.txt").symlink_to("meson.options")
        (root / "src/include/gnunet_protocols.h").write_text(
            "#define GNUNET_MESSAGE_TYPE_CORE_INIT 64\n"
            "#define GNUNET_MESSAGE_TYPE_ALIAS 64\n"
            "#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_HEADER \\\n692 // inline comment\n"
            "#ifdef CONDITIONAL\n#define GNUNET_MESSAGE_TYPE_FAKE 955\n#endif\n")
        (root / "src/service/core/main.c").write_text(
            "/* GNUNET_MESSAGE_TYPE_GHOST */\n"
            "const char *s = \"GNUNET_MESSAGE_TYPE_GHOST\";\n"
            "GNUNET_MESSAGE_TYPE_CORE_\\\nINIT;\n"
            "// continued comment \\\nGNUNET_MESSAGE_TYPE_GHOST\n"
            "#if 0\nGNUNET_MESSAGE_TYPE_FAKE;\n#endif\n")
        (root / "src/service/rest/plugin.c").write_text('const char *route = "/identity";\n')

    def test_real_C_splicing_literals_aliases_and_physical_lines(self):
        with tempfile.TemporaryDirectory(prefix="gnunet-contract-scan-") as temporary:
            root = Path(temporary)
            self.fixture(root)
            result = discover(root)
            rows = {row["id"]: row for row in result["registry"]}
            self.assertEqual(rows["CORE_INIT"]["number"], rows["ALIAS"]["number"])
            self.assertEqual(rows["PSYC_MESSAGE_HEADER"]["number"], 692)
            self.assertEqual(rows["CORE_INIT"]["source_references"][0]["line"], 3)
            self.assertEqual(rows["FAKE"]["source_references"][0]["line"], 8)
            self.assertFalse(result["unregistered_source_tokens"])
            self.assertIn("src/service/rest/plugin.c", result["C_files"])
            self.assertFalse(result["scan_policy"]["preprocessor_conditions_evaluated"])
            self.assertEqual(result["source_aliases"], {"meson_options.txt": "meson.options"})

    def test_new_source_unknown_message_and_meson_options_change_discovery(self):
        with tempfile.TemporaryDirectory(prefix="gnunet-contract-drift-") as temporary:
            root = Path(temporary)
            self.fixture(root)
            original = discover(root)
            (root / "src/service/rest/other.c").write_text("GNUNET_MESSAGE_TYPE_NEW_EXTERNAL;\n")
            added = discover(root)
            self.assertNotEqual(original, added)
            self.assertIn("GNUNET_MESSAGE_TYPE_NEW_EXTERNAL", added["unregistered_source_tokens"])
            (root / "meson.options").write_text("option('different', type: 'boolean')\n")
            self.assertNotEqual(added["input_files"], discover(root)["input_files"])

    def test_unsafe_reference_alias_or_extra_path_cannot_escape_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="gnunet-contract-alias-") as temporary:
            root = Path(temporary)
            self.fixture(root)
            with self.assertRaises(ValueError):
                discover(root, ["../outside"])
            alias = root / "src/service/core/alias.c"
            alias.symlink_to("main.c")
            with self.assertRaises(ValueError):
                discover(root)

    def test_registry_unknown_expressions_and_duplicates_are_not_silently_dropped(self):
        for text in ("#define GNUNET_MESSAGE_TYPE_X (64 + 1)\n",
                     "#define GNUNET_MESSAGE_TYPE_X 1\n#define GNUNET_MESSAGE_TYPE_X 2\n"):
            with self.assertRaises(ValueError):
                registry(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
