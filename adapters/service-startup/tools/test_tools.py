#!/usr/bin/env python3
"""Ten proof-boundary regressions; no native-account/socket observations."""
import json
import pathlib
import tempfile
import unittest
from _common import (local_snapshot, require_disjoint_output, sha, validated_build,
                     _validate_normal_reference_data, PINNED_REVISION, PINNED_TAG,
                     require_rust_fixture_success)


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gnunet-startup-tool-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()

    def test_outputs_reject_descendant_ancestor_and_existing(self):
        protected = self.root / 'repo'
        protected.mkdir()
        for output in (protected, protected / 'output', self.root):
            with self.assertRaises(ValueError):
                require_disjoint_output(output, [protected])
        existing = self.root / 'exists'
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            require_disjoint_output(existing, [protected])
        self.assertEqual(require_disjoint_output(self.root / 'fresh', [protected]),
                         self.root / 'fresh')

    def fixture(self):
        repo, package, dependency, unused = [self.root / name for name in
                                             ('repo', 'repo/package',
                                              'repo/dep', 'repo/unused')]
        for directory in (package, dependency, unused):
            (directory / 'src').mkdir(parents=True)
            (directory / 'Cargo.toml').write_text('[package]\n')
            (directory / 'src/lib.rs').write_text('')
        (repo / 'Cargo.lock').write_text('locked')
        (repo / 'Cargo.toml').write_text('[workspace]\n')
        (repo / '.cargo').mkdir()
        (repo / '.cargo/config.toml').write_text('[build]\n')
        (dependency / 'src/payload.txt').write_bytes(b'include_str input')
        (package / 'docs').mkdir()
        (package / 'docs/notes.md').write_text('notes')
        (package / 'target').mkdir()
        (package / 'target/generated').write_text('ignore me')
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'helper.py').write_text('helper')
        metadata = {'workspace_root': str(repo), 'packages': [
            {'id': name, 'name': name, 'source': None,
             'manifest_path': str(path / 'Cargo.toml')}
            for name, path in [('p', package), ('d', dependency), ('u', unused)]],
            'resolve': {'nodes': [
                {'id': 'p', 'dependencies': ['d']},
                {'id': 'd', 'dependencies': []},
                {'id': 'u', 'dependencies': []}]}}
        return repo, package, dependency, unused, tools, metadata

    def test_snapshot_includes_nonrust_dependencies_lock_settings_docs_tools(self):
        repo, package, dep, unused, tools, metadata = self.fixture()
        _, inputs = local_snapshot(metadata, package, tools)
        required = [dep / 'src/payload.txt', repo / 'Cargo.lock',
                    repo / '.cargo/config.toml', package / 'docs/notes.md',
                    tools / 'helper.py']
        self.assertTrue(all(str(path) in inputs for path in required))
        self.assertFalse(any(str(unused) in path for path in inputs))
        self.assertFalse(any('/target/' in path for path in inputs))

    def test_snapshot_detects_added_removed_and_nonrust_changed_files(self):
        _, package, dep, _, tools, metadata = self.fixture()
        _, initial = local_snapshot(metadata, package, tools)
        added = dep / 'src/new.bin'
        added.write_bytes(b'new')
        _, current = local_snapshot(metadata, package, tools)
        self.assertNotEqual(initial, current)
        added.unlink()
        self.assertEqual(initial, local_snapshot(metadata, package, tools)[1])
        (dep / 'src/payload.txt').write_bytes(b'changed')
        self.assertNotEqual(initial, local_snapshot(metadata, package, tools)[1])
        (dep / 'src/lib.rs').unlink()
        self.assertNotEqual(initial, local_snapshot(metadata, package, tools)[1])

    def receipt(self):
        source, binary, receipt = [self.root / name for name in
                                    ('source.txt', 'binary', 'receipt.json')]
        source.write_text('source')
        binary.write_bytes(b'not an executable; pure receipt-boundary fixture')
        receipt.write_text(json.dumps({'exit_code': 0, 'inputs_unchanged': True,
            'inputs': {str(source): sha(source)},
            'binary': {'path': str(binary), 'sha256': sha(binary)}}))
        return source, binary, receipt

    def test_build_receipt_rejects_changed_source_or_binary(self):
        source, binary, receipt = self.receipt()
        self.assertEqual(validated_build(receipt)['exit_code'], 0)
        original = source.read_bytes()
        source.write_text('different')
        with self.assertRaises(ValueError):
            validated_build(receipt)
        source.write_bytes(original)
        binary.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            validated_build(receipt)

    def test_build_receipt_rejects_failed_or_empty_evidence(self):
        _, _, receipt = self.receipt()
        value = json.loads(receipt.read_text())
        for field, replacement in [('exit_code', 1), ('inputs', {}),
                                   ('binary', None), ('inputs_unchanged', False)]:
            bad = {**value, field: replacement}
            receipt.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                validated_build(receipt)


    def normal_fixture(self):
        source = self.root / 'official-source'
        source.mkdir()
        build = self.root / 'build'
        build.mkdir()
        config = build / 'gnunet_private_config.h'
        config.write_bytes(b'pure config-boundary fixture')
        prefix = self.root / 'prefix'
        (prefix / 'lib').mkdir(parents=True)
        library = prefix / 'lib/libgnunetutil.23.dylib'
        library.write_bytes(b'pure library-boundary fixture; not executable')
        state = {'revision': PINNED_REVISION, 'tag': PINNED_TAG,
                 'tracked_files': 1, 'tracked_input_sha256': 'a' * 64,
                 'tracked_sources_clean': True, 'gitlinks': []}
        receipt = {'status': 'passed',
                   'kind': 'unmodified-official-c-reference-build',
                   'source_unchanged': True, 'source': str(source),
                   'upstream': dict(state), 'build': str(build),
                   'prefix': str(prefix),
                   'generated_config': {'path': str(config), 'sha256': sha(config)},
                   'libraries': [{'path': str(library), 'sha256': sha(library)}],
                   'runtime_environment': {'GNUNET_PREFIX': str(prefix),
                       'LD_LIBRARY_PATH': str(prefix / 'lib'),
                       'DYLD_LIBRARY_PATH': str(prefix / 'lib')}}
        # This pure helper is fed an explicit state fixture. Native verification
        # must instead call normal_reference(), which computes actual Git state.
        self.assertTrue(_validate_normal_reference_data(receipt, source, state))
        return receipt, source, state, config, library

    def test_normal_reference_rejects_wrong_revision(self):
        receipt, source, state, _, _ = self.normal_fixture()
        receipt['upstream']['revision'] = '0' * 40
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, source, state)

    def test_normal_reference_rejects_changed_source_and_false_claim(self):
        receipt, source, state, _, _ = self.normal_fixture()
        changed = {**state, 'tracked_input_sha256': 'b' * 64}
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, source, changed)
        receipt['source_unchanged'] = False
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, source, state)
        receipt['source_unchanged'] = True
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, self.root / 'other-source', state)

    def test_normal_reference_rejects_changed_declared_library(self):
        receipt, source, state, _, library = self.normal_fixture()
        library.write_bytes(b'changed library')
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, source, state)

    def test_normal_reference_rejects_changed_compile_config(self):
        receipt, source, state, config, _ = self.normal_fixture()
        config.write_bytes(b'changed compile profile')
        with self.assertRaises(ValueError):
            _validate_normal_reference_data(receipt, source, state)


    def test_rust_valid_json_followed_by_nonzero_child_exit_is_rejected(self):
        import subprocess
        import sys
        # A real private exec produces valid observation JSON, then fails late.
        # It does not touch credentials, files, sockets or foreign descriptors.
        code = "import json,sys; print(json.dumps({'ok': True})); sys.exit(7)"
        child = subprocess.run([sys.executable, '-c', code], capture_output=True,
                               check=False, timeout=5)
        row = {'kind': 'rust', 'exit_code': child.returncode,
               'observation': json.loads(child.stdout)}
        self.assertEqual(row['observation'], {'ok': True})
        self.assertEqual(row['exit_code'], 7)
        with self.assertRaises(ValueError):
            require_rust_fixture_success(row)
        self.assertEqual(require_rust_fixture_success({**row, 'exit_code': 0})
                         ['observation'], {'ok': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
