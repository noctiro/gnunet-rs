"""Control exact workspace staging and required native reference witnesses."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import verify


class RuntimeVerifierTests(unittest.TestCase):
    def test_additional_rust_tests_do_not_invalidate_required_witnesses(self):
        output = ''.join('test ' + name + ' ... ok\n'
                         for name in sorted(verify.REQUIRED_RUST_TESTS))
        output += 'test new::independent_case ... ok\n'
        output += ''.join(f'test result: ok. {count} passed; 0 failed; 0 ignored;\n'
                          for count in (40, 18, 3, 2))
        self.assertEqual([row['passed'] for row in verify.require_rust_tests(output)],
                         [40, 18, 3, 2])
        for altered in (output.replace(' ... ok\n', ' ... ignored\n', 1),
                        output.replace('40 passed', '0 passed'),
                        output.replace('0 failed', '1 failed', 1),
                        output.rsplit('test result:', 1)[0]):
            with self.assertRaises(ValueError):
                verify.require_rust_tests(altered)

    def test_staged_workspace_uses_original_manifests_and_detects_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            for directory in ('crates', 'adapters', 'apps', 'tools/interop',
                              'tests', '.cargo', '.github', 'spec'):
                (root / directory).mkdir(parents=True)
            for directory in ('crates', 'adapters', 'apps', 'tests', '.cargo', '.github'):
                (root / directory / 'marker.txt').write_text(directory)
            for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                         'ARCHITECTURE.md', 'README.md', 'rustfmt.toml'):
                (root / name).write_text('original ' + name)
            (root / 'spec/contract.json').write_text('{}')
            repository = Path(__file__).resolve().parents[3]
            helper = Path('tools/interop/run_reference.py')
            shutil.copyfile(repository / helper, root / helper)
            original = verify.workspace_inputs(root)
            staged = Path(temporary) / 'staged'
            verify.stage(root, staged, original)
            self.assertEqual((staged / 'Cargo.toml').read_bytes(),
                             (root / 'Cargo.toml').read_bytes())
            self.assertEqual(verify.workspace_inputs(staged), original)
            (staged / 'Cargo.toml').write_text('changed feature/dependency contract')
            self.assertNotEqual(verify.workspace_inputs(staged), original)
            with self.assertRaises(FileExistsError):
                verify.stage(root, staged, original)

    def test_contract_comparison_preserves_target_features_and_development_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            first, second = base / 'original', base / 'staged'

            def metadata(root):
                return {'packages': [{
                    'source': None, 'manifest_path': str(root / 'package/Cargo.toml'),
                    'name': 'example', 'version': '1.0.0', 'edition': '2024',
                    'license': 'MPL-2.0', 'rust_version': '1.100.0',
                    'features': {'default': [], 'service': ['dep:socket2']},
                    'dependencies': [{'name': 'socket2', 'path': str(root / 'socket2'),
                                      'req': '*', 'kind': 'dev', 'rename': None,
                                      'optional': True, 'uses_default_features': False,
                                      'source': None, 'target': 'cfg(windows)',
                                      'features': ['all']}],
                }]}

            original, staged = metadata(first), metadata(second)
            self.assertEqual(verify.contracts(original, first), verify.contracts(staged, second))
            staged['packages'][0]['dependencies'][0]['target'] = 'cfg(unix)'
            self.assertNotEqual(verify.contracts(original, first), verify.contracts(staged, second))

    def test_optimized_reference_runner_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'must-not-exist'
            result = subprocess.run([
                sys.executable, '-O', '-B', str(Path(verify.__file__)),
                '--repository', str(root / 'repo'), '--upstream', str(root / 'upstream'),
                '--reference', str(root / 'reference.json'), '--output', str(output),
            ], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'assertion-enabled Python', result.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
