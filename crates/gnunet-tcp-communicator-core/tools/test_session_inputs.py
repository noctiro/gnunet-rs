#!/usr/bin/env python3
"""Failure controls execute only owned temporary files and fresh Python children."""
import ast
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from session_inputs import (TOOLS, CRYPTO, HOST, CORE, copy_workspace, disjoint_output,
                            CORE_PATH,PIN,Reference,historical_builder,metadata_contract, registry_contract, require_processes, role_contract, same, sha, tree)

LABELS = [
    'test_nonzero_original_process_is_rejected',
    'test_changed_original_binary_is_rejected',
    'test_empty_or_duplicate_processes_are_rejected',
    'test_new_and_removed_files_are_both_detected',
    'test_normal_dev_build_target_rename_optional_default_and_features_survive_contract',
    'test_complete_roles_include_unselected_workspace_members',
    'test_registry_name_version_source_and_checksum_changes_are_rejected',
    'test_both_lock_files_and_settings_are_copied_verbatim',
    'test_real_optimized_python_rejects_nonzero_json_and_accepts_control',
    'test_duplicate_session_crypto_identity_is_rejected',
    'test_resolved_features_and_dependency_kinds_are_preserved',
    'test_output_and_ancestor_overlap_are_rejected',
    'test_mode_and_symlink_identity_changes_are_detected',
    'test_critical_tools_have_no_optimizable_assert_statements',
    'test_reference_source_setup_builder_and_artifact_negative_fields',
    'test_historical_builder_source_is_exact_inert_and_explicitly_distinct',
    'test_both_actual_optimized_builders_reject_before_meson_and_allow_valid_control',
]


def metadata():
    root = '/fixture'
    packages = []
    for name, directory in ((CORE, 'crates/core'), (HOST, 'adapters/host'),
                            (CRYPTO, 'crates/crypto'), ('unselected-owner', 'crates/other')):
        packages.append({'id': name, 'name': name, 'version': '0.1.0', 'source': None,
                         'manifest_path': root + '/' + directory + '/Cargo.toml',
                         'dependencies': [], 'targets': [], 'features': {'default': []}})
    dependency = {'name': 'provider', 'source': 'registry+https://example.test/index', 'req': '=1.0.0',
                  'kind': None, 'rename': 'renamed', 'optional': True, 'uses_default_features': False,
                  'features': ['zeroize'], 'target': 'cfg(unix)', 'registry': None, 'path': None}
    packages[0]['dependencies'] = [{**dependency, 'kind': kind} for kind in (None, 'dev', 'build')]
    return {'packages': packages, 'workspace_members': [p['id'] for p in packages],
            'workspace_default_members': [p['id'] for p in packages], 'metadata': {'full': True},
            'resolve': {'root': None, 'nodes': [
                {'id': p['id'], 'dependencies': [], 'deps': [], 'features': []} for p in packages]}}


class Controls(unittest.TestCase):
    def test_historical_builder_source_is_exact_inert_and_explicitly_distinct(self):
        with tempfile.TemporaryDirectory()as directory:
            repo=Path(directory);tools=repo/CORE_PATH/'tools';history=tools/'history';history.mkdir(parents=True)
            current=tools/'build_normal.py';current.write_text('new explicit checks')
            archive=history/'original.py.snapshot';archive.write_text('original source');archive.chmod(0o644)
            original=sha(archive);kind='unmodified-official-c-tcp-communicator-reference-build'
            row={'builder':current.name,'profile_kind':kind,'original_sha256':original,'archive':'history/'+archive.name,
                 'replacement_builder_sha256':sha(current),'archive_executed':False}
            mapping=tools/'historical-builders.json';mapping.write_text(json.dumps({'schema':1,'entries':[row]}))
            provenance=historical_builder(repo,kind,original)
            self.assertTrue(provenance['archived']);self.assertFalse(provenance['executed_by_verifier'])
            self.assertFalse(historical_builder(repo,kind,sha(current))['archived'])
            for change in ('content','missing','duplicate','replacement','executable'):
                archive.write_text('original source');archive.chmod(0o644)
                data={'schema':1,'entries':[copy.deepcopy(row)]}
                if change=='content':archive.write_text('modified historical source')
                elif change=='missing':archive.unlink()
                elif change=='duplicate':data['entries'].append(copy.deepcopy(row))
                elif change=='replacement':data['entries'][0]['replacement_builder_sha256']='0'*64
                else:archive.chmod(0o755)
                mapping.write_text(json.dumps(data))
                with self.assertRaises(ValueError):historical_builder(repo,kind,original)

    def test_both_actual_optimized_builders_reject_before_meson_and_allow_valid_control(self):
        for filename in ('build_normal.py','build_peer_normal.py'):
            with tempfile.TemporaryDirectory()as directory:
                root=Path(directory).resolve();repo=root/'repo';source=root/'source';receipts=root/'receipts'
                for p in (repo,source,receipts):p.mkdir()
                helper=repo/'tools/reference/build_reference.py';helper.parent.mkdir(parents=True)
                helper.write_text("from pathlib import Path\ndef source_state(source):return {'revision':'fixture'}\ndef run_logged(out,name,argv,env):\n (Path(out)/'meson-port-reached').write_text(name)\n return {'exit_code':1}\n")
                recipe=receipts/'recipe.json';data={'upstream':{'revision':'fixture'},'status':'failed',
                    'build_environment':{},'commands':[{'name':'meson-setup','argv':['/fixture/meson','setup','build','source','--prefix=old','--libdir=lib']}]}
                argv=[sys.executable,'-O',str(TOOLS/filename),'--repository',str(repo),'--source',str(source),
                      '--reference',str(recipe),'--output',str(root/'invalid-build'),'--prefix',str(root/'invalid-prefix')]
                env=os.environ.copy();env.update(PYTHONOPTIMIZE='1',PYTHONDONTWRITEBYTECODE='1')
                recipe.write_text(json.dumps(data));bad=subprocess.run(argv,env=env,capture_output=True)
                self.assertNotEqual(bad.returncode,0);self.assertIn(b'normal prerequisite recipe/state mismatch',bad.stderr)
                self.assertFalse((root/'invalid-build/meson-port-reached').exists())
                data['status']='passed';recipe.write_text(json.dumps(data))
                argv[argv.index(str(root/'invalid-build'))]=str(root/'valid-build')
                argv[argv.index(str(root/'invalid-prefix'))]=str(root/'valid-prefix')
                good=subprocess.run(argv,env=env,capture_output=True)
                self.assertNotEqual(good.returncode,0);self.assertIn(b'meson-version failed',good.stderr)
                self.assertEqual((root/'valid-build/meson-port-reached').read_text(),'meson-version')
    def test_reference_source_setup_builder_and_artifact_negative_fields(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();repo=root/'repo';source=root/'source';build=root/'build';prefix=root/'prefix'
            for path in(repo,source,build,prefix):path.mkdir()
            helper=repo/'tools/reference/build_reference.py';helper.parent.mkdir(parents=True);helper.write_text('fixture source-state port')
            builder=repo/CORE_PATH/'tools/build_normal.py';builder.parent.mkdir(parents=True);builder.write_text('fixture historical builder')
            files=[]
            for name in('program','library.dylib','private.h','compile_commands.json'):
                path=root/name;path.write_text('fixture:'+name);files.append({'path':str(path),'sha256':sha(path)})
            state={'revision':PIN,'tag':'v0.29.1','tracked_sources_clean':True}
            kind='unmodified-official-c-tcp-communicator-reference-build'
            value={'status':'passed','kind':kind,'source':str(source),'source_unchanged':True,'upstream':state,
                'build':str(build),'prefix':str(prefix),'runtime_environment':{'DYLD_LIBRARY_PATH':str(prefix/'lib'),
                'LD_LIBRARY_PATH':str(prefix/'lib'),'GNUNET_PREFIX':str(prefix)},'commands':[{'name':'meson-setup','exit_code':0,
                'argv':['meson','setup',str(build),str(source),'--prefix='+str(prefix)]}],
                'builder_sha256':sha(builder),'inputs':{str(helper):sha(helper)},'artifacts':{'program':files[0]},
                'libraries':[files[1]],'generated_config':files[2],'compile_commands':files[3]}
            ref=Reference.__new__(Reference);ref.repo=repo;ref.source=source;ref.helper=helper;ref.kind=kind;ref.receipt=root/'receipt.json'
            ref.module=type('SourceStatePort',(),{'source_state':staticmethod(lambda _:state)})
            def check(data):
                ref.normal=data;ref.receipt.write_text(json.dumps(data));return ref.check()
            check(value)
            mutations=[lambda x:x.update(status='failed'),lambda x:x.update(kind='other'),
                lambda x:x.update(source=str(root/'other')),lambda x:x.update(source_unchanged=False),
                lambda x:x.update(upstream={**state,'revision':'0'*40}),
                lambda x:x['commands'].append(copy.deepcopy(x['commands'][0])),
                lambda x:x['commands'][0]['argv'].__setitem__(3,str(root/'other')),
                lambda x:x.update(builder_sha256='0'*64),lambda x:x['libraries'][0].update(sha256='0'*64),
                lambda x:x['generated_config'].update(sha256='0'*64),lambda x:x['compile_commands'].update(sha256='0'*64)]
            for mutate in mutations:
                data=copy.deepcopy(value);mutate(data)
                with self.assertRaises(ValueError):check(data)
    def test_nonzero_original_process_is_rejected(self):
        with self.assertRaises(ValueError):
            require_processes([{'label': 'owned', 'exit': 7, 'binary_sha256': 'a', 'after_sha256': 'a'}])

    def test_changed_original_binary_is_rejected(self):
        with self.assertRaises(ValueError):
            require_processes([{'label': 'owned', 'exit': 0, 'binary_sha256': 'a', 'after_sha256': 'b'}])

    def test_empty_or_duplicate_processes_are_rejected(self):
        row = {'label': 'owned', 'exit': 0, 'binary_sha256': 'a', 'after_sha256': 'a'}
        for rows in ([], [row, row]):
            with self.assertRaises(ValueError):
                require_processes(rows)
        require_processes([row])

    def test_new_and_removed_files_are_both_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('fixture')
            before = tree(root)
            (root / 'new.rs').write_text('new')
            with self.assertRaises(ValueError):
                same(tree(root), before, 'new source path')
            after = tree(root)
            (root / 'new.rs').unlink()
            with self.assertRaises(ValueError):
                same(tree(root), after, 'removed source path')
            same(tree(root), before, 'positive source control')

    def test_normal_dev_build_target_rename_optional_default_and_features_survive_contract(self):
        value = metadata()
        before = metadata_contract(value, '/fixture')
        changes = {'name': 'other', 'source': 'registry+https://other.test/index', 'req': '=2.0.0',
                   'kind': 'dev', 'rename': None, 'optional': False, 'uses_default_features': True,
                   'features': ['alloc'], 'target': 'cfg(windows)', 'registry': 'alternate',
                   'path': '/fixture/another'}
        for index in range(3):
            for field, replacement in changes.items():
                changed = copy.deepcopy(value)
                if field == 'kind' and changed['packages'][0]['dependencies'][index][field] == replacement:
                    replacement = 'build'
                changed['packages'][0]['dependencies'][index][field] = replacement
                with self.assertRaises(ValueError, msg=field + '/' + str(index)):
                    same(metadata_contract(changed, '/fixture'), before, 'dependency contract')

    def test_complete_roles_include_unselected_workspace_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'tools/xtask/src/checks.rs'
            target.parent.mkdir(parents=True)
            entries = [(CORE, 'crates/core', True), (HOST, 'adapters/host', False),
                       (CRYPTO, 'crates/crypto', True), ('unselected-owner', 'crates/other', True)]
            text = '\n'.join('Policy {\n name: "' + n + '",\n directory: "' + p
                             + '",\n core: ' + str(c).lower() + ',\n dependencies: &[],\n}' for n, p, c in entries)
            target.write_text(text)
            before = role_contract(root)
            self.assertEqual(set(before), {e[0] for e in entries})
            target.write_text(text.replace('directory: "crates/other"', 'directory: "adapters/other"'))
            with self.assertRaises(ValueError):
                same(role_contract(root), before, 'unselected full workspace role')

    def test_registry_name_version_source_and_checksum_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cargo.lock'
            original = '[[package]]\nname = "provider"\nversion = "1.0.0"\nsource = "registry+https://example.test/index"\nchecksum = "' + '0' * 64 + '"\n'
            path.write_text(original)
            before = registry_contract(path)
            for old, new in [('provider', 'other'), ('1.0.0', '2.0.0'), ('example.test', 'other.test'), ('0' * 64, '1' * 64)]:
                path.write_text(original.replace(old, new))
                with self.assertRaises(ValueError):
                    same(registry_contract(path), before, 'registry identity/checksum')

    def test_both_lock_files_and_settings_are_copied_verbatim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'original'
            root.mkdir()
            for path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rustfmt.toml',
                         '.cargo/config.toml', 'tests/embedded/noalloc/Cargo.toml', 'tests/embedded/noalloc/Cargo.lock',
                         'unselected-member/src/lib.rs'):
                p = root / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('fixture:' + path)
            clone = Path(directory) / 'copy'
            before = copy_workspace(root, clone)
            same(tree(clone), before, 'full copy')
            (clone / 'tests/embedded/noalloc/Cargo.lock').write_text('changed')
            with self.assertRaises(ValueError):
                same(tree(clone), before, 'second lock')
            local_output=root/'target/proof/workspace'
            local_output.parent.mkdir(parents=True)
            same(copy_workspace(root,local_output),before,'controlled excluded target output')
            same(tree(root),before,'target output never becomes a source input')

    def test_real_optimized_python_rejects_nonzero_json_and_accepts_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'process.json'
            row = {'label': 'owned', 'exit': 7, 'binary_sha256': 'a', 'after_sha256': 'a'}
            env = os.environ.copy()
            env['PYTHONOPTIMIZE'] = '1'
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            argv = [sys.executable, '-O', str(TOOLS / 'session_inputs.py'), '--check-processes', str(path)]
            path.write_text(json.dumps([row]))
            rejected = subprocess.run(argv, env=env, capture_output=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b'rejected-process-contract: process failure', rejected.stderr)
            row['exit'] = 0
            path.write_text(json.dumps([row]))
            accepted = subprocess.run(argv, env=env, capture_output=True)
            self.assertEqual(accepted.returncode, 0)
            self.assertEqual(accepted.stdout.strip(), b'valid-process-contract')

    def test_duplicate_session_crypto_identity_is_rejected(self):
        value = metadata()
        duplicate = copy.deepcopy(value['packages'][2])
        duplicate['id'] = 'registry-copy'
        duplicate['source'] = 'registry+https://example.test/index'
        value['packages'].append(duplicate)
        with self.assertRaises(ValueError):
            metadata_contract(value, '/fixture')

    def test_resolved_features_and_dependency_kinds_are_preserved(self):
        value = metadata()
        value['resolve']['nodes'][0]['deps'] = [{'name': 'same', 'pkg': CRYPTO,
                                               'dep_kinds': [{'kind': None, 'target': 'cfg(unix)'}]}]
        value['resolve']['nodes'][0]['dependencies'] = [CRYPTO]
        before = metadata_contract(value, '/fixture')
        for mutate in ('features', 'kind', 'target'):
            changed = copy.deepcopy(value)
            node = changed['resolve']['nodes'][0]
            if mutate == 'features':
                node['features'] = ['alloc']
            else:
                node['deps'][0]['dep_kinds'][0][mutate] = 'dev' if mutate == 'kind' else 'cfg(windows)'
            with self.assertRaises(ValueError):
                same(metadata_contract(changed, '/fixture'), before, 'resolved graph')

    def test_output_and_ancestor_overlap_are_rejected(self):
        for output in ('/fixture', '/fixture/child', '/'):
            with self.assertRaises(ValueError):
                disjoint_output(output, ['/fixture'])
        disjoint_output('/sibling', ['/fixture'])
        disjoint_output('/fixture/target/proof',['/fixture'],workspace='/fixture')
        with self.assertRaises(ValueError):
            disjoint_output('/fixture/src/proof',['/fixture'],workspace='/fixture')

    def test_mode_and_symlink_identity_changes_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p = root / 'source'
            p.write_text('source')
            before = tree(root)
            p.chmod(0o700)
            with self.assertRaises(ValueError):
                same(tree(root), before, 'mode')
            link = root / 'alias'
            link.symlink_to('source')
            before = tree(root)
            link.unlink()
            link.symlink_to('different')
            with self.assertRaises(ValueError):
                same(tree(root), before, 'symlink')

    def test_critical_tools_have_no_optimizable_assert_statements(self):
        for path in TOOLS.rglob('*.py'):
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(path.read_bytes()))), path.name)


if __name__ == '__main__':
    names = sorted(n for n in dir(Controls) if n.startswith('test_'))
    same(names, sorted(LABELS), 'exact nonempty17 negative/control names')
    unittest.main(verbosity=2)
