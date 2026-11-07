#!/usr/bin/env python3
"""Source-bound independent broker validation. Outputs never enter source trees."""
import argparse, json, os, pathlib, re, subprocess, sys, time
from common import sha, disjoint, local_files, expected_tests, observed_tests, check_actor_result, rust_library, workspace_files, workspace_contract, copy_workspace, normalized_metadata, apply_overlay, witness_inventory, normal_receipt_inputs

CONTROL_NAMES=['test_actual_library_artifact_selected_without_glob', 'test_actual_second_lock_is_required', 'test_compile_source_in_different_clone_rejected', 'test_compile_source_relative_cwd_is_bound', 'test_duplicate_actual_rejected', 'test_duplicate_library_artifact_rejected', 'test_duplicate_local_cargo_identity_rejected', 'test_empty_actor_rejected', 'test_empty_actual_rejected', 'test_empty_expected_rejected', 'test_foreign_actual_library_manifest_rejected', 'test_foreign_actual_library_package_id_rejected', 'test_foreign_local_cargo_identity_rejected', 'test_ignored_actual_rejected', 'test_missing_library_artifact_rejected', 'test_named_nonempty_positive', 'test_optimized_actual_decoder_rejects_malformed_header', 'test_source_bytes_mutation_changes_digest', 'test_source_overlap_rejected', 'test_valid_json_nonzero_actor_rejected', 'test_workspace_addition_and_deletion_change_file_set', 'test_wrong_name_rejected']
CONTROL_COUNT=len(CONTROL_NAMES)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--package', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    p.add_argument('--repo', type=pathlib.Path, required=True)
    p.add_argument('--upstream', type=pathlib.Path, required=True)
    p.add_argument('--normal-receipt', type=pathlib.Path, required=True)
    p.add_argument('--normal-statistics-receipt', type=pathlib.Path, required=True)
    p.add_argument('--normal-resolver-base', type=pathlib.Path, required=True)
    p.add_argument('--normal-resolver-receipt', type=pathlib.Path, required=True)
    p.add_argument('--reference-helper', type=pathlib.Path, required=True)
    p.add_argument('--toolchain', default='1.99.1')
    p.add_argument('--profile', choices=['clock-source','native-retry'],default='native-retry')
    p.add_argument('--overlay-manifest',type=pathlib.Path)
    p.add_argument('--preflight',action='store_true',help='Copy/metadata/source/normal receipt and exact guard checks only; no compilation or actors')
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.package = a.package.resolve()
    a.repo = a.repo.resolve()
    a.output = a.output.resolve()
    disjoint(a.output, a.package, a.repo, a.upstream, a.normal_receipt.parent, a.normal_statistics_receipt.parent, a.normal_resolver_base.parent, a.normal_resolver_receipt.parent)
    a.output.mkdir(exist_ok=False, parents=True)
    manifest = a.package / 'Cargo.toml'
    env = os.environ.copy()
    env['CARGO_BUILD_JOBS'] = '2'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['CARGO_NET_OFFLINE'] = 'true'
    env['CARGO_TARGET_DIR'] = str(a.output / 'target')
    commands = []
    result = {'status': 'failed', 'scope': 'Integrated shared Resolver broker/CLIENT/ARM/STATISTICS implementation only; no owner promotion; full PROGRAM integration remains separately developing', 'commands': commands}
    python = [sys.executable, '-B']
    cargo = ['cargo', '+' + a.toolchain]
    cargo_args = ['--manifest-path', str(manifest), '--offline', '--locked', '-j2', '--target-dir', str(a.output / 'target')]

    def run(name, argv, timeout=120):
        started = time.monotonic()
        proc = subprocess.run([str(x) for x in argv], cwd=a.package, env=env, capture_output=True, timeout=timeout)
        out = a.output / (name + '.stdout')
        err = a.output / (name + '.stderr')
        out.write_bytes(proc.stdout)
        err.write_bytes(proc.stderr)
        commands.append({'name': name, 'argv': [str(x) for x in argv], 'exit_code': proc.returncode, 'elapsed': time.monotonic() - started, 'stdout_sha256': sha(out), 'stderr_sha256': sha(err)})
        if not proc.returncode == 0:
            raise ValueError((name, proc.returncode, proc.stderr.decode(errors='replace')[-2500:]))
        return proc.stdout.decode()

    def metadata(name):
        return json.loads(run(name, cargo + ['metadata', '--manifest-path', manifest, '--offline', '--locked', '--format-version', '1']))
    try:
        input_repo=a.repo;input_package=a.package
        if input_package!=input_repo/'adapters/resolver-broker-std':raise ValueError('package must be the canonical broker in the full repository')
        original_metadata=normalized_metadata(metadata('metadata-input'),input_repo)
        original_noalloc=json.loads(run('metadata-noalloc-input',cargo+['metadata','--manifest-path',input_repo/'tests/embedded/noalloc/Cargo.toml','--offline','--locked','--format-version','1']))
        original_noalloc=normalized_metadata(original_noalloc,input_repo,input_repo/'tests/embedded/noalloc',False)
        original_inputs=copy_workspace(input_repo,a.output/'workspace');result['input_repository']={'path':str(input_repo),'files':original_inputs,'settings_two_locks':workspace_contract(input_repo)}
        a.repo=a.output/'workspace';a.package=a.repo/'adapters/resolver-broker-std';manifest=a.package/'Cargo.toml'
        cargo_args=['--manifest-path',str(manifest),'--offline','--locked','-j2','--target-dir',str(a.output/'target')]
        if a.reference_helper.resolve().is_relative_to(input_repo):a.reference_helper=a.repo/a.reference_helper.resolve().relative_to(input_repo)
        copied_metadata=metadata('metadata-before')
        if normalized_metadata(copied_metadata,a.repo)!=original_metadata:raise ValueError('full workspace Cargo role/type identity changed during copy')
        copied_noalloc=json.loads(run('metadata-noalloc-before',cargo+['metadata','--manifest-path',a.repo/'tests/embedded/noalloc/Cargo.toml','--offline','--locked','--format-version','1']))
        if normalized_metadata(copied_noalloc,a.repo,a.repo/'tests/embedded/noalloc',False)!=original_noalloc:raise ValueError('second workspace Cargo identity changed')
        result['cargo_package_roles']=original_metadata;result['noalloc_package_roles']=original_noalloc
        if a.overlay_manifest:result['overlay']=apply_overlay(a.repo,a.overlay_manifest)
        inventories=witness_inventory(a.repo,a.profile);result['witness_profile']=a.profile;result['reviewed_witness_inventory']={name:sorted(names)for name,names in inventories.items()}
        before = local_files(copied_metadata, a.package, a.repo)
        result['source_inputs'] = before
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(a.reference_helper.resolve().parent))
        from build_reference import source_state
        upstream_before = source_state(a.upstream)
        if not upstream_before == json.loads(a.normal_receipt.read_text())['upstream']:
            raise ValueError('required condition failed at original line 12')
        result['upstream'] = upstream_before
        external = {str(p.resolve()): sha(p) for p in [a.normal_receipt, a.normal_statistics_receipt, a.normal_resolver_base, a.normal_resolver_receipt, a.reference_helper]}
        result['external_inputs'] = external
        normal_inputs={};normal_profiles=[]
        for receipt_path in [a.normal_receipt,a.normal_statistics_receipt,a.normal_resolver_base,a.normal_resolver_receipt]:
            value,binding=normal_receipt_inputs(receipt_path,upstream_before);normal_inputs.update(binding)
            normal_profiles.append({'path':str(receipt_path.resolve()),'receipt_sha256':sha(receipt_path),'recorded_historical_builder_sha256':value.get('builder_sha256'),'kind':value.get('kind'),'scope':'Existing unmodified normal build is validated, not rebuilt or attributed to current Python builder'})
        resolver_ref=json.loads(a.normal_resolver_receipt.read_text())
        if resolver_ref.get('base_receipt_sha256')!=sha(a.normal_resolver_base)or pathlib.Path(resolver_ref['base_receipt']).resolve()!=a.normal_resolver_base.resolve()or resolver_ref.get('base_files_unchanged')is not True:raise ValueError('normal Resolver base provenance mismatch')
        result['normal_build_profiles']=normal_profiles;result['normal_bound_inputs']=normal_inputs
        boundaries = run('tool-controls', python + [a.package / 'tools/test_tools.py'])
        if not not boundaries:
            raise ValueError('required condition failed at original line 13')
        err = (a.output / 'tool-controls.stderr').read_text()
        if not ('Ran '+str(CONTROL_COUNT)+' tests' in err and err.rstrip().endswith('OK')):
            raise ValueError('required condition failed at original line 13')
        actual_controls=re.findall(r'^(test_\w+) \(.*\) \.\.\. ok$',err,re.M)
        if sorted(actual_controls)!=CONTROL_NAMES:raise ValueError('tool controls did not run exact reviewed nonempty method names')
        result['tool_controls'] = CONTROL_COUNT
        result['tool_control_names']=actual_controls
        if a.preflight:
            if local_files(metadata('metadata-preflight-after'),a.package,a.repo)!=before or workspace_files(input_repo)!=original_inputs:raise ValueError('preflight source file set/bytes changed')
            if not all(sha(path)==digest for path,digest in normal_inputs.items()):raise ValueError('normal input changed during preflight')
            result.update(status='preflight_passed',actual_rust_tests=0,actual_C_R_actors=0,normal_builds_rebuilt=0,inputs_unchanged=True)
            return
        run('strict-clippy', cargo + ['clippy', *cargo_args, '-p', 'gnunet-resolver-broker', '-p', 'gnunet-client', '-p', 'gnunet-ipc-unix', '-p', 'gnunet-arm-host', '-p', 'gnunet-arm-cli', '--all-targets','--','-D','warnings'])
        run('spawn-helper-build',cargo+['build',*cargo_args,'-p','gnunet-arm-host','--bin','gnunet-arm-spawn-helper'])
        for group,name,args in [
            ('broker','broker-tests',['-p','gnunet-resolver-broker','--tests','--','--test-threads=2']),
            ('pure_core','core-tests',['-p','gnunet-client','--lib','--test','resolver','--test','broker_boundaries']),
            ('ipc','ipc-tests',['-p','gnunet-ipc-unix','--tests']),
            ('arm_endpoint','arm-endpoint-tests',['-p','gnunet-arm-host','--lib','--test','loopback','--test','live_configuration','--test','logical_clock','--test','physical_clock','--','--test-threads=2']),
            ('arm_core','arm-core-tests',['-p','gnunet-arm-core','--tests']),
        ]:
            expected=inventories[group]
            result[group+'_tests']=observed_tests(run(name,cargo+['test',*cargo_args,*args]),expected,len(expected))
        for check in ['check-deps', 'check-features', 'check-lints', 'check-noalloc']:
            run(check, cargo + ['run', *cargo_args, '-p', 'xtask', '--', check])
        run('sdk-constructors', cargo + ['check', *cargo_args, '-p', 'gnunet', '--no-default-features', '--features', 'official-ipc,official-arm'])
        docs = run('lifetime-docs', cargo + ['test', *cargo_args, '-p', 'gnunet-resolver-broker', '--doc'])
        if not (docs.count(' ... ok') == 2 and 'compile fail ... ok' in docs and ('compile ... ok' in docs)):
            raise ValueError('required condition failed at original line 21')
        result['doctests'] = 2
        run('examples-build', cargo + ['build', *cargo_args, '-p', 'gnunet-resolver-broker', '--examples'])
        for target in ['thumbv6m-none-eabi', 'thumbv7em-none-eabi']:
            run('embedded-' + target, cargo + ['check', *cargo_args, '-p', 'gnunet-client', '--no-default-features', '--target', target])
        binary = a.output / 'target/debug/examples/public_broker'
        config_binary = a.output / 'target/debug/examples/configuration'
        two_binary = a.output / 'target/debug/examples/two_services'
        binary_hashes = {str(p): sha(p) for p in [binary, config_binary, two_binary]}
        result['rust_binaries'] = binary_hashes
        deps = a.output / 'target/debug/deps'
        artifacts=run('ui-library-build', cargo + ['build', *cargo_args, '-p', 'gnunet-resolver-broker', '--lib', '--message-format=json'])
        rlib = rust_library(artifacts, 'gnunet_resolver_broker',manifest,next(row['id']for row in copied_metadata['packages']if pathlib.Path(row['manifest_path']).resolve()==manifest))
        if not rlib.is_file():
            raise ValueError('required condition failed at original line 26')
        result['ui_library'] = {'path': str(rlib), 'sha256': sha(rlib)}
        for (name, ok) in [('lease_live', False), ('lease_returned', True)]:
            argv = ['rustc', '+' + a.toolchain, '--edition', '2024', '--crate-type', 'lib', '--crate-name', name,'--error-format=json', str(a.package / ('tests/ui/' + name + '.rs')), '-L', 'dependency=' + str(deps), '--extern', 'gnunet_resolver_broker=' + str(rlib), '--out-dir', str(a.output / 'ui')]
            (a.output / 'ui').mkdir(exist_ok=True)
            proc = subprocess.run(argv, cwd=a.package, env=env, capture_output=True, timeout=30)
            (a.output / (name + '.stdout')).write_bytes(proc.stdout)
            (a.output / (name + '.stderr')).write_bytes(proc.stderr)
            diagnostics=[json.loads(line)for line in proc.stderr.decode().splitlines()if line.startswith('{')]
            codes=[d['code']['code']for d in diagnostics if d.get('level')=='error'and d.get('code')]
            if (ok and (proc.returncode!=0 or codes))or(not ok and(proc.returncode==0 or codes!=['E0505'])):raise ValueError('exact original Delivery UI outcome failed '+name)
        result['ui'] = 2
        ipc_id=next(row['id']for row in copied_metadata['packages']if pathlib.Path(row['manifest_path']).resolve()==a.repo/'adapters/ipc-unix/Cargo.toml')
        run('clock-ui',python+[a.package/'tools/clock_ui.py','--repo',a.repo,'--artifacts',a.output/'ui-library-build.stdout','--package-id',ipc_id,'--toolchain',a.toolchain,'--output',a.output/'clock-ui'])
        clock_ui=json.loads((a.output/'clock-ui/result.json').read_text())
        if clock_ui['status']!='passed'or clock_ui['actual_count']!=4 or len(clock_ui['cases'])!=4 or not all(row['passed']for row in clock_ui['cases']):raise ValueError('canonical clock UI inventory failed')
        result['clock_ui']=4
        base = python + [a.package / 'tools/build_probe.py', '--receipt', a.normal_receipt, '--source', a.upstream, '--reference-helper', a.reference_helper, '--package', a.package]
        run('build-c-public', base + ['--output', a.output / 'c-public'])
        run('build-c-config', base + ['--caller', 'tools/configuration.c', '--output', a.output / 'c-config'])
        cb = a.output / 'c-public/result.json'
        cc = a.output / 'c-config/result.json'
        sandbox = a.package / 'tools/no_ip.sb'
        run('literal-pairs', python + [a.package / 'tools/paired.py', '--c-build', cb, '--rust-binary', binary, '--sandbox', sandbox, '--output', a.output / 'literal'])
        check_actor_result(json.loads((a.output / 'literal/result.json').read_text()), 5, 10)
        run('client-pair', python + [a.package / 'tools/client_pair.py', '--c-build', cb, '--rust-binary', binary, '--output', a.output / 'client'])
        check_actor_result(json.loads((a.output / 'client/result.json').read_text()), 1, 2)
        run('configuration-pair', python + [a.package / 'tools/configuration_pair.py', '--c-build', cc, '--rust-binary', config_binary, '--sandbox', sandbox, '--output', a.output / 'configuration'])
        check_actor_result(json.loads((a.output / 'configuration/result.json').read_text()), 1, 2)
        run('normal-daemon', python + [a.package / 'tools/normal_service.py', '--c-build', cb, '--rust-binary', binary, '--normal-base', a.normal_resolver_base, '--normal-resolver', a.normal_resolver_receipt, '--source', a.upstream, '--reference-helper', a.reference_helper, '--sandbox', sandbox, '--output', a.output / 'normal-daemon'])
        value = json.loads((a.output / 'normal-daemon/result.json').read_text())
        check_actor_result(value, 1, 2)
        if not (value['source_unchanged'] and value['daemon']['exit_code'] == 0 and (value['actual_normal_daemons'] == 1)):
            raise ValueError('required condition failed at original line 35')
        run('orphan-component', python + [a.package / 'tools/reconnect_component.py', '--c-build', cb, '--source', a.upstream, '--output', a.output / 'component'])
        component = json.loads((a.output / 'component/result.json').read_text())
        if not (component['status'] == 'passed' and component['inputs_unchanged'] and (component['exit_code'] == 0) and (set(component['extracted_functions']) == {'check_disconnect','reconnect'})):
            raise ValueError('required condition failed at original line 36')
        run('build-c-two-services', python + [a.package / 'tools/build_two_services.py', '--arm-receipt', a.normal_receipt, '--statistics-receipt', a.normal_statistics_receipt, '--upstream', a.upstream, '--reference-helper', a.reference_helper, '--package', a.package, '--output', a.output / 'c-two-services'])
        two_build = a.output / 'c-two-services/result.json'
        run('two-services-pair', python + [a.package / 'tools/two_services_pair.py', '--package', a.package, '--c-build', two_build, '--rust-binary', two_binary, '--output', a.output / 'two-services'])
        two = json.loads((a.output / 'two-services/result.json').read_text())
        if not (two['status'] == 'passed' and two['inputs_unchanged'] and (two['paired_profiles'] == 1) and (len(two['cases']) == 2) and all((row['exit_code'] == 0 and row['callback_trace'] for row in two['cases']))):
            raise ValueError('required condition failed at original line 38')
        run('numeric-component', python + [a.package / 'tools/numeric_component.py', '--c-build', two_build, '--source', a.upstream, '--output', a.output / 'numeric-component'])
        numeric = json.loads((a.output / 'numeric-component/result.json').read_text())
        if not (numeric['status'] == 'passed' and numeric['inputs_unchanged'] and (numeric['exit_code'] == 0) and (set(numeric['extracted']) == {'AddressProbe','ClientState','RequestHandle','try_connect_using_address','numeric_resolution'}) and (len(numeric['trace']) == 10) and (numeric['actual_peer']['eof'] is True)):
            raise ValueError('required condition failed at original line 39')
        after = local_files(metadata('metadata-after'), a.package, a.repo)
        if workspace_files(input_repo)!=original_inputs:raise ValueError('input Root source file set/bytes changed')
        if not all(sha(path)==digest for path,digest in normal_inputs.items()):raise ValueError('normal bound input changed')
        result['inputs_unchanged'] = before == after
        if not result['inputs_unchanged']:
            raise ValueError('local source closure changed')
        if not all((sha(p) == h for (p, h) in binary_hashes.items())):
            raise ValueError('Rust actor binary changed during execution')
        if not sha(rlib) == result['ui_library']['sha256']:
            raise ValueError('required condition failed at original line 40')
        result['rust_binaries_unchanged'] = True
        result['upstream_unchanged'] = source_state(a.upstream) == upstream_before
        result['external_inputs_unchanged'] = all((sha(p) == h for (p, h) in external.items()))
        if not (result['upstream_unchanged'] and result['external_inputs_unchanged']):
            raise ValueError('required condition failed at original line 40')
        result.update(status='passed', paired_profiles=9, actual_C_R_actors=18, actual_normal_daemons=1, source_components=2)
    except Exception as e:
        result['failure'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    main()
